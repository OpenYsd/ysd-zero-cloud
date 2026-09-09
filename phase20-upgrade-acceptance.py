"""Phase 20 central local gate: a managed Agent upgrades itself, and can undo it.

Runs only against a local control plane this script owns and a current-user
Windows scheduled task it registers and removes. It creates no Production
resource, touches no Production data, and never modifies a task it did not
create.

The starting state is the real one: a managed Agent 0.6.0, built from the
Phase 19 commit, installed by its own `autostart enable`, running an
application. The upgrade is then driven exactly as an operator would drive it --
`node ysd-node-agent-<current>.mjs autostart upgrade` -- and every claim about
staging, the trial, promotion, rollback and the untouched OS registration is
checked against what is actually on disk and actually running.
"""

import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from acceptance_preflight import app_runtime_port_minimum, probe_port
from acceptance_ports import (
    first_bindable_port,
    release_reserved_ports,
    reserve_unbindable_ports,
)

REPO = Path(__file__).resolve().parent
REQUESTED_BASE = os.environ.get("YSD_PHASE20_BASE")
BASE = REQUESTED_BASE or ""
AUTH_ORIGIN = "http://localhost:3000"
NODE = os.environ.get(
    "YSD_ACCEPTANCE_NODE",
    r"C:\Users\qazpl\AppData\Local\Temp\ysd-node-v26.8.1\node-v26.8.1-win-x64\node.exe",
)
# The Phase 19 commit. Agent 0.6.0 is built from it so the migration bridge is
# exercised against the launcher that actually shipped, not a reconstruction.
PREVIOUS_COMMIT = "78f7ac74fcf2e0588e13a91455e1b727c620daa3"
PREVIOUS_AGENT_VERSION = "0.6.0"
CURRENT_AGENT_VERSION = json.loads(
    (Path(__file__).resolve().parent / "public/agent/manifest.json").read_text(encoding="utf8")
)["version"]
RUN = secrets.token_hex(3)
CLIENT_ADDRESS = f"198.51.100.{20 + (int(RUN, 16) % 220)}"
FIXTURE = "cyclic-software/express-hello-world"
COMMIT = "1b5eeb79b757a8cd496e58518aa1711889fa7253"
MARKER = "src='http://d3js.org/d3.v3.min.js'"
PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    return bool(condition)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()
        )

    def request(self, method, route, body=None, headers=None, retries=3):
        raw = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            BASE + route,
            data=raw,
            method=method,
            headers={
                "Content-Type": "application/json",
                # Local auth intentionally trusts this fixed development origin.
                # Requests still go to the isolated harness-owned BASE.
                "Origin": AUTH_ORIGIN,
                "Referer": AUTH_ORIGIN + "/",
                "CF-Connecting-IP": CLIENT_ADDRESS,
                "User-Agent": "ysd-phase20-local/1.0",
                **(headers or {}),
            },
        )
        try:
            with self.opener.open(request, timeout=180) as response:
                payload, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        if status == 429 and retries:
            time.sleep(8)
            return self.request(method, route, body, headers, retries - 1)
        try:
            return status, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return status, payload.decode("utf8", "replace")


# ---------------------------------------------------------------------------
# Local observation helpers.
# ---------------------------------------------------------------------------


def free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_control_plane(process, log_path):
    for _ in range(120):
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf8", errors="replace")[-2000:]
            raise RuntimeError(f"Owned control plane exited early ({process.returncode}): {detail}")
        try:
            with urllib.request.urlopen(BASE + "/", timeout=2) as response:
                if response.status < 500:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Owned local control plane did not become ready.")


def body_at(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as response:
            return response.read().decode("utf8", "replace")
    except Exception:
        return ""


def pid_on_port(port):
    result = subprocess.run(["netstat.exe", "-ano", "-p", "tcp"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[0] == "TCP" and fields[1].endswith(f":{port}") and fields[3] == "LISTENING":
            return int(fields[4])
    return None


def task_xml(task_name):
    result = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/XML"], capture_output=True, text=True
    )
    return result.stdout if result.returncode == 0 else ""


def canonical_registration(document):
    """The task's configuration with its operational history removed.

    Task Scheduler stamps a registration date into the document it hands back.
    That is bookkeeping about when the task was written, not what it does, so
    it is excluded -- everything else, including every argument and the
    principal, must be identical across the whole upgrade.
    """
    if not document:
        return ""
    stripped = re.sub(r"<Date>.*?</Date>", "", document, flags=re.S)
    return re.sub(r"\s+", " ", stripped).strip()


def managed_processes(install):
    """Only the launcher for this exact install and its direct Agent child."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'node.exe' -and $_.CommandLine} | "
         "Select-Object ProcessId,ParentProcessId,CommandLine) | ConvertTo-Json -Compress"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {"launcherCount": 0, "launcherPid": None, "agentCount": 0, "agentPid": None, "agentRelease": None}
    records = json.loads(result.stdout)
    if isinstance(records, dict):
        records = [records]
    install_path = str(Path(install["workingDirectory"]) / "install.json")
    launchers = [
        row for row in records
        if install["launcherPath"] in row.get("CommandLine", "") and install_path in row.get("CommandLine", "")
    ]
    agents = [
        row for row in records
        if len(launchers) == 1
        and row.get("ParentProcessId") == launchers[0].get("ProcessId")
        and install["credentialPath"] in row.get("CommandLine", "")
        and " run " in row.get("CommandLine", "")
    ]
    release = None
    if len(agents) == 1:
        found = re.search(r"releases[\\/](\d+\.\d+\.\d+)[\\/]", agents[0].get("CommandLine", ""))
        release = found.group(1) if found else None
    return {
        "launcherCount": len(launchers),
        "launcherPid": launchers[0]["ProcessId"] if len(launchers) == 1 else None,
        "agentCount": len(agents),
        "agentPid": agents[0]["ProcessId"] if len(agents) == 1 else None,
        "agentRelease": release,
    }


def wait_task_idle(task_name, install, limit=90):
    for _ in range(limit):
        query = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", task_name, "/FO", "LIST"],
            capture_output=True,
            text=True,
        )
        managed = managed_processes(install)
        if (
            query.returncode == 0
            and re.search(r"^Status:\s+Ready\s*$", query.stdout, re.MULTILINE | re.IGNORECASE)
            and managed.get("launcherCount") == 0
            and managed.get("agentCount") == 0
        ):
            return True
        time.sleep(0.5)
    return False


def read_install(install_path):
    for _ in range(20):
        try:
            return json.loads(Path(install_path).read_text(encoding="utf8"))
        except (json.JSONDecodeError, FileNotFoundError):
            time.sleep(0.2)
    return {}


def wait_deployment(client, deployment_id, states, limit=90):
    row = None
    for _ in range(limit):
        time.sleep(2)
        _, body = client.request("GET", "/api/deployments")
        rows = [item for item in (body or {}).get("deployments", []) if item["id"] == deployment_id]
        if rows:
            row = rows[0]
            if row.get("state") in states:
                return row
    return row


def wait_node_version(client, node_id, version, limit=90):
    for _ in range(limit):
        _, body = client.request("GET", "/api/nodes")
        for item in (body or {}).get("nodes", []):
            if item.get("id") == node_id and item.get("agentVersion") == version and item.get("status") == "online":
                return item
        time.sleep(2)
    return None


def build_previous_agent():
    """Builds Agent 0.6.0 from the Phase 19 commit, once, into a temp tree.

    The migration bridge only means anything if the Agent it migrates from is
    the one that shipped, launcher and all. So this reconstructs it from git
    rather than approximating it.
    """
    root = Path(tempfile.gettempdir()) / "ysd-phase20-previous"
    artifact = root / "public" / "agent" / f"ysd-node-agent-{PREVIOUS_AGENT_VERSION}.mjs"
    if artifact.exists():
        return artifact
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    archive = root.parent / f"ysd-phase20-previous-{RUN}.tar"
    subprocess.run(
        ["git", "archive", "--format=tar", "-o", str(archive), PREVIOUS_COMMIT],
        cwd=REPO, check=True, capture_output=True,
    )
    with tarfile.open(archive) as tar:
        tar.extractall(root)
    archive.unlink()
    # A directory junction, not a copy: the build only needs rolldown, and
    # duplicating node_modules would take longer than the whole acceptance run.
    subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(root / "node_modules"), str(REPO / "node_modules")],
        check=True, capture_output=True, text=True,
    )
    built = subprocess.run(
        [NODE, str(root / "scripts" / "build-agent.mjs")],
        cwd=root, capture_output=True, text=True, timeout=300,
    )
    if not artifact.exists():
        raise RuntimeError(f"Could not build Agent {PREVIOUS_AGENT_VERSION}: {built.stderr[-2000:]}")
    return artifact


FAILING_CANDIDATE = """// YSD_TEST_ONLY_FAILING_AGENT
// A candidate that is structurally valid, reports a newer version, and then
// fails its managed start. It exists only so automatic rollback can be proved
// against a real launcher; the release build refuses to ship anything carrying
// the marker above.
const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-v')) {
  console.log('YSD Node Agent 9.9.9');
  console.log('Protocol 1');
  process.exit(0);
}
console.error('test_only_candidate_failure');
process.exit(7);
"""


# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------

manifest = json.loads((REPO / "public/agent/manifest.json").read_text(encoding="utf8"))
current_agent = REPO / "public/agent" / manifest["filename"]
home = Path(tempfile.mkdtemp(prefix="ysd-phase20-"))
config = home / "credentials.json"
# Agent 0.6.0 resolves whoami.exe and schtasks.exe through PATH. A developer
# shell can put its own lookalikes ahead of System32, which is not the
# environment a managed Agent starts in -- the scheduled task inherits the
# user session's PATH, where System32 comes first. Reproduce that here so the
# previous Agent runs the way it does on a real machine. Agent 0.7.0 no longer
# depends on it: it addresses the Windows system tools absolutely.
SYSTEM32 = str(Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32")
env = {
    **os.environ,
    "PATH": SYSTEM32 + os.pathsep + os.environ.get("PATH", ""),
    "YSD_NODE_AGENT_HOME": str(home),
    "YSD_NODE_CONFIG": str(config),
    "LOCALAPPDATA": str(home),
    "XDG_DATA_HOME": str(home),
}
env.pop("YSD_NODE_AGENT_KEY", None)

deployment_id = None
port = None
node_id = None
task_name = None
install = {}
install_path = None
control_plane = None
control_plane_log_handle = None
control_plane_log_path = home / "control-plane.log"


def managed_log_text():
    if not install:
        return ""
    return "\n".join(
        file.read_text(encoding="utf8", errors="replace")
        for file in (Path(install["workingDirectory"]) / "logs").glob("*.log")
    )


def run_agent(artifact, arguments, timeout=420):
    return subprocess.run(
        [NODE, str(artifact), *arguments, "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=timeout,
    )



def legacy_environment_preflight():
    """Refuses to start when the frozen Agent's prerequisite cannot be met.

    Frozen Agent 0.6.0 cannot renegotiate a private port, so the fixture needs
    one this host will grant. It does not have to be the bottom of the range --
    the harness reserves whatever prefix Windows refuses, and the real allocator
    then picks the first free port by itself. What this cannot survive is a host
    with no bindable port in the range at all.

    Reads only; writes nothing and starts nothing.
    """
    try:
        range_start, bindable = first_bindable_port(REPO)
    except RuntimeError:
        print("\n=== PHASE 20 / 20.1: BLOCKED \u2014 ENVIRONMENT ===", flush=True)
        print(json.dumps({
            "reason": "no_bindable_private_port_in_range",
            "rangeStart": app_runtime_port_minimum(REPO),
            "agentVersion": PREVIOUS_AGENT_VERSION,
            "why": "the frozen Agent cannot renegotiate a private port",
            "productGateResult": "not produced",
        }), flush=True)
        raise SystemExit(2) from None
    print("PORT_PREFLIGHT=" + json.dumps({
        "rangeStart": range_start,
        "firstBindable": bindable,
        "hostReservesPrefix": bindable != range_start,
    }), flush=True)


legacy_environment_preflight()

try:
    print("=== build the shipped Agent 0.6.0 to start from ===", flush=True)
    previous_agent = build_previous_agent()
    reported = subprocess.run(
        [NODE, str(previous_agent), "--version"], capture_output=True, text=True, timeout=60
    ).stdout
    check(
        f"Agent {PREVIOUS_AGENT_VERSION} rebuilt from the Phase 19 commit",
        PREVIOUS_AGENT_VERSION in reported and "Protocol 1" in reported,
        reported.strip().replace("\n", " / "),
    )
    check(
        f"Agent {manifest['version']} is the published candidate",
        manifest["version"] == CURRENT_AGENT_VERSION and manifest["protocolVersion"] == 1,
    )

    if REQUESTED_BASE:
        BASE = REQUESTED_BASE
        print(f"=== externally owned local control plane: {BASE} ===", flush=True)
    else:
        control_port = free_loopback_port()
        BASE = f"http://127.0.0.1:{control_port}"
        control_plane_log_handle = control_plane_log_path.open("w", encoding="utf8")
        control_plane = subprocess.Popen(
            ["node.exe", str(REPO / "node_modules/vinext/dist/cli.js"), "dev",
             "--hostname", "127.0.0.1", "--port", str(control_port)],
            cwd=REPO,
            stdout=control_plane_log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        wait_control_plane(control_plane, control_plane_log_path)
        check("harness owns a live isolated control-plane process", control_plane.poll() is None)

    operator = Client()
    print("\n=== pair a controlled node on managed Agent 0.6.0 ===", flush=True)
    email = f"phase20-{RUN}@ysd.test"
    password = f"phase20-local-{RUN}-longpassword"
    status, _ = operator.request("POST", "/api/auth/sign-up/email", {
        "name": "Phase 20 Operator", "email": email, "password": password,
    })
    if not check("authenticated local Better Auth session", status == 200, f"got {status}"):
        raise RuntimeError("The local Better Auth session was not established.")
    status, body = operator.request("POST", "/api/nodes", {"name": f"Phase 20 Node {RUN}"})
    pairing = (body or {}).get("pairing")
    if not check("controlled node pairing ticket", status == 201 and pairing, f"got {status}"):
        raise RuntimeError("The controlled pairing ticket was not created.")
    paired = subprocess.run(
        [NODE, str(previous_agent), "pair", "--url", BASE, "--config", str(config)],
        cwd=home, env={**env, "YSD_NODE_PAIRING_CODE": pairing["code"]},
        capture_output=True, text=True, timeout=180,
    )
    check("Agent 0.6.0 pairs on Protocol 1", paired.returncode == 0, paired.stderr.strip()[:200])

    enabled = subprocess.run(
        [NODE, str(previous_agent), "autostart", "enable", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=120,
    )
    check("Agent 0.6.0 registers real Task Scheduler auto-start", enabled.returncode == 0, enabled.stderr.strip()[:200])
    install_path = next((home / "managed").glob("*/install.json"))
    install = read_install(install_path)
    task_name = install["registrationId"]
    registration_before = canonical_registration(task_xml(task_name))
    check("live scheduled task exists", bool(registration_before))
    check("managed install starts at the Phase 19 shape", install.get("version") == 1 and install.get("agentVersion") == PREVIOUS_AGENT_VERSION,
          json.dumps({"version": install.get("version"), "agentVersion": install.get("agentVersion"), "installSchema": install.get("installSchema")}))
    check("Phase 19 install records no verifiable previous release",
          install.get("previousRelease") is None and install.get("upgrade") is None)
    launcher_v1 = Path(install["launcherPath"]).read_text(encoding="utf8")
    check("launcher v1 reads its metadata once", launcher_v1.count("readFile(installPath") == 1)

    node_row = None
    for _ in range(60):
        _, nodes_body = operator.request("GET", "/api/nodes")
        match = [item for item in (nodes_body or {}).get("nodes", []) if item.get("name") == f"Phase 20 Node {RUN}"]
        if match and match[0].get("status") == "online":
            node_row = match[0]
            break
        time.sleep(2)
    node_id = (node_row or {}).get("id")
    check("managed Agent 0.6.0 is online", node_id is not None and node_row.get("agentVersion") == PREVIOUS_AGENT_VERSION,
          json.dumps({"status": (node_row or {}).get("status"), "agentVersion": (node_row or {}).get("agentVersion")}))

    print("\n=== deploy the safe fixture and record it ===", flush=True)
    # Frozen Agent 0.6.0 cannot renegotiate a private port, so the fixture has
    # to be given one this host will actually grant. Nothing about the product
    # changes: the allocator, the range and every Phase 20 expectation stay as
    # they are, and the harness simply owns the ports Windows refuses so the
    # real `nextPort()` skips them of its own accord. The holders describe no
    # application -- no job, no artifact, nothing running -- and are removed in
    # cleanup.
    range_start, bindable_port = first_bindable_port(REPO)
    reserved = reserve_unbindable_ports(REPO, node_id, bindable_port, int(time.time() * 1000))
    print("PORT_RESERVATION=" + json.dumps({
        "rangeStart": range_start,
        "firstBindable": bindable_port,
        "reservedCount": len(reserved),
    }), flush=True)
    check("the fixture will be offered a port this host can bind",
          probe_port(bindable_port)[0], f"port {bindable_port} is not bindable")

    status, body = operator.request("POST", "/api/smart-deploy", {
        "repository": FIXTURE, "branch": "main", "commit": COMMIT,
        "nodeId": node_id, "environment": "Production", "healthPath": "/",
        "memoryMb": 256, "diskQuotaBytes": 256 * 1024**2, "target": "user-node",
    }, {"Idempotency-Key": f"phase20-deploy-{RUN}"})
    deployment = (body or {}).get("deployment")
    check("private Zero Mode deployment queued", status == 202 and deployment, f"got {status}")
    deployment_id, port = deployment["id"], deployment["localPort"]
    check("the server allocator assigned the first bindable port itself",
          port == bindable_port, f"expected {bindable_port}, got {port}")
    row = wait_deployment(operator, deployment_id, {"healthy", "failed", "crash_loop"}, limit=150)
    # Named fields rather than a truncated dump: a 300-character `str(row)` put
    # the repository and commit first and cut off `state` and `lastError`, which
    # is exactly what a failure needs to say. Safe fields only -- no
    # environment, token, cookie or credential.
    if row is not None and row.get("state") != "healthy":
        print("FIXTURE_DEPLOYMENT=" + json.dumps({key: row.get(key) for key in (
            "id", "state", "desiredState", "observedState", "localPort",
            "currentArtifactId", "restartCount", "crashLoop",
            "recoveryReasonCode", "buildDurationMs", "lastError",
        )}, default=str), flush=True)
    check("deployment is healthy before the upgrade", (row or {}).get("state") == "healthy",
          json.dumps({"state": (row or {}).get("state"), "port": (row or {}).get("localPort"),
                      "lastError": (row or {}).get("lastError")}, default=str))
    check("marker is served before the upgrade", MARKER in body_at(port))
    _, before_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    before = (before_detail or {}).get("deployment", {})
    before_artifacts = before.get("artifacts", [])
    artifact_id = before.get("currentArtifactId")
    artifact_checksum = next((a.get("checksum") for a in before_artifacts if a.get("id") == artifact_id), None)
    check("app artifact recorded", bool(artifact_id and artifact_checksum))
    log_before = managed_log_text()

    print(f"\n=== THE CENTRAL GATE: user-initiated 0.6.0 to {CURRENT_AGENT_VERSION} upgrade ===", flush=True)
    upgraded = run_agent(current_agent, ["autostart", "upgrade"], timeout=600)
    try:
        result = json.loads(upgraded.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        result = {}
    check(
        "autostart upgrade promoted the candidate",
        upgraded.returncode == 0 and result.get("outcome") == "promoted",
        json.dumps({"code": upgraded.returncode, "result": result, "stderr": upgraded.stderr.strip()[:300]}),
    )
    check("promotion recorded the Agent it replaced", result.get("previousVersion") == PREVIOUS_AGENT_VERSION, json.dumps(result))

    install = read_install(install_path)
    check(f"top-level current is now {CURRENT_AGENT_VERSION}", install.get("agentVersion") == CURRENT_AGENT_VERSION and install.get("installSchema") == 2)
    check(
        "previous release is recorded by exact path and hash",
        (install.get("previousRelease") or {}).get("version") == PREVIOUS_AGENT_VERSION
        and len((install.get("previousRelease") or {}).get("releaseHash", "")) == 64
        and Path((install.get("previousRelease") or {}).get("releasePath", "")).exists(),
        json.dumps(install.get("previousRelease")),
    )
    check("the transaction is settled and carries no candidate",
          (install.get("upgrade") or {}).get("state") == "idle" and (install.get("upgrade") or {}).get("candidate") is None,
          json.dumps(install.get("upgrade")))
    check(
        "the promoted release is the published Agent byte for byte",
        Path(install["releasePath"]).read_bytes() == current_agent.read_bytes(),
    )
    launcher_v2 = Path(install["launcherPath"]).read_text(encoding="utf8")
    check("launcher v2 re-reads its metadata before every launch", launcher_v2.count("loadInstall()") >= 2)
    check("launcher v2 knows the transaction", "readiness.json" in launcher_v2 and "rollback_pending" in launcher_v2)

    registration_after = canonical_registration(task_xml(task_name))
    check("scheduled task registration is unchanged by the upgrade", registration_after == registration_before)
    check("task registration still contains no secrets",
          pairing["code"] not in registration_after and "YSD_NODE_AGENT_KEY" not in registration_after)

    upgraded_node = wait_node_version(operator, node_id, CURRENT_AGENT_VERSION)
    check(f"the same node identity now reports Agent {CURRENT_AGENT_VERSION}", upgraded_node is not None,
          json.dumps({"nodeId": node_id}))
    managed = managed_processes(install)
    check("exactly one launcher owns exactly one Agent", managed.get("launcherCount") == 1 and managed.get("agentCount") == 1,
          json.dumps(managed))
    check("the running Agent is the promoted release", managed.get("agentRelease") == CURRENT_AGENT_VERSION, json.dumps(managed))

    print("\n=== the application recovers from the same artifact ===", flush=True)
    recovered = wait_deployment(operator, deployment_id, {"healthy", "failed", "blocked", "timed_out"}, limit=120)
    for _ in range(60):
        if MARKER in body_at(port):
            break
        time.sleep(1)
    check(
        "the application is healthy again after the Agent upgrade",
        (recovered or {}).get("state") == "healthy" and MARKER in body_at(port),
        json.dumps({"state": (recovered or {}).get("state"),
                    "recoveryStatus": (recovered or {}).get("recoveryStatus"),
                    "served": MARKER in body_at(port)}),
    )
    _, after_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    after = (after_detail or {}).get("deployment", {})
    after_artifact = next((a for a in after.get("artifacts", []) if a.get("id") == artifact_id), {})
    check(
        "same deployment, same node, same private port",
        after.get("id") == deployment_id and after.get("nodeId") == node_id and after.get("localPort") == port,
    )
    check(
        "same artifact and checksum, and no new artifact was created",
        after.get("currentArtifactId") == artifact_id
        and after_artifact.get("checksum") == artifact_checksum
        and len(after.get("artifacts", [])) == len(before_artifacts),
        json.dumps({"artifacts": len(after.get("artifacts", [])), "before": len(before_artifacts)}),
    )
    upgrade_log = managed_log_text()[len(log_before):]
    check(
        "recovery performed no GitHub fetch, no npm invocation and no build",
        not re.search(r"github\.com|\bnpm\b|\bbuilding\b", upgrade_log, re.I),
        upgrade_log[-400:].replace("\n", " | "),
    )
    check("the managed log records the upgrade in fixed language",
          "Upgrade staged" in upgrade_log and "candidate promoted" in upgrade_log)
    check("the managed log carries no secret", not re.search(r"ysdp_|YSD_NODE_AGENT_KEY=[^\[]|Authorization: Bearer [A-Za-z0-9]", upgrade_log))

    print("\n=== repeated and duplicate upgrades ===", flush=True)
    repeated = run_agent(current_agent, ["autostart", "upgrade"], timeout=180)
    repeat_result = json.loads(repeated.stdout.strip().splitlines()[-1]) if repeated.stdout.strip() else {}
    check("re-running the same upgrade is refused as already current",
          repeat_result.get("outcome") == "refused" and repeat_result.get("reason") == "already_current",
          json.dumps(repeat_result))
    still = managed_processes(install)
    check("the refusal disturbed nothing", still.get("agentCount") == 1 and MARKER in body_at(port))

    print("\n=== a candidate that fails its trial is rolled back ===", flush=True)
    failing = home / "ysd-node-agent-9.9.9.mjs"
    failing.write_text(FAILING_CANDIDATE, encoding="utf8")
    check("the failure fixture is test-only and never published",
          "YSD_TEST_ONLY_FAILING_AGENT" in failing.read_text(encoding="utf8")
          and not any("YSD_TEST_ONLY_FAILING_AGENT" in file.read_text(encoding="utf8", errors="replace")
                      for file in (REPO / "public/agent").glob("*")))
    log_before_rollback = managed_log_text()
    # The failing trial takes long enough to guarantee a genuine overlap, so a
    # second upgrade launched while it runs really is contending for the same
    # maintenance owner rather than arriving after the first one finished.
    rolling = subprocess.Popen(
        [NODE, str(current_agent), "autostart", "upgrade", "--source", str(failing), "--config", str(config)],
        cwd=home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(8)
    concurrent = run_agent(current_agent, ["autostart", "upgrade"], timeout=180)
    concurrent_result = json.loads(concurrent.stdout.strip().splitlines()[-1]) if concurrent.stdout.strip() else {}
    check(
        "a second upgrade during an active transaction is refused as maintenance busy",
        concurrent_result.get("outcome") == "refused" and concurrent_result.get("reason") == "maintenance_busy",
        json.dumps(concurrent_result),
    )
    try:
        rolled_out, rolled_err = rolling.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        rolling.kill()
        rolled_out, rolled_err = rolling.communicate(timeout=60)
    try:
        rollback_result = json.loads(rolled_out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        rollback_result = {"stderr": rolled_err.strip()[:300]}
    check(
        "the failing candidate is staged and then rolled back",
        rollback_result.get("outcome") == "rolled_back" and rollback_result.get("candidateVersion") == "9.9.9",
        json.dumps(rollback_result),
    )
    install = read_install(install_path)
    check("the known-good Agent is current again", install.get("agentVersion") == CURRENT_AGENT_VERSION)
    check("the failure is classified as candidate-specific",
          (install.get("upgrade") or {}).get("reason") == "candidate_start_failed",
          json.dumps(install.get("upgrade")))
    check("only one managed transaction ever ran", (install.get("upgrade") or {}).get("state") == "idle")
    quarantine = (install.get("upgrade") or {}).get("quarantine", [])
    check("the failed candidate is quarantined by exact hash",
          len(quarantine) == 1 and quarantine[0].get("version") == "9.9.9" and len(quarantine[0].get("releaseHash", "")) == 64,
          json.dumps(quarantine))
    check("the failed candidate bundle is pruned",
          not (Path(install["releasePath"]).parent.parent / "9.9.9").exists())
    check("registration is unchanged by staging, trial and rollback",
          canonical_registration(task_xml(task_name)) == registration_before)
    restored_node = wait_node_version(operator, node_id, CURRENT_AGENT_VERSION)
    check("the known-good Agent reconnects after the rollback", restored_node is not None)
    rollback_log = managed_log_text()[len(log_before_rollback):]
    check("the rollback is recorded in fixed language",
          "candidate failed reason=candidate_start_failed" in rollback_log and "previous Agent restored" in rollback_log,
          rollback_log[-400:].replace("\n", " | "))
    trials = rollback_log.count("candidate trial started")
    check("the trial is bounded and does not loop", trials == 2, f"trial starts: {trials}")

    retry_refused = run_agent(current_agent, ["autostart", "upgrade", "--source", str(failing)], timeout=180)
    retry_result = json.loads(retry_refused.stdout.strip().splitlines()[-1]) if retry_refused.stdout.strip() else {}
    check("the same failed candidate is refused without explicit intent",
          retry_result.get("reason") == "candidate_quarantined", json.dumps(retry_result))

    lower = home / "ysd-node-agent-lower.mjs"
    lower.write_text(FAILING_CANDIDATE.replace("9.9.9", "0.5.0"), encoding="utf8")
    downgrade = run_agent(current_agent, ["autostart", "upgrade", "--source", str(lower)], timeout=180)
    downgrade_result = json.loads(downgrade.stdout.strip().splitlines()[-1]) if downgrade.stdout.strip() else {}
    check("an arbitrary lower bundle is refused as a downgrade",
          downgrade_result.get("reason") == "downgrade_refused", json.dumps(downgrade_result))

    print("\n=== manual restore to the exact previous Agent, and back ===", flush=True)
    restored = run_agent(current_agent, ["autostart", "restore-previous"], timeout=420)
    restore_result = json.loads(restored.stdout.strip().splitlines()[-1]) if restored.stdout.strip() else {}
    check("restore-previous selects the exact recorded release",
          restore_result.get("outcome") == "restored" and restore_result.get("currentVersion") == PREVIOUS_AGENT_VERSION,
          json.dumps(restore_result))
    install = read_install(install_path)
    check("launcher v2 is retained while running Agent 0.6.0",
          Path(install["launcherPath"]).read_text(encoding="utf8") == launcher_v2)
    check("registration is unchanged by the restore",
          canonical_registration(task_xml(task_name)) == registration_before)
    downgraded_node = wait_node_version(operator, node_id, PREVIOUS_AGENT_VERSION)
    check("Agent 0.6.0 is accepted by the 0.20.0 control plane", downgraded_node is not None)

    print("\n=== PHASE 20.1 GATE: restored 0.6.0 reads the status surface ===", flush=True)
    status_060 = subprocess.run(
        [NODE, str(previous_agent), "autostart", "status", "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=120,
    )
    try:
        restored_status = json.loads(status_060.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        restored_status = {"stderr": status_060.stderr.strip()[:200]}
    check(
        "Agent 0.6.0 parses the status file this Agent wrote",
        restored_status.get("state") is not None and "stderr" not in restored_status,
        json.dumps(restored_status),
    )
    # What the hotfix guarantees, and what it does not.
    #
    # Agent 0.6.0 validates BOTH managed files by exact key set. `status.json`
    # is now written in the shape it expects, which is what the heartbeat and
    # the Nodes badge read -- that is the defect this hotfix targets. Its
    # `autostart status` command additionally parses `install.json`, and that
    # file legitimately carries the Phase 20 transaction, so 0.6.0 still cannot
    # read it. Removing those keys would discard the recorded previous release,
    # so the boundary is stated rather than papered over.
    check(
        "the status file is exactly the Phase 19 key set",
        sorted(restored_status.keys()) == sorted([
            "agentVersion", "crashFailures", "enabled", "lastExitAt", "lastStartAt",
            "manager", "registrationFingerprint", "restartCount", "scope", "state", "version",
        ]),
        json.dumps(sorted(restored_status.keys())),
    )
    known_boundary = restored_status.get("registrationFingerprint") is None
    check(
        "0.6.0's own status command is limited by install.json, not by status.json",
        known_boundary,
        "install.json carries the Phase 20 transaction and 0.6.0 validates it by exact key set",
    )
    fresh_node = wait_node_version(operator, node_id, PREVIOUS_AGENT_VERSION) or downgraded_node
    restored_capability = (fresh_node or {}).get("capabilities", {}).get("autostart", {})
    check(
        "THE HOTFIX: the control plane sees the restored 0.6.0 as auto-start enabled",
        restored_capability.get("enabled") is True and restored_capability.get("state") == "enabled",
        json.dumps(restored_capability),
    )

    # And the other direction: with the registration gone it must NOT claim
    # Enabled. The task is ended first -- deleting a task does not stop an
    # instance that is already running, and an orphaned launcher would keep the
    # node identity and make the later upgrade contend with itself.
    subprocess.run(["schtasks.exe", "/End", "/TN", task_name], capture_output=True)
    check("the managed task reaches idle before its registration is removed",
          wait_task_idle(task_name, install))
    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True)
    absent_060 = subprocess.run(
        [NODE, str(previous_agent), "autostart", "status", "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=120,
    )
    try:
        absent_status = json.loads(absent_060.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        absent_status = {}
    check(
        "with the task removed the restored Agent does not claim Enabled",
        absent_status.get("enabled") is False and absent_status.get("state") in {"disabled", "registration_invalid"},
        json.dumps(absent_status),
    )
    repaired = subprocess.run(
        [NODE, str(previous_agent), "autostart", "repair", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=180,
    )
    check("Agent 0.6.0 repairs its own registration", repaired.returncode == 0, repaired.stderr.strip()[:200])
    install = read_install(install_path)
    task_name = install["registrationId"]
    check("the repaired registration is canonically identical",
          canonical_registration(task_xml(task_name)) == registration_before)

    back = run_agent(current_agent, ["autostart", "upgrade"], timeout=600)
    back_result = json.loads(back.stdout.strip().splitlines()[-1]) if back.stdout.strip() else {}
    check(f"upgrading again from the restored Agent promotes {CURRENT_AGENT_VERSION}",
          back_result.get("outcome") == "promoted" and back_result.get("currentVersion") == CURRENT_AGENT_VERSION,
          json.dumps(back_result))
    install = read_install(install_path)
    releases = sorted(p.name for p in (Path(install["releasePath"]).parent.parent).iterdir() if p.is_dir())
    check("release retention stays at current plus previous", releases == sorted(["0.6.0", CURRENT_AGENT_VERSION]), json.dumps(releases))
    final_node = wait_node_version(operator, node_id, CURRENT_AGENT_VERSION)
    check(f"the node is back on Agent {CURRENT_AGENT_VERSION}", final_node is not None)
    wait_deployment(operator, deployment_id, {"healthy"}, limit=120)

    print("\n=== an intentionally stopped application stays stopped ===", flush=True)
    status, _ = operator.request(
        "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "stop"},
        {"Idempotency-Key": f"phase20-stop-{RUN}"},
    )
    check("intentional Stop queued", status == 202, f"got {status}")
    stopped = wait_deployment(operator, deployment_id, {"stopped", "failed"})
    check("desired state is stopped", (stopped or {}).get("state") == "stopped")
    subprocess.run(["schtasks.exe", "/End", "/TN", task_name], capture_output=True)
    check("the managed task reaches idle before the final start", wait_task_idle(task_name, install))
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], check=True, capture_output=True)
    time.sleep(12)
    _, final_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    final = (final_detail or {}).get("deployment", {})
    check("a fresh managed Agent never reopens an intentional Stop",
          final.get("desiredState") == "stopped" and not body_at(port),
          json.dumps({"desiredState": final.get("desiredState"), "serving": bool(body_at(port))}))

    print(f"\nBROWSER_EMAIL={email}\nBROWSER_PASSWORD={password}\nBROWSER_NODE={node_id}")
finally:
    try:
        released = release_reserved_ports(REPO)
        if released:
            print(f"released {released} harness port holder(s)", flush=True)
    except Exception as error:  # noqa: BLE001 - cleanup must not mask a result
        print(f"port holder cleanup note: {type(error).__name__}", flush=True)
    if FAILED and install:
        status_path = Path(install["workingDirectory"]) / "status.json"
        if status_path.exists():
            print("\nDIAGNOSTIC_MANAGED_STATUS=" + status_path.read_text(encoding="utf8", errors="replace")[:2000])
        if install_path and Path(install_path).exists():
            print("DIAGNOSTIC_MANAGED_INSTALL=" + Path(install_path).read_text(encoding="utf8", errors="replace")[:3000])
        print("DIAGNOSTIC_MANAGED_LOG_TAIL=" + managed_log_text()[-6000:])
        print("DIAGNOSTIC_CONTROL_PLANE_ALIVE=" + str(control_plane is None or control_plane.poll() is None))
    if task_name:
        subprocess.run(
            [NODE, str(current_agent), "autostart", "uninstall", "--config", str(config)],
            cwd=home, env=env, capture_output=True, text=True, timeout=120,
        )
        subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True)
    if port:
        process = pid_on_port(port)
        if process:
            subprocess.run(["taskkill.exe", "/PID", str(process), "/T", "/F"], capture_output=True)
    if node_id:
        try:
            operator.request("DELETE", f"/api/nodes/{node_id}")
        except OSError:
            pass
    if control_plane is not None:
        subprocess.run(["taskkill.exe", "/PID", str(control_plane.pid), "/T", "/F"], capture_output=True, text=True)
        try:
            control_plane.wait(timeout=20)
        except subprocess.TimeoutExpired:
            control_plane.kill()
    if control_plane_log_handle is not None:
        control_plane_log_handle.close()
    for _ in range(10):
        try:
            shutil.rmtree(home)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.5)

print("\n=== cleanup ===")
check("controlled task removed", not task_name or not task_xml(task_name))
check("temporary Agent home removed", not home.exists())
print(f"\nPASSED {len(PASSED)}  FAILED {len(FAILED)}")
for failure in FAILED:
    print("  FAIL — " + failure)
sys.exit(1 if FAILED else 0)
