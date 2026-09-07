"""Phase 19 central local gate: native managed startup drives Phase 18 recovery.

This runs only against the local control plane and a current-user Windows task.
It creates no Production resource and always removes its task and temporary home.
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
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent
REQUESTED_BASE = os.environ.get("YSD_PHASE19_BASE")
BASE = REQUESTED_BASE or ""
AUTH_ORIGIN = "http://localhost:3000"
NODE = os.environ.get(
    "YSD_ACCEPTANCE_NODE",
    r"C:\Users\qazpl\AppData\Local\Temp\ysd-node-v26.8.1\node-v26.8.1-win-x64\node.exe",
)
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
                "User-Agent": "ysd-phase19-local/1.0",
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


def managed_processes(install):
    """Return only the launcher and its direct Agent child for this exact install."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'node.exe' -and $_.CommandLine} | "
         "Select-Object ProcessId,ParentProcessId,CommandLine) | ConvertTo-Json -Compress"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {"launcherCount": 0, "launcherPid": None, "agentCount": 0, "agentPid": None}
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
        and install["releasePath"] in row.get("CommandLine", "")
        and install["credentialPath"] in row.get("CommandLine", "")
        and " run " in row.get("CommandLine", "")
    ]
    return {
        "launcherCount": len(launchers),
        "launcherPid": launchers[0]["ProcessId"] if len(launchers) == 1 else None,
        "agentCount": len(agents),
        "agentPid": agents[0]["ProcessId"] if len(agents) == 1 else None,
    }


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


def task_xml(task_name):
    result = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/XML"], capture_output=True, text=True
    )
    return result.stdout if result.returncode == 0 else ""


def wait_task_idle(task_name, install, limit=60):
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


manifest = json.loads((REPO / "public/agent/manifest.json").read_text(encoding="utf8"))
artifact = REPO / "public/agent" / manifest["filename"]
home = Path(tempfile.mkdtemp(prefix="ysd-phase19-recovery-"))
config = home / "credentials.json"
env = {
    **os.environ,
    "YSD_NODE_AGENT_HOME": str(home),
    "YSD_NODE_CONFIG": str(config),
    "LOCALAPPDATA": str(home),
    "XDG_DATA_HOME": str(home),
}
env.pop("YSD_NODE_AGENT_KEY", None)
agent = None
agent_log_handle = None
deployment_id = None
port = None
node_id = None
task_name = None
control_plane = None
control_plane_log_handle = None
control_plane_log_path = home / "control-plane.log"

try:
    if REQUESTED_BASE:
        BASE = REQUESTED_BASE
        print(f"=== externally owned local control plane: {BASE} ===", flush=True)
    else:
        control_port = free_loopback_port()
        BASE = f"http://127.0.0.1:{control_port}"
        control_plane_log_handle = control_plane_log_path.open("w", encoding="utf8")
        control_plane = subprocess.Popen(
            ["node.exe", str(REPO / "node_modules/vinext/dist/cli.js"), "dev", "--hostname", "127.0.0.1", "--port", str(control_port)],
            cwd=REPO,
            stdout=control_plane_log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        wait_control_plane(control_plane, control_plane_log_path)
        check("harness owns a live isolated control-plane process", control_plane.poll() is None)
    operator = Client()
    print("=== pair and deploy through the real Agent ===", flush=True)
    email = f"phase19-{RUN}@ysd.test"
    password = f"phase19-local-{RUN}-longpassword"
    status, _ = operator.request("POST", "/api/auth/sign-up/email", {
        "name": "Phase 19 Operator", "email": email, "password": password,
    })
    if not check("authenticated local Better Auth session", status == 200, f"got {status}"):
        raise RuntimeError("The local Better Auth session was not established.")
    status, body = operator.request("POST", "/api/nodes", {"name": f"Phase 19 Node {RUN}"})
    pairing = (body or {}).get("pairing")
    if not check("controlled node pairing ticket", status == 201 and pairing, f"got {status}"):
        raise RuntimeError("The controlled pairing ticket was not created.")
    pair_env = {**env, "YSD_NODE_PAIRING_CODE": pairing["code"]}
    paired = subprocess.run(
        [NODE, str(artifact), "pair", "--url", BASE, "--config", str(config)],
        cwd=home, env=pair_env, capture_output=True, text=True, timeout=180,
    )
    check("Agent 0.6.0 pairs on Protocol 1", paired.returncode == 0)
    agent_log_handle = (home / "manual-agent.log").open("w", encoding="utf8")
    agent = subprocess.Popen(
        [NODE, str(artifact), "run", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, stdout=agent_log_handle, stderr=subprocess.STDOUT, text=True,
    )
    for _ in range(40):
        time.sleep(2)
        _, nodes_body = operator.request("GET", "/api/nodes")
        match = [item for item in (nodes_body or {}).get("nodes", []) if item.get("name") == f"Phase 19 Node {RUN}"]
        if match and match[0].get("status") == "online":
            node_id = match[0]["id"]
            break
    check("manual Agent heartbeat is online", node_id is not None)
    status, body = operator.request("POST", "/api/smart-deploy", {
        "repository": FIXTURE, "branch": "main", "commit": COMMIT,
        "nodeId": node_id, "environment": "Production", "healthPath": "/",
        "memoryMb": 256, "diskQuotaBytes": 256 * 1024**2, "target": "user-node",
    }, {"Idempotency-Key": f"phase19-deploy-{RUN}"})
    deployment = (body or {}).get("deployment")
    check("private Zero Mode deployment queued", status == 202 and deployment, f"got {status}")
    deployment_id, port = deployment["id"], deployment["localPort"]
    row = wait_deployment(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    check("initial deployment is healthy", (row or {}).get("state") == "healthy", str(row))
    check("marker is served before recovery", MARKER in body_at(port))
    _, before_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    before = (before_detail or {}).get("deployment", {})
    before_artifacts = before.get("artifacts", [])
    artifact_id = before.get("currentArtifactId")
    before_artifact = next((item for item in before_artifacts if item.get("id") == artifact_id), {})
    artifact_checksum = before_artifact.get("checksum")

    print("\n=== managed Task Scheduler reboot simulation ===", flush=True)
    enabled = subprocess.run(
        [NODE, str(artifact), "autostart", "enable", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=60,
    )
    check("autostart enable succeeds", enabled.returncode == 0, enabled.stderr.strip())
    managed_roots = list((home / "managed").glob("*/install.json"))
    install = json.loads(managed_roots[0].read_text(encoding="utf8"))
    task_name = install["registrationId"]
    check("live task and managed hash exist", bool(task_xml(task_name)) and len(install["releaseHash"]) == 64)
    check("managed release equals published Agent", (Path(install["releasePath"]).read_bytes() == artifact.read_bytes()))
    xml = task_xml(task_name)
    check("task registration contains no secrets", pairing["code"] not in xml and "YSD_NODE_AGENT_KEY" not in xml)

    subprocess.run(["schtasks.exe", "/End", "/TN", task_name], capture_output=True)
    check("previous task invocation reaches idle before reboot simulation", wait_task_idle(task_name, install))
    manual_runtime_pid = pid_on_port(port)
    stopped_tree = subprocess.run(
        ["taskkill.exe", "/PID", str(agent.pid), "/T", "/F"], capture_output=True, text=True
    )
    agent.wait(timeout=20)
    agent = None
    for _ in range(40):
        if pid_on_port(port) is None and not body_at(port):
            break
        time.sleep(0.25)
    check(
        "owned manual Agent tree and its fixture runtime are absent",
        manual_runtime_pid is not None and pid_on_port(port) is None and not body_at(port),
        f"agent={agent.pid if agent else 'reaped'} runtime={manual_runtime_pid} taskkill={stopped_tree.returncode}",
    )
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], check=True, capture_output=True)
    managed_started = False
    for _ in range(30):
        time.sleep(0.5)
        managed = managed_processes(install)
        if managed.get("launcherCount") == 1 and managed.get("agentCount") == 1:
            managed_started = True
            break
    check("one launcher owns one Agent immediately after managed start", managed_started)
    saw_recovering = False
    for _ in range(30):
        time.sleep(1)
        _, recovery_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
        recovery_row = (recovery_detail or {}).get("deployment", {})
        if (
            recovery_row.get("observedState") == "recovering"
            or recovery_row.get("recoveryStatus") in {"pending", "running", "succeeded"}
            or recovery_row.get("lastReconciledAt") is not None
        ):
            saw_recovering = True
            break
    check("fresh managed generation enters Phase 18 reconciliation", saw_recovering)
    recovered = wait_deployment(operator, deployment_id, {"healthy", "failed", "blocked", "timed_out"}, limit=90)
    for _ in range(40):
        if MARKER in body_at(port):
            break
        time.sleep(1)
    check(
        "headless Agent restores healthy runtime",
        (recovered or {}).get("state") == "healthy" and MARKER in body_at(port),
        json.dumps({
            "state": (recovered or {}).get("state"),
            "observedState": (recovered or {}).get("observedState"),
            "recoveryStatus": (recovered or {}).get("recoveryStatus"),
            "recoveryReasonCode": (recovered or {}).get("recoveryReasonCode"),
            "served": MARKER in body_at(port),
        }),
    )
    _, after_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    after = (after_detail or {}).get("deployment", {})
    check("same deployment, node, and port recover", after.get("id") == deployment_id and after.get("nodeId") == node_id and after.get("localPort") == port)
    after_artifact = next((item for item in after.get("artifacts", []) if item.get("id") == artifact_id), {})
    check(
        "same verified artifact and checksum recover with no new build",
        after.get("currentArtifactId") == artifact_id
        and len(after.get("artifacts", [])) == len(before_artifacts)
        and artifact_checksum
        and after_artifact.get("checksum") == artifact_checksum,
    )
    _, audit_body = operator.request("GET", "/api/audit?action=deployment.recovery&limit=100")
    deployment_recovery_events = [
        event for event in (audit_body or {}).get("events", [])
        if event.get("resourceId") == deployment_id
    ]
    recovery_events = [event for event in deployment_recovery_events if event.get("outcome") == "success"]
    check(
        "exactly one automatic recovery evidence path succeeds",
        len(recovery_events) == 1,
        json.dumps([
            {"actorType": event.get("actorType"), "actorId": event.get("actorId"),
             "outcome": event.get("outcome"), "metadata": event.get("metadata")}
            for event in deployment_recovery_events
        ]),
    )
    managed_log = "\n".join(file.read_text(encoding="utf8", errors="replace") for file in (Path(install["workingDirectory"]) / "logs").glob("*.log"))
    check("recovery performs no GitHub fetch, npm, or build", not re.search(r"github\.com|\bnpm\b|\bbuilding\b", managed_log, re.I))

    print("\n=== duplicate and later managed restart ===", flush=True)
    duplicate_process = subprocess.Popen(
        [NODE, str(artifact), "run", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        _, duplicate_error = duplicate_process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill.exe", "/PID", str(duplicate_process.pid), "/T", "/F"], capture_output=True)
        _, duplicate_error = duplicate_process.communicate(timeout=10)
    check("manual duplicate is refused", duplicate_process.returncode == 20 and "already_running" in duplicate_error)
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], capture_output=True)
    check("task invoked twice remains one registration and one runtime", bool(task_xml(task_name)) and pid_on_port(port) is not None)
    managed = managed_processes(install)
    check(
        "exactly one launcher owns exactly one managed Agent child",
        managed.get("launcherCount") == 1 and managed.get("agentCount") == 1 and managed.get("agentPid") is not None,
    )
    before_status = json.loads(Path(install["workingDirectory"], "status.json").read_text(encoding="utf8"))
    subprocess.run(["schtasks.exe", "/End", "/TN", task_name], capture_output=True)
    idle_again = wait_task_idle(task_name, install)
    check("managed task reaches idle before a later Agent start", idle_again)
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], check=True, capture_output=True)
    restarted = False
    for _ in range(45 if idle_again else 0):
        time.sleep(1)
        current = json.loads(Path(install["workingDirectory"], "status.json").read_text(encoding="utf8"))
        managed = managed_processes(install)
        if (
            current.get("lastStartAt", 0) > (before_status.get("lastStartAt") or 0)
            and managed.get("launcherCount") == 1
            and managed.get("agentCount") == 1
        ):
            restarted = True
            break
    check("native manager starts exactly one later Agent", restarted)
    recovered_again = wait_deployment(operator, deployment_id, {"healthy", "failed", "blocked", "timed_out"}, limit=90)
    check(
        "a successful previous recovery does not suppress recovery after a later Agent start",
        (recovered_again or {}).get("state") == "healthy" and MARKER in body_at(port),
    )

    print("\n=== intentional Stop remains stopped ===", flush=True)
    status, _ = operator.request(
        "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "stop"},
        {"Idempotency-Key": f"phase19-stop-{RUN}"},
    )
    check("intentional Stop queued", status == 202, f"got {status}")
    stopped = wait_deployment(operator, deployment_id, {"stopped", "failed"})
    check("desired state is stopped", (stopped or {}).get("state") == "stopped")
    subprocess.run(["schtasks.exe", "/End", "/TN", task_name], capture_output=True)
    check("stopped task reaches idle before final start", wait_task_idle(task_name, install))
    subprocess.run(["schtasks.exe", "/Run", "/TN", task_name], check=True, capture_output=True)
    time.sleep(8)
    _, final_detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    final = (final_detail or {}).get("deployment", {})
    check("fresh managed Agent never reopens intentional Stop", final.get("desiredState") == "stopped" and not body_at(port))
    print(f"\nBROWSER_EMAIL={email}\nBROWSER_PASSWORD={password}\nBROWSER_NODE={node_id}")
finally:
    if FAILED and task_name:
        status_path = Path(install["workingDirectory"]) / "status.json"
        if status_path.exists():
            print("\nDIAGNOSTIC_MANAGED_STATUS=" + status_path.read_text(encoding="utf8", errors="replace")[:2000])
        managed_logs = "\n".join(
            file.read_text(encoding="utf8", errors="replace")
            for file in (Path(install["workingDirectory"]) / "logs").glob("*.log")
        )
        print("DIAGNOSTIC_MANAGED_LOG_TAIL=" + managed_logs[-6000:])
        print("DIAGNOSTIC_CONTROL_PLANE_ALIVE=" + str(control_plane is None or control_plane.poll() is None))
    if agent is not None:
        agent.terminate()
        try:
            agent.wait(timeout=15)
        except subprocess.TimeoutExpired:
            agent.kill()
    if agent_log_handle is not None:
        agent_log_handle.close()
    if task_name:
        subprocess.run(
            [NODE, str(artifact), "autostart", "uninstall", "--config", str(config)],
            cwd=home, env=env, capture_output=True, text=True, timeout=60,
        )
        subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True)
    if port:
        process = pid_on_port(port)
        if process:
            subprocess.run(["taskkill.exe", "/PID", str(process), "/F"], capture_output=True)
    if node_id:
        try:
            operator.request("DELETE", f"/api/nodes/{node_id}")
        except OSError:
            pass
    if control_plane is not None:
        subprocess.run(
            ["taskkill.exe", "/PID", str(control_plane.pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )
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
