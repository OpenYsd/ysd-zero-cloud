"""Phase 21 central local gate: an artifact is backed up, lost, and put back.

Runs only against a local control plane this script owns. It writes its backup
to a directory outside everything the Agent manages -- standing in for the
external disk an operator would really use -- and it deletes exactly one
artifact directory, the one it created.

The claim under test is narrow and worth stating: losing the local bytes of a
deployment's current artifact is recoverable from a backup, on the same node,
without fetching source, installing dependencies, or building anything.
"""

import base64
import hashlib
import hmac
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

from acceptance_preflight import app_runtime_port_minimum, probe_port

REPO = Path(__file__).resolve().parent
REQUESTED_BASE = os.environ.get("YSD_PHASE21_BASE")
BASE = REQUESTED_BASE or ""
AUTH_ORIGIN = "http://localhost:3000"
NODE = os.environ.get(
    "YSD_ACCEPTANCE_NODE",
    r"C:\Users\qazpl\AppData\Local\Temp\ysd-node-v26.8.1\node-v26.8.1-win-x64\node.exe",
)
CURRENT_AGENT_VERSION = json.loads(
    (REPO / "public/agent/manifest.json").read_text(encoding="utf8")
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


# A second node exists only to be refused. It never runs anything: it holds a
# real credential so the confirmation is attacked the way a compromised or
# buggy Agent would attack it, not with an anonymous request.
INTRUDER_CAPABILITIES = {
    "cpu": {"cores": 4, "model": "Phase 21 Intruder CPU"},
    "memory": {"totalBytes": 8 * 1024**3, "freeBytes": 6 * 1024**3},
    "gpu": {"available": False, "model": None, "vramBytes": None},
    "disk": {"totalBytes": 64 * 1024**3, "freeBytes": 48 * 1024**3},
    "docker": {"available": False},
    "ai": {"runtimes": [], "cachedModels": [], "maxConcurrentJobs": 1},
    "gameServers": {
        "minecraftJavaAvailable": False, "javaVersion": None,
        "activeServers": 0, "maxConcurrentServers": 1,
    },
    "appRuntime": {
        "available": True, "nodeVersion": "26.8.1", "nodeMajor": 26,
        "permissionModel": True, "networkGuard": True,
        "packageManagers": ["npm"], "activeDeployments": 0, "maxDeployments": 12,
    },
    "contracts": {"ai": False, "gameServers": False, "appRuntime": True},
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()
        )
        # Counts deployment actions once the restore half begins. The central
        # Phase 21 claim is that recovery needs no operator command, and this
        # is what makes that claim checkable rather than merely intended.
        self.count_actions = False
        self.actions_after_restore = 0

    def request(self, method, route, body=None, headers=None, retries=3):
        if self.count_actions and route.endswith("/actions") and method == "POST":
            self.actions_after_restore += 1
        raw = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            BASE + route,
            data=raw,
            method=method,
            headers={
                "Content-Type": "application/json",
                # Local auth trusts this fixed development origin. Requests
                # still go to the isolated control plane this script owns.
                "Origin": AUTH_ORIGIN,
                "Referer": AUTH_ORIGIN + "/",
                "CF-Connecting-IP": CLIENT_ADDRESS,
                "User-Agent": "ysd-phase21-local/1.0",
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


def signed_node_post(token, path, body):
    """One signed `ysd-node-request-v1` POST, as an Agent would send it."""
    raw = json.dumps(body, separators=(",", ":"))
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(18)).rstrip(b"=").decode()
    timestamp = int(time.time() * 1000)
    body_hash = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()).rstrip(b"=").decode()
    message = "\n".join(["ysd-node-request-v1", "POST", path, str(timestamp), nonce, body_hash])
    signature = base64.urlsafe_b64encode(
        hmac.new(token.encode(), message.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    request = urllib.request.Request(
        f"{BASE}{path}", data=raw.encode(), method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {token}",
            "X-YSD-Timestamp": str(timestamp), "X-YSD-Nonce": nonce,
            "X-YSD-Signature": signature,
            "User-Agent": "ysd-phase21-local-agent/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def port_open(port):
    """True when anything at all is listening on the private port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.5)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def deployment_detail(client, deployment_id):
    _, body = client.request("GET", f"/api/deployments/{deployment_id}")
    return (body or {}).get("deployment", {})


def artifact_availability(client, deployment_id, artifact_id):
    """What the control plane currently believes about one artifact's bytes."""
    detail = deployment_detail(client, deployment_id)
    for artifact in detail.get("artifacts", []):
        if artifact.get("id") == artifact_id:
            return artifact.get("availabilityState")
    return None


def runtime_job_count(client):
    """Every App Runtime job the control plane has, recovery or otherwise.

    The jobs projection does not expose which actor queued one, and widening
    it to suit a test would be the wrong trade. Counting all of them is the
    stronger claim anyway: with no operator command issued, a single new App
    Runtime job in this window can only be the automatic recovery.
    """
    _, body = client.request("GET", "/api/nodes")
    return sum(
        1 for job in (body or {}).get("jobs", [])
        if job.get("type") == "app-runtime.action"
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_checksum(directory):
    """The App Runtime's own checksum: sorted path, NUL, bytes, NUL."""
    digest = hashlib.sha256()
    files = []
    for current, _, names in os.walk(directory):
        for name in names:
            full = Path(current) / name
            relative = str(full.relative_to(directory)).replace(os.sep, "/")
            if relative == ".ysd-artifact.json":
                continue
            files.append((relative, full))
    for relative, full in sorted(files):
        digest.update(relative.encode())
        digest.update(b"\x00")
        digest.update(full.read_bytes())
        digest.update(b"\x00")
    return "sha256:" + digest.hexdigest()


home = Path(tempfile.mkdtemp(prefix="ysd-phase21-"))
# The backup destination stands in for an external disk: outside the Agent
# home, outside the managed root, outside app-runtime storage.
external = Path(tempfile.mkdtemp(prefix="ysd-phase21-external-"))
config = home / "credentials.json"
SYSTEM32 = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32")
env = {
    **os.environ,
    "PATH": SYSTEM32 + os.pathsep + os.environ.get("PATH", ""),
    "YSD_NODE_AGENT_HOME": str(home),
    "YSD_NODE_CONFIG": str(config),
    "LOCALAPPDATA": str(home),
    "XDG_DATA_HOME": str(home),
}
env.pop("YSD_NODE_AGENT_KEY", None)

agent = None
agent_log_handle = None
control_plane = None
control_plane_log_handle = None
control_plane_log_path = home / "control-plane.log"
deployment_id = None
port = None
node_id = None
artifact_path = None


def run_agent(artifact, args, timeout=600):
    return subprocess.run(
        [NODE, str(artifact), *args, "--config", str(config)],
        cwd=home, env=env, capture_output=True, text=True, timeout=timeout,
    )


def last_json(result):
    for line in reversed((result.stdout or "").strip().splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"stderr": (result.stderr or "").strip()[:300]}


def start_agent():
    global agent, agent_log_handle
    agent_log_handle = (home / "agent.log").open("a", encoding="utf8")
    return subprocess.Popen(
        [NODE, str(current_agent), "run", "--url", BASE, "--config", str(config)],
        cwd=home, env=env, stdout=agent_log_handle, stderr=subprocess.STDOUT, text=True,
    )


def stop_agent(process):
    if process is None:
        return
    subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()


try:
    manifest = json.loads((REPO / "public/agent/manifest.json").read_text(encoding="utf8"))
    current_agent = REPO / "public/agent" / manifest["filename"]
    check(f"Agent {CURRENT_AGENT_VERSION} is the built artifact",
          manifest["version"] == CURRENT_AGENT_VERSION and manifest["protocolVersion"] == 1)

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
            cwd=REPO, stdout=control_plane_log_handle, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        wait_control_plane(control_plane, control_plane_log_path)
        check("harness owns a live isolated control plane", control_plane.poll() is None)

    operator = Client()
    print("\n=== controlled node and safe fixture ===", flush=True)
    email = f"phase21-{RUN}@ysd.test"
    password = f"phase21-local-{RUN}-longpassword"
    status, _ = operator.request("POST", "/api/auth/sign-up/email",
                                 {"name": "Phase 21 Operator", "email": email, "password": password})
    if not check("authenticated local session", status == 200, f"got {status}"):
        raise RuntimeError("local session not established")

    status, body = operator.request("POST", "/api/nodes", {"name": f"Phase 21 Node {RUN}"})
    pairing = (body or {}).get("pairing")
    if not check("controlled pairing ticket", status == 201 and pairing, f"got {status}"):
        raise RuntimeError("pairing ticket not created")
    paired = subprocess.run(
        [NODE, str(current_agent), "pair", "--url", BASE, "--config", str(config)],
        cwd=home, env={**env, "YSD_NODE_PAIRING_CODE": pairing["code"]},
        capture_output=True, text=True, timeout=180,
    )
    check(f"Agent {CURRENT_AGENT_VERSION} pairs on Protocol 1", paired.returncode == 0,
          paired.stderr.strip()[:200])

    agent = start_agent()
    for _ in range(40):
        time.sleep(2)
        _, nodes_body = operator.request("GET", "/api/nodes")
        match = [n for n in (nodes_body or {}).get("nodes", []) if n.get("name") == f"Phase 21 Node {RUN}"]
        if match and match[0].get("status") == "online":
            node_id = match[0]["id"]
            break
    check("controlled node is online", node_id is not None)
    _, nodes_body = operator.request("GET", "/api/nodes")
    node_row = next((n for n in (nodes_body or {}).get("nodes", []) if n["id"] == node_id), {})
    capability = node_row.get("capabilities", {}).get("artifactBackup", {})
    check("node reports the artifact-backup capability",
          capability.get("supported") is True and capability.get("offlineVerify") is True
          and capability.get("sameNodeRestore") is True, json.dumps(capability))
    check("the capability carries no path, filename or device",
          not re.search(r"[A-Za-z]:\\\\|/|\.ysdbak", json.dumps(capability)), json.dumps(capability))

    status, body = operator.request("POST", "/api/smart-deploy", {
        "repository": FIXTURE, "branch": "main", "commit": COMMIT,
        "nodeId": node_id, "environment": "Production", "healthPath": "/",
        "memoryMb": 256, "diskQuotaBytes": 256 * 1024 ** 2, "target": "user-node",
    }, {"Idempotency-Key": f"phase21-deploy-{RUN}"})
    deployment = (body or {}).get("deployment")
    if not check("private Zero Mode deployment queued", status == 202 and deployment,
                 f"got {status}: {json.dumps(body)[:300]}"):
        raise RuntimeError("deployment not queued")
    deployment_id = deployment["id"]
    preferred = deployment["localPort"]
    row = wait_deployment(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    # The creation response carries the port the allocator *proposed*. Where the
    # operating system refuses it -- Windows reserves blocks for Hyper-V and WSL
    # and denies them with EACCES while reporting nothing listening -- Agent 0.8
    # finds a bindable one and the control plane records that instead. So the
    # authoritative port is read back here, not assumed; everything downstream,
    # including the "same port" claim across restore, uses this value.
    port = (row or {}).get("localPort", preferred)
    preferred_bindable, preferred_code = probe_port(preferred)
    print("PORT_NEGOTIATION=" + json.dumps({
        "preferredPort": preferred,
        "preferredBindable": preferred_bindable,
        "preferredOsError": preferred_code,
        "authoritativePort": port,
        "negotiated": port != preferred,
        "localAddress": (row or {}).get("localAddress"),
    }), flush=True)
    check("deployment is healthy", (row or {}).get("state") == "healthy", json.dumps({
        key: (row or {}).get(key) for key in
        ("state", "observedState", "localPort", "localAddress", "lastError")
    }, default=str))
    check("the authoritative port is bindable on this host", probe_port(port)[0],
          f"port {port} reported unbindable")
    if not preferred_bindable:
        check("an unbindable preferred port was renegotiated", port != preferred,
              f"still assigned the unbindable {preferred}")
        check("the control plane records the negotiated port",
              (row or {}).get("localAddress") == f"http://127.0.0.1:{port}",
              str((row or {}).get("localAddress")))
        check("the negotiated port stays inside the private App Runtime range",
              app_runtime_port_minimum(REPO) <= port <= 41999, f"got {port}")
    check("marker is served before the backup", MARKER in body_at(port))
    if os.environ.get("YSD_PHASE21_PORT_ONLY"):
        # Feature-focused run: the port negotiation is the subject, so stop
        # before the backup work rather than pretending a partial suite ran.
        print("PORT_ONLY stop after the deployment gate", flush=True)
        raise SystemExit(0 if not FAILED else 1)

    before = deployment_detail(operator, deployment_id)
    artifact_id = before.get("currentArtifactId")
    before_artifacts = before.get("artifacts", [])
    before_checksum = next((a.get("checksum") for a in before_artifacts if a.get("id") == artifact_id), None)
    project_id = before.get("projectId")
    # Locate the artifact by shape rather than by guessing the workspace id.
    matches = list((home / ".ysd-app-runtime" / "workspaces").glob(
        f"*/projects/{project_id}/deployments/{deployment_id}/artifacts/{artifact_id}"))
    artifact_path = matches[0] if matches else None
    if artifact_path is None:
        raise RuntimeError("the controlled artifact directory was not found on disk")
    check("the controlled artifact exists on disk", artifact_path.is_dir(), str(artifact_path))
    check("recorded deployment, node, port, artifact and checksum",
          all([deployment_id, node_id, port, artifact_id, before_checksum]),
          json.dumps({"deployment": deployment_id, "port": port, "artifact": artifact_id,
                      "artifacts": len(before_artifacts)}))

    print("\n=== create the backup on a user-controlled path ===", flush=True)
    created = run_agent(current_agent, ["artifact", "backup", "create",
                                        "--artifact", str(artifact_id), "--output", str(external)])
    create_result = last_json(created)
    check("backup created", created.returncode == 0 and create_result.get("outcome") == "created",
          json.dumps(create_result)[:300])
    bundle = Path(create_result.get("bundle", "")) if create_result.get("bundle") else None
    check("the bundle is outside everything the Agent manages",
          bundle is not None and bundle.exists() and str(home) not in str(bundle),
          str(bundle))
    check("the bundle checksum matches the artifact the control plane recorded",
          create_result.get("artifactChecksum") == before_checksum,
          f"{create_result.get('artifactChecksum')} vs {before_checksum}")
    check("the reported outer digest matches the file on disk",
          bundle is not None and sha256_file(bundle) == create_result.get("bundleSha256"))
    check("no partial bundle is left behind",
          sorted(p.name for p in external.iterdir()) == [bundle.name] if bundle else False,
          str(sorted(p.name for p in external.iterdir())))

    # Creating a backup must not disturb the running application.
    after_create = deployment_detail(operator, deployment_id)
    check("creating a backup changed nothing about the deployment",
          after_create.get("currentArtifactId") == artifact_id
          and after_create.get("state") == "healthy"
          and len(after_create.get("artifacts", [])) == len(before_artifacts)
          and MARKER in body_at(port))

    print("\n=== YSD credentials must not be in the bundle ===", flush=True)
    credential_bytes = config.read_bytes()
    bundle_bytes = bundle.read_bytes()
    secrets_absent = [
        ("pairing code", pairing["code"].encode()),
        ("credential file bytes", credential_bytes),
        ("node id", str(node_id).encode()),
    ]
    leaked = [name for name, needle in secrets_absent if needle and needle in bundle_bytes]
    check("no YSD credential material is present in the bundle", not leaked, ",".join(leaked))
    check("the node token is absent", not re.search(rb"node_[A-Za-z0-9_.-]{30,}", bundle_bytes))

    print("\n=== offline verification, with the control plane stopped ===", flush=True)
    if control_plane is not None:
        subprocess.run(["taskkill.exe", "/PID", str(control_plane.pid), "/T", "/F"], capture_output=True)
        try:
            control_plane.wait(timeout=20)
        except subprocess.TimeoutExpired:
            control_plane.kill()
        time.sleep(2)
    reachable = True
    try:
        urllib.request.urlopen(BASE + "/", timeout=3)
    except Exception:
        reachable = False
    check("the control plane really is unavailable", not reachable or REQUESTED_BASE is not None)
    # No --config: verification needs no credential at all.
    verified = subprocess.run([NODE, str(current_agent), "artifact", "backup", "verify", str(bundle)],
                              cwd=home, env=env, capture_output=True, text=True, timeout=300)
    verify_result = last_json(verified)
    check("offline verify succeeds without credential or control plane",
          verified.returncode == 0 and verify_result.get("outcome") == "verified",
          json.dumps(verify_result)[:300])
    check("offline verify reports the exact artifact identity",
          verify_result.get("artifactId") == artifact_id
          and verify_result.get("artifactChecksum") == before_checksum
          and verify_result.get("deploymentId") == deployment_id)
    check("offline verify output carries no path or secret",
          not re.search(r"[A-Za-z]:\\\\|node_[A-Za-z0-9]{20,}|\.ysdbak", json.dumps(verify_result)),
          json.dumps(verify_result)[:200])

    corrupt = external / f"corrupt-{RUN}.ysdbak"
    payload = bytearray(bundle_bytes)
    marker_at = payload.find(b"d3js.org")
    if marker_at > 0:
        payload[marker_at] ^= 0x01
    corrupt.write_bytes(bytes(payload))
    corrupted = subprocess.run([NODE, str(current_agent), "artifact", "backup", "verify", str(corrupt)],
                               cwd=home, env=env, capture_output=True, text=True, timeout=300)
    check("a corrupted bundle fails offline verification",
          corrupted.returncode != 0 and "payload_mismatch" in (corrupted.stderr or ""),
          (corrupted.stderr or "").strip()[:160])
    corrupt.unlink(missing_ok=True)

    if control_plane is not None:
        control_plane_log_handle = control_plane_log_path.open("a", encoding="utf8")
        control_plane = subprocess.Popen(
            ["node.exe", str(REPO / "node_modules/vinext/dist/cli.js"), "dev",
             "--hostname", "127.0.0.1", "--port", str(BASE.rsplit(":", 1)[1])],
            cwd=REPO, stdout=control_plane_log_handle, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        wait_control_plane(control_plane, control_plane_log_path)
        check("control plane is back for the restore half", control_plane.poll() is None)

    print("\n=== lose the artifact ===", flush=True)
    status, _ = operator.request("POST", f"/api/deployments/{deployment_id}/actions",
                                 {"operation": "stop"}, {"Idempotency-Key": f"phase21-stop-{RUN}"})
    check("controlled runtime stop queued", status == 202, f"got {status}")
    stopped = wait_deployment(operator, deployment_id, {"stopped", "failed"})
    check("controlled runtime is stopped", (stopped or {}).get("state") == "stopped")
    stop_agent(agent)
    agent = None

    log_before_restore = (home / "agent.log").read_text(encoding="utf8", errors="replace")
    shutil.rmtree(artifact_path)
    check("only the controlled artifact directory was removed",
          not artifact_path.exists() and artifact_path.parent.exists())

    # Bring the deployment back to Running with the artifact absent, so Phase 18
    # is asked to recover something that is not there.
    status, _ = operator.request("POST", f"/api/deployments/{deployment_id}/actions",
                                 {"operation": "start"}, {"Idempotency-Key": f"phase21-start-{RUN}"})
    check("start requested with the artifact missing", status == 202, f"got {status}")
    agent = start_agent()
    missing_state = None
    for _ in range(45):
        time.sleep(2)
        detail = deployment_detail(operator, deployment_id)
        if detail.get("recoveryReasonCode") in {"artifact_missing", "artifact_corrupted"}:
            missing_state = detail
            break
    check("Phase 18 reports the artifact as missing and cannot recover",
          missing_state is not None,
          json.dumps({"reason": (missing_state or deployment_detail(operator, deployment_id)).get("recoveryReasonCode"),
                      "observed": (missing_state or {}).get("observedState")}))
    check("nothing is serving on the private port", not body_at(port))
    before_availability = artifact_availability(operator, deployment_id, artifact_id)
    check("the control plane records the artifact as missing",
          before_availability == "missing", f"got {before_availability}")
    recoveries_before = runtime_job_count(operator)

    print("\n=== restore from the backup ===", flush=True)
    # From here on, any deployment action this harness sends is a failure of
    # the thing being proved, so they are counted rather than trusted.
    operator.count_actions = True
    restored = run_agent(current_agent, ["artifact", "backup", "restore", str(bundle)])
    restore_result = last_json(restored)
    check("restore succeeds on the same node",
          restored.returncode == 0 and restore_result.get("outcome") == "restored",
          json.dumps(restore_result)[:300])
    check("the artifact directory is back", artifact_path.is_dir())
    check("the restored payload checksum is exact",
          artifact_checksum(artifact_path) == before_checksum,
          f"{artifact_checksum(artifact_path)} vs {before_checksum}")
    runtime_manifest = json.loads((artifact_path / ".ysd-artifact.json").read_text(encoding="utf8"))
    check("a fresh runtime manifest was written for this node",
          runtime_manifest.get("checksum") == before_checksum
          and isinstance(runtime_manifest.get("signature"), str)
          and runtime_manifest.get("artifactId") == artifact_id)
    check("no restore staging survives", not (artifact_path.parent.parent / ".restore-tmp").exists()
          or not any((artifact_path.parent.parent / ".restore-tmp").iterdir()))

    print("\n=== Phase 18 recovers with no operator Start ===", flush=True)
    # The restore told the control plane, in one signed same-node statement,
    # that this exact artifact is back. That is the whole difference: the
    # artifact stops being "missing", the condition blocking recovery is the
    # one that statement answers, and ordinary reconciliation takes it from
    # there. Nothing below issues Start, restart, or any runtime command.
    after_availability = artifact_availability(operator, deployment_id, artifact_id)
    check("the control plane records the artifact as available again",
          after_availability in {"present", "verified"}, f"got {after_availability}")
    recovered = wait_deployment(operator, deployment_id, {"healthy"}, limit=120)
    for _ in range(40):
        if MARKER in body_at(port):
            break
        time.sleep(1)
    check("the application is healthy again with no Start command",
          (recovered or {}).get("state") == "healthy" and MARKER in body_at(port),
          json.dumps({"state": (recovered or {}).get("state"),
                      "recovery": (recovered or {}).get("recoveryReasonCode"),
                      "served": MARKER in body_at(port)}))
    check("no application Start was issued after the artifact was restored",
          operator.actions_after_restore == 0,
          f"{operator.actions_after_restore} deployment action(s) were sent")
    healthy = deployment_detail(operator, deployment_id)
    check("the recovery condition is over, not merely overtaken",
          healthy.get("recoveryReasonCode") in (None, "recovery_succeeded"),
          json.dumps({"recovery": healthy.get("recoveryReasonCode")}))
    recoveries_after = runtime_job_count(operator)
    check("exactly one App Runtime job ran, and it was the recovery",
          recoveries_after - recoveries_before == 1,
          f"{recoveries_after - recoveries_before} App Runtime jobs")
    after = deployment_detail(operator, deployment_id)
    check("same deployment, node and port",
          after.get("id") == deployment_id and after.get("nodeId") == node_id
          and after.get("localPort") == port)
    after_artifact = next((a for a in after.get("artifacts", []) if a.get("id") == artifact_id), {})
    check("same artifact id, same checksum, no new artifact",
          after.get("currentArtifactId") == artifact_id
          and after_artifact.get("checksum") == before_checksum
          and len(after.get("artifacts", [])) == len(before_artifacts),
          json.dumps({"artifacts": len(after.get("artifacts", [])), "before": len(before_artifacts)}))
    log_after_restore = (home / "agent.log").read_text(encoding="utf8", errors="replace")
    recovery_window = log_after_restore[len(log_before_restore):]
    check("recovery performed no GitHub fetch, no npm and no build",
          not re.search(r"github\.com|\bnpm\b|installing dependencies|\bbuilding\b", recovery_window, re.I),
          recovery_window[-200:].replace("\n", " | "))


    print("\n=== restore confirmation refuses everything else ===", flush=True)
    # The confirmation is the only write this feature makes, so it is attacked
    # with a real credential: a second node, genuinely paired to the same
    # workspace, holding a valid token. Phase 21 is same-node only, and this is
    # what that has to mean in practice.
    status, ticket = operator.request("POST", "/api/nodes", {"name": f"Phase 21 Intruder {RUN}"})
    intruder_code = (ticket or {}).get("pairing", {}).get("code")
    check("a second node pairing ticket was issued", status == 201 and bool(intruder_code),
          f"got {status}")
    status, paired = operator.request("POST", "/api/nodes/agent/pair", {
        "code": intruder_code, "agentVersion": CURRENT_AGENT_VERSION, "protocolVersion": 1,
        "platform": "win32", "architecture": "x64",
        "capabilities": INTRUDER_CAPABILITIES,
    })
    intruder_token = (paired or {}).get("token")
    intruder_id = (paired or {}).get("nodeId")
    check("the second node paired", status == 201 and bool(intruder_token), f"got {status}")

    confirm_path = f"/api/nodes/agent/deployments/{deployment_id}/restore-complete"
    attempts = [
        ("another node confirming this node's artifact",
         confirm_path, {"artifactId": artifact_id, "checksum": before_checksum}),
        ("another node naming a deployment that is not its own",
         f"/api/nodes/agent/deployments/{'dpl_' + 'c' * 24}/restore-complete",
         {"artifactId": artifact_id, "checksum": before_checksum}),
        ("a malformed artifact id",
         confirm_path, {"artifactId": "art_nope", "checksum": before_checksum}),
        ("a malformed checksum",
         confirm_path, {"artifactId": artifact_id, "checksum": "not-a-digest"}),
        ("a checksum that matches nothing",
         confirm_path, {"artifactId": artifact_id, "checksum": "sha256:" + "0" * 64}),
        ("an artifact id that is not the current release",
         confirm_path, {"artifactId": "art_" + "b" * 24, "checksum": before_checksum}),
        ("a missing checksum", confirm_path, {"artifactId": artifact_id}),
        ("a missing artifact id", confirm_path, {"checksum": before_checksum}),
        ("an empty body", confirm_path, {}),
    ]
    for label, target, payload in attempts:
        code = signed_node_post(intruder_token, target, payload)
        check(f"restore confirmation refuses {label}", code in {400, 404, 409},
              f"got {code}")

    # A revoked credential is refused even when everything else is correct.
    status, _ = operator.request("DELETE", f"/api/nodes/{intruder_id}")
    check("the second node was revoked", status == 200, f"got {status}")
    code = signed_node_post(intruder_token, confirm_path,
                            {"artifactId": artifact_id, "checksum": before_checksum})
    check("restore confirmation refuses a revoked node", code in {401, 403, 404},
          f"got {code}")

    # None of that may have moved a single field.
    after_negative = deployment_detail(operator, deployment_id)
    negative_artifact = next(
        (a for a in after_negative.get("artifacts", []) if a.get("id") == artifact_id), {})
    check("refused confirmations changed no state",
          negative_artifact.get("checksum") == before_checksum
          and negative_artifact.get("availabilityState") in {"present", "verified"}
          and after_negative.get("currentArtifactId") == artifact_id
          and after_negative.get("nodeId") == node_id
          and len(after_negative.get("artifacts", [])) == len(before_artifacts),
          json.dumps({"artifacts": len(after_negative.get("artifacts", [])),
                      "current": after_negative.get("currentArtifactId"),
                      "node": after_negative.get("nodeId")}))
    check("no deployment was rebound to the second node",
          after_negative.get("nodeId") == node_id and intruder_id != node_id)

    print("\n=== restoring twice, and refusing the wrong bytes ===", flush=True)
    again = run_agent(current_agent, ["artifact", "backup", "restore", str(bundle)])
    check("restoring an artifact that is already present is a no-op",
          last_json(again).get("outcome") == "already_restored", json.dumps(last_json(again))[:200])
    check("the no-op did not disturb the running application", MARKER in body_at(port))

    print("\n=== an intentionally stopped deployment stays stopped ===", flush=True)
    status, _ = operator.request("POST", f"/api/deployments/{deployment_id}/actions",
                                 {"operation": "stop"}, {"Idempotency-Key": f"phase21-stop2-{RUN}"})
    check("second stop queued", status == 202, f"got {status}")
    stopped_again = wait_deployment(operator, deployment_id, {"stopped", "failed"})
    check("desired state is stopped", (stopped_again or {}).get("state") == "stopped")
    stop_agent(agent)
    agent = None
    shutil.rmtree(artifact_path)
    restored_stopped = run_agent(current_agent, ["artifact", "backup", "restore", str(bundle)])
    stopped_result = last_json(restored_stopped)
    check("the artifact restores while the deployment is stopped",
          restored_stopped.returncode == 0 and stopped_result.get("outcome") == "restored",
          json.dumps(stopped_result)[:200])
    check("restore reports the deployment's desired state without changing it",
          stopped_result.get("desiredState") == "stopped", json.dumps(stopped_result)[:200])
    check("the stopped artifact is recorded available again, truthfully",
          artifact_availability(operator, deployment_id, artifact_id) in {"present", "verified"},
          f"got {artifact_availability(operator, deployment_id, artifact_id)}")
    stopped_jobs_before = runtime_job_count(operator)
    agent = start_agent()
    time.sleep(25)
    final = deployment_detail(operator, deployment_id)
    check("restoring bytes never starts a stopped application",
          final.get("desiredState") == "stopped" and not body_at(port),
          json.dumps({"desired": final.get("desiredState"), "serving": bool(body_at(port))}))
    # Availability is a fact about bytes, not an instruction. Telling the truth
    # about a stopped deployment's artifact must not talk Phase 18 into
    # reviving something an operator deliberately stopped.
    check("no recovery was created for the stopped deployment",
          runtime_job_count(operator) == stopped_jobs_before,
          f"{runtime_job_count(operator) - stopped_jobs_before} new App Runtime jobs")
    check("the private port stays closed", not port_open(port))
    check("desired state was never touched by the restore",
          final.get("desiredState") == "stopped"
          and final.get("nodeId") == node_id
          and final.get("currentArtifactId") == artifact_id)

    print(f"\nBROWSER_EMAIL={email}\nBROWSER_PASSWORD={password}\nBROWSER_NODE={node_id}")

finally:
    if FAILED:
        print("\nDIAGNOSTIC_AGENT_LOG_TAIL="
              + (home / "agent.log").read_text(encoding="utf8", errors="replace")[-4000:]
              if (home / "agent.log").exists() else "")
    stop_agent(agent)
    if agent_log_handle is not None:
        agent_log_handle.close()
    if port:
        stray = pid_on_port(port)
        if stray:
            subprocess.run(["taskkill.exe", "/PID", str(stray), "/F"], capture_output=True)
    if node_id:
        try:
            Client().request("DELETE", f"/api/nodes/{node_id}")
        except OSError:
            pass
    if control_plane is not None:
        subprocess.run(["taskkill.exe", "/PID", str(control_plane.pid), "/T", "/F"], capture_output=True)
        try:
            control_plane.wait(timeout=20)
        except subprocess.TimeoutExpired:
            control_plane.kill()
    if control_plane_log_handle is not None:
        control_plane_log_handle.close()
    for directory in (home, external):
        for _ in range(10):
            try:
                shutil.rmtree(directory)
                break
            except FileNotFoundError:
                break
            except OSError:
                time.sleep(0.5)

print("\n=== cleanup ===")
check("temporary Agent home removed", not home.exists())
check("controlled backup destination removed", not external.exists())
print(f"\nPASSED {len(PASSED)}  FAILED {len(FAILED)}")
for failure in FAILED:
    print("  FAIL — " + failure)
sys.exit(1 if FAILED else 0)
