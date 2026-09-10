"""Phase 22 central local gate: an artifact is backed up, lost, and put back.

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
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from acceptance_ports import (
    port_holder_row,
    release_reserved_ports,
    reserve_specific_port,
)
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
    "cpu": {"cores": 4, "model": "Phase 22 Intruder CPU"},
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
        # Phase 22 claim is that recovery needs no operator command, and this
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
                "User-Agent": "ysd-phase22-local/1.0",
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


def body_at_path(client, path):
    """One authenticated page from the local control plane, as HTML.

    The session is the opener's cookie jar inside `Client`, so this goes
    through the same `request()` every other call uses rather than rebuilding
    or forging anything. A non-JSON body comes back already decoded, which is
    exactly what an HTML page is.
    """
    status, body = client.request("GET", path)
    return body if isinstance(body, str) and status == 200 else ""


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


def signed_node_json(token, path, body):
    """One signed `ysd-node-request-v1` POST, returning `(status, parsed body)`.

    Phase 22 needs what a preflight *says* -- which artifact it reserved -- not
    just whether it was accepted, so this is the shape those checks use.
    `signed_node_post` below keeps its original status-only contract.
    """
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
            "User-Agent": "ysd-phase22-local-agent/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    try:
        return status, json.loads(payload) if payload else None
    except json.JSONDecodeError:
        return status, None


def signed_node_post(token, path, body):
    """One signed POST, as an Agent would send it. Returns the status only."""
    return signed_node_json(token, path, body)[0]


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


home = Path(tempfile.mkdtemp(prefix="ysd-phase22-"))
# The backup destination stands in for an external disk: outside the Agent
# home, outside the managed root, outside app-runtime storage.
external = Path(tempfile.mkdtemp(prefix="ysd-phase22-external-"))
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


# ---------------------------------------------------------------------------
# Phase 22 additions to the Phase 22 scaffolding above.
#
# Everything the control plane already publishes is read through the operator
# API, exactly as the earlier harnesses do. Two facts are not published --
# how many import actions and jobs exist -- and one step has no API at all,
# because simulating a crash is not something a product should be able to do.
# Both use the local miniflare D1 file directly, read-only except for the one
# deliberately scoped deletion below. This file only exists for a local
# acceptance run; Production D1 is not reachable from here and is never touched.
# ---------------------------------------------------------------------------

LOCAL_D1 = sorted(
    (REPO / ".wrangler/state/v3/d1/miniflare-D1DatabaseObject").glob("*.sqlite"),
    key=lambda path: path.stat().st_size, reverse=True,
)


def local_d1_path():
    """The biggest sqlite file in the local miniflare D1 directory is the database."""
    candidates = sorted(
        (REPO / ".wrangler/state/v3/d1/miniflare-D1DatabaseObject").glob("*.sqlite"),
        key=lambda path: path.stat().st_size, reverse=True)
    return candidates[0] if candidates else None


def d1_read(sql, params=()):
    """Read-only access to the LOCAL acceptance database. Never Production."""
    path = local_d1_path()
    if path is None:
        return []
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        connection.close()


def import_reservation(deployment_id):
    """The three rows one authorized import must converge to."""
    jobs = d1_read(
        "SELECT id, state, payload FROM node_job WHERE idempotencyKey LIKE ?",
        (f"app:import:{deployment_id}:%",))
    actions = d1_read(
        "SELECT id, jobId, state FROM app_deployment_action "
        "WHERE deploymentId = ? AND kind = 'import'", (deployment_id,))
    provisional = d1_read(
        "SELECT id, nodeId, state FROM app_artifact "
        "WHERE deploymentId = ? AND state = 'building' AND deletedAt IS NULL",
        (deployment_id,))
    return jobs, actions, provisional


def artifact_rows(deployment_id):
    return d1_read(
        "SELECT id, nodeId, state, checksum, availabilityState, version FROM app_artifact "
        "WHERE deploymentId = ? AND deletedAt IS NULL ORDER BY createdAt", (deployment_id,))


def artifact_row(artifact_id):
    rows = d1_read(
        "SELECT id, nodeId, deploymentId, state, checksum, availabilityState, version "
        "FROM app_artifact WHERE id = ?", (artifact_id,))
    return rows[0] if rows else {}


def compute_node_row(node_id):
    rows = d1_read(
        "SELECT id, revokedAt, assignmentsDisabledAt, agentVersion, capabilities "
        "FROM compute_node WHERE id = ?", (node_id,))
    return rows[0] if rows else {}


def app_runtime_jobs(deployment_id):
    """Every App Runtime job for one deployment, by operation, from its payload."""
    rows = d1_read(
        "SELECT j.id AS id, j.state AS state, j.payload AS payload, a.kind AS kind "
        "FROM node_job j LEFT JOIN app_deployment_action a ON a.jobId = j.id "
        "WHERE j.type = 'app-runtime.action'", ())
    out = []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            continue
        if payload.get("deploymentId") == deployment_id:
            out.append({"id": row["id"], "state": row["state"],
                        "operation": payload.get("operation"), "kind": row["kind"],
                        "artifactId": payload.get("artifactId")})
    return out


def operations(deployment_id, name):
    return [job for job in app_runtime_jobs(deployment_id) if job["operation"] == name]


def inject_reservation_crash(deployment_id, artifact_id):
    """Reproduce the Prompt 3C window: the job survives, its two rows do not.

    Deliberately narrow. It asserts the exact controlled ids before and after,
    deletes exactly those two rows by primary key, and touches nothing else.
    There is no Product API for this and there should not be: a crash is not a
    feature. It exists only in this acceptance harness, against the local
    miniflare database.
    """
    jobs, actions, provisional = import_reservation(deployment_id)
    if len(jobs) != 1 or len(actions) != 1 or len(provisional) != 1:
        raise RuntimeError("crash injection refused: reservation is not 1/1/1")
    if provisional[0]["id"] != artifact_id:
        raise RuntimeError("crash injection refused: unexpected provisional artifact")
    action_id = actions[0]["id"]
    path = local_d1_path()
    connection = sqlite3.connect(path)
    try:
        removed_action = connection.execute(
            "DELETE FROM app_deployment_action WHERE id = ? AND deploymentId = ? AND kind = 'import'",
            (action_id, deployment_id)).rowcount
        removed_artifact = connection.execute(
            "DELETE FROM app_artifact WHERE id = ? AND deploymentId = ? AND state = 'building'",
            (artifact_id, deployment_id)).rowcount
        connection.commit()
    finally:
        connection.close()
    if removed_action != 1 or removed_artifact != 1:
        raise RuntimeError("crash injection removed an unexpected number of rows")
    return {"action": action_id, "artifact": artifact_id}



# The Agent seals its credential file, so its contents are not signing material.
# The legitimate way to hold N2's token is to be the party that supplied the key
# it was sealed with: the harness sets YSD_NODE_AGENT_KEY for N2's home, the
# Agent pairs and seals exactly as it always does, and this reads the envelope
# back with that key. One N2, one real pairing transaction, nothing forged and
# no second node invented to borrow a token from.
REPLACEMENT_AGENT_KEY = "ysd-phase22-" + secrets.token_hex(16)

CREDENTIAL_READER = """
const { readFileSync } = require('node:fs');
const { scryptSync, createDecipheriv } = require('node:crypto');
const envelope = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const b = (value) => Buffer.from(value, 'base64url');
const key = scryptSync(process.argv[3], b(envelope.salt), 32,
  { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const decipher = createDecipheriv('aes-256-gcm', key, b(envelope.iv));
decipher.setAuthTag(b(envelope.tag));
const plain = Buffer.concat([decipher.update(b(envelope.ciphertext)), decipher.final()]);
const parsed = JSON.parse(plain.toString('utf8'));
process.stdout.write(JSON.stringify({ nodeId: parsed.nodeId, token: parsed.token }));
"""


def read_sealed_credentials(config_path, agent_key):
    """The paired identity behind a sealed credential file. Never printed."""
    reader = second_home.parent / f"ysd-phase22-reader-{RUN}.cjs"
    reader.write_text(CREDENTIAL_READER, encoding="utf8")
    try:
        result = subprocess.run([NODE, str(reader), str(config_path), agent_key],
                                capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError("the sealed credential could not be read: " + (result.stderr or "").strip()[-160:])
        return json.loads(result.stdout)
    finally:
        reader.unlink(missing_ok=True)


def assert_signed_node_identity(node_id, token):
    """Proves a retained token really is that node's, without revealing it."""
    status = signed_node_post(token, "/api/nodes/agent/heartbeat", {
        "agentVersion": CURRENT_AGENT_VERSION,
        "protocolVersion": 1,
        "capabilities": {},
        "metrics": None,
    })
    # Any authenticated answer proves the signature verified against this node's
    # stored token. A rejected credential is 401 and nothing else.
    return status != 401 and status != 403


def authenticated_operator(email, password):
    """A second real operator session, signed in the ordinary way."""
    client = Client()
    status, _ = client.request("POST", "/api/auth/sign-in/email",
                               {"email": email, "password": password})
    if status != 200:
        return None
    probe, _ = client.request("GET", "/api/nodes")
    return client if probe == 200 else None


def wait_recovered(client, deployment_id, limit=180):
    """Wait for recovery to settle, and stop the moment it refuses.

    `wait_deployment` only knows terminal *runtime* states, so a deployment that
    recovery has blocked -- artifact unavailable, port in use -- is never going
    to reach one, and polling the full budget turns a failed acceptance into a
    hang. The recovery status is the authoritative signal that nothing further
    is coming. Same budget, no waiting past the answer.
    """
    row = None
    for _ in range(limit):
        time.sleep(2)
        row = deployment_detail(client, deployment_id)
        if row.get("state") in {"healthy", "failed", "crash_loop"}:
            return row
        exhausted = d1_read(
            "SELECT j.state, j.attempts, j.maxAttempts, j.lastError FROM node_job j "
            "JOIN app_deployment_action a ON a.jobId = j.id "
            "WHERE a.deploymentId = ? AND a.kind = 'recover' "
            "ORDER BY j.createdAt DESC LIMIT 1", (deployment_id,))
        job = exhausted[0] if exhausted else None
        if job and job["state"] in ("failed", "timed_out") \
                and (job["attempts"] or 0) >= (job["maxAttempts"] or 1):
            # Recovery ran and gave up. Waiting out the rest of the budget would
            # only delay a result that is already decided.
            print("RECOVERY_FAILED=" + json.dumps({
                "state": row.get("state"), "observedState": row.get("observedState"),
                "recoveryStatus": row.get("recoveryStatus"),
                "recoveryReasonCode": row.get("recoveryReasonCode"),
                "recoverJobState": job["state"], "attempts": job["attempts"],
                "lastError": (job["lastError"] or "")[:200],
                "currentArtifactId": row.get("currentArtifactId"),
                "localPort": row.get("localPort"),
            }), flush=True)
            return row
        if row.get("recoveryStatus") == "blocked":
            print("RECOVERY_BLOCKED=" + json.dumps({
                "state": row.get("state"), "observedState": row.get("observedState"),
                "recoveryStatus": row.get("recoveryStatus"),
                "recoveryReasonCode": row.get("recoveryReasonCode"),
                "currentArtifactId": row.get("currentArtifactId"),
                "localPort": row.get("localPort"),
            }), flush=True)
            return row
    return row



REDACTIONS = [
    (re.compile(r"(?i)(authorization|cookie|token|agent[_-]?key|ciphertext)\s*[:=]\s*\S+"),
     r"\1: [REDACTED]"),
    (re.compile(r"ysdp_[A-Za-z0-9_-]{8,}"), "[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [REDACTED]"),
]


def redact(text):
    """Nothing that could be a credential leaves this function."""
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def replacement_diagnostic(row):
    """Everything needed to explain a failed recovery on N2, safely.

    Printed before cleanup, because the Agent home and its log are removed in
    `finally` and the previous run lost the only evidence of why the runtime
    would not start.
    """
    job = d1_read(
        "SELECT j.state, j.attempts, j.maxAttempts, j.lastError FROM node_job j "
        "JOIN app_deployment_action a ON a.jobId = j.id "
        "WHERE a.deploymentId = ? AND a.kind = 'recover' "
        "ORDER BY j.createdAt DESC LIMIT 1", (deployment_id,))
    artifact_directory = None
    manifest_present = None
    artifact_present = None
    try:
        current = (row or {}).get("currentArtifactId")
        if current and replacement_node_id:
            artifact_directory = (second_home / ".ysd-app-runtime" / "workspaces")
            matches = list(artifact_directory.glob(f"*/projects/*/deployments/*/artifacts/{current}")) \
                if artifact_directory.exists() else []
            artifact_present = bool(matches)
            manifest_present = bool(matches) and (matches[0] / ".ysd-artifact.json").exists()
    except OSError:
        pass
    print("DIAGNOSTIC_REPLACEMENT_RECOVERY=" + json.dumps({
        "state": (row or {}).get("state"),
        "observedState": (row or {}).get("observedState"),
        "recoveryStatus": (row or {}).get("recoveryStatus"),
        "recoveryReasonCode": (row or {}).get("recoveryReasonCode"),
        "currentArtifactId": (row or {}).get("currentArtifactId"),
        "localPort": (row or {}).get("localPort"),
        "recoverJob": job[0] if job else None,
        "artifactDirectoryPresent": artifact_present,
        "runtimeManifestPresent": manifest_present,
        "portListening": port_open((row or {}).get("localPort") or 0)
        if (row or {}).get("localPort") else None,
    }, default=str), flush=True)
    try:
        tail = agent2_log.read_text(encoding="utf8", errors="replace")[-4000:]
        print("DIAGNOSTIC_REPLACEMENT_AGENT_LOG_TAIL=" + redact(tail), flush=True)
    except OSError:
        print("DIAGNOSTIC_REPLACEMENT_AGENT_LOG_TAIL=<unavailable>", flush=True)


def run_agent_on(home_dir, config_path, args, timeout=900):
    """One Agent command against a specific controlled home."""
    return subprocess.run(
        [NODE, str(current_agent), *args, "--config", str(config_path)],
        cwd=home_dir,
        env={**env, "YSD_NODE_AGENT_HOME": str(home_dir),
             "YSD_NODE_CONFIG": str(config_path),
             "LOCALAPPDATA": str(home_dir), "XDG_DATA_HOME": str(home_dir),
             "YSD_NODE_AGENT_KEY": REPLACEMENT_AGENT_KEY},
        capture_output=True, text=True, timeout=timeout)


def concurrently(call, times=2):
    """Two real HTTP requests in flight at once. The Product stays as it is."""
    with ThreadPoolExecutor(max_workers=times) as pool:
        return list(pool.map(lambda index: call(index), range(times)))

# --- Phase 22 controlled fixtures -------------------------------------------
second_home = Path(tempfile.mkdtemp(prefix="ysd-phase22-replacement-"))
second_config = second_home / "credentials.json"
second_node_name = f"Phase 22 Replacement {RUN}"
agent2_log = second_home.parent / f"ysd-phase22-agent2-{RUN}.log"
agent2 = None
agent2_log_handle = None
replacement_node_id = None
port_holder_created = False
new_artifact_id = None
bundle_sha = None

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
    email = f"phase22-{RUN}@ysd.test"
    password = f"phase22-local-{RUN}-longpassword"
    status, _ = operator.request("POST", "/api/auth/sign-up/email",
                                 {"name": "Phase 22 Operator", "email": email, "password": password})
    if not check("authenticated local session", status == 200, f"got {status}"):
        raise RuntimeError("local session not established")

    status, body = operator.request("POST", "/api/nodes", {"name": f"Phase 22 Node {RUN}"})
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
        match = [n for n in (nodes_body or {}).get("nodes", []) if n.get("name") == f"Phase 22 Node {RUN}"]
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
    }, {"Idempotency-Key": f"phase22-deploy-{RUN}"})
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
    bundle_sha = sha256_file(bundle)

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


    # =======================================================================
    # C. Declare the source node permanently lost.
    # =======================================================================
    print("\n=== C. declare lost ===", flush=True)
    source_node_id = node_id
    source_artifact_id = artifact_id
    baseline = deployment_detail(operator, deployment_id)
    baseline_revision = baseline.get("desiredRevision") or 1
    baseline_desired = baseline.get("desiredState")
    baseline_checksum = artifact_row(source_artifact_id).get("checksum")
    marker_before = MARKER in body_at(port)
    n1_key_probe = home / "agent.key"
    n1_before = read_sealed_credentials(config, n1_key_probe.read_text(encoding="utf8").strip()) \
        if n1_key_probe.exists() else None
    check("C0a the source node credential authenticates before the loss",
          n1_before is not None
          and assert_signed_node_identity(n1_before["nodeId"], n1_before["token"]))
    check("C0 source deployment is healthy with a verified artifact on N1",
          baseline.get("state") == "healthy" and marker_before
          and artifact_row(source_artifact_id).get("nodeId") == source_node_id)

    status, body = operator.request("POST", f"/api/nodes/{source_node_id}/declare-lost", {})
    check("C1 declare-lost accepted", status == 200 and (body or {}).get("declared") is True,
          f"got {status}: {json.dumps(body)[:200]}")
    lost = deployment_detail(operator, deployment_id)
    check("C2 desired state preserved", lost.get("desiredState") == baseline_desired,
          json.dumps({"before": baseline_desired, "after": lost.get("desiredState")}))
    check("C3 deployment blocked and reports node_lost",
          lost.get("state") == "blocked" and lost.get("recoveryReasonCode") == "node_lost",
          json.dumps({k: lost.get(k) for k in ("state", "observedState", "recoveryReasonCode")}))
    check("C4 desired revision incremented exactly once",
          (lost.get("desiredRevision") or 0) == baseline_revision + 1,
          json.dumps({"before": baseline_revision, "after": lost.get("desiredRevision")}))
    check("C5 the source artifact row is untouched",
          artifact_row(source_artifact_id).get("nodeId") == source_node_id
          and artifact_row(source_artifact_id).get("checksum") == baseline_checksum)
    check("C6 N1 is revoked in the database", compute_node_row(source_node_id).get("revokedAt") is not None)
    operator.request("POST", f"/api/nodes/{source_node_id}/declare-lost", {})
    check("C7 a second declaration does not bump the revision again",
          (deployment_detail(operator, deployment_id).get("desiredRevision") or 0)
          == baseline_revision + 1)
    n1_key_file = home / "agent.key"
    n1_credentials = read_sealed_credentials(config, n1_key_file.read_text(encoding="utf8").strip()) \
        if n1_key_file.exists() else None
    check("C8a the source node credential could be read for a live fence test",
          n1_credentials is not None and bool(n1_credentials.get("token")))
    n1_token = (n1_credentials or {}).get("token", "")
    fenced_status = signed_node_post(
        n1_token, f"/api/nodes/agent/deployments/{deployment_id}/restore-preflight", {})
    # This only means something because the token is real: it authenticated
    # before the node was declared lost, and is refused after.
    check("C8 the old credential is rejected", fenced_status in (401, 403), f"got {fenced_status}")
    check("C9 no Start job was created by declaring loss",
          len(operations(deployment_id, "start")) == 0)

    # =======================================================================
    # D. Pair the replacement node and transfer ownership.
    # =======================================================================
    print("\n=== D. replacement node and transfer ===", flush=True)
    second_home.mkdir(parents=True, exist_ok=True)
    status, body = operator.request("POST", "/api/nodes", {"name": second_node_name})
    pairing2 = (body or {}).get("pairing")
    check("D0 replacement pairing ticket", status == 201 and pairing2, f"got {status}")
    paired2 = subprocess.run(
        [NODE, str(current_agent), "pair", "--url", BASE, "--config", str(second_config)],
        cwd=second_home,
        env={**env, "YSD_NODE_AGENT_HOME": str(second_home),
             "YSD_NODE_CONFIG": str(second_config), "LOCALAPPDATA": str(second_home),
             "XDG_DATA_HOME": str(second_home), "YSD_NODE_AGENT_KEY": REPLACEMENT_AGENT_KEY,
         "YSD_NODE_PAIRING_CODE": pairing2["code"]},
        capture_output=True, text=True, timeout=180)
    check("D1 replacement node pairs", paired2.returncode == 0, paired2.stderr.strip()[:200])
    sealed = read_sealed_credentials(second_config, REPLACEMENT_AGENT_KEY)
    n2_token = sealed["token"]
    check("D1a the retained token authenticates as a real node credential",
          assert_signed_node_identity(sealed["nodeId"], n2_token))

    agent2_log_handle = agent2_log.open("w", encoding="utf8")
    agent2 = subprocess.Popen(
        [NODE, str(current_agent), "run", "--url", BASE, "--config", str(second_config)],
        cwd=second_home,
        env={**env, "YSD_NODE_AGENT_HOME": str(second_home),
             "YSD_NODE_CONFIG": str(second_config), "LOCALAPPDATA": str(second_home),
             "XDG_DATA_HOME": str(second_home), "YSD_NODE_AGENT_KEY": REPLACEMENT_AGENT_KEY},
        stdout=agent2_log_handle, stderr=subprocess.STDOUT, text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    for _ in range(40):
        time.sleep(2)
        _, nodes_body = operator.request("GET", "/api/nodes")
        match = [n for n in (nodes_body or {}).get("nodes", [])
                 if n.get("name") == second_node_name and n.get("status") == "online"]
        if match:
            replacement_node_id = match[0]["id"]
            break
    check("D2 replacement node is online", replacement_node_id is not None)
    _, nodes_body = operator.request("GET", "/api/nodes")
    n2 = next((n for n in (nodes_body or {}).get("nodes", []) if n["id"] == replacement_node_id), {})
    check("D2a the retained token belongs to the replacement node under test",
          sealed["nodeId"] == replacement_node_id)
    check("D3 replacement advertises replacementImport",
          n2.get("capabilities", {}).get("artifactBackup", {}).get("replacementImport") is True,
          json.dumps(n2.get("capabilities", {}).get("artifactBackup", {})))

    transfer_body = {
        "sourceNodeId": source_node_id, "replacementNodeId": replacement_node_id,
        "expectedDesiredRevision": lost.get("desiredRevision"),
        "expectedArtifactId": source_artifact_id,
    }
    # F1: two operators pressing the same button at the same moment.
    racers = [authenticated_operator(email, password) for _ in range(2)]
    check("F0 two independent operator sessions are authenticated",
          all(racer is not None for racer in racers))
    both = concurrently(lambda index: racers[index].request(
        "POST", f"/api/deployments/{deployment_id}/transfer", transfer_body))
    winners = [item for item in both if item[0] == 200]
    check("F1 exactly one concurrent transfer wins", len(winners) == 1,
          json.dumps([item[0] for item in both]))
    moved = deployment_detail(operator, deployment_id)
    check("D4 ownership moved N1 -> N2", moved.get("nodeId") == replacement_node_id)
    check("D5 same deployment id", moved.get("id") == deployment_id)
    check("D6 transfer incremented the revision exactly once",
          (moved.get("desiredRevision") or 0) == (lost.get("desiredRevision") or 0) + 1)
    check("D7 desired state survived the transfer", moved.get("desiredState") == baseline_desired)
    check("D8 the source artifact is still current", moved.get("currentArtifactId") == source_artifact_id)
    check("D9 deployment awaits its import", moved.get("recoveryReasonCode") == "awaiting_import")
    check("D10 A1 still belongs to the lost node",
          artifact_row(source_artifact_id).get("nodeId") == source_node_id)
    check("D11 no runtime was started by the transfer",
          len(operations(deployment_id, "start")) == 0)

    # =======================================================================
    # E. The crash window, reproduced against the real database.
    # =======================================================================
    print("\n=== E. crash-injected reservation repair ===", flush=True)
    pre_status, pre_body = signed_node_json(
        n2_token, f"/api/nodes/agent/deployments/{deployment_id}/import-preflight", {})
    check("E1 import-preflight reserves", pre_status == 200, f"got {pre_status}")
    reserved_artifact = (pre_body or {}).get("replacementArtifactId")
    jobs, actions, provisional = import_reservation(deployment_id)
    check("E2 one job, one action, one provisional artifact",
          len(jobs) == 1 and len(actions) == 1 and len(provisional) == 1,
          json.dumps({"jobs": len(jobs), "actions": len(actions), "artifacts": len(provisional)}))

    injected = inject_reservation_crash(deployment_id, reserved_artifact)
    jobs, actions, provisional = import_reservation(deployment_id)
    check("E3 crash window reproduced: job kept, both rows gone",
          len(jobs) == 1 and len(actions) == 0 and len(provisional) == 0,
          json.dumps({"jobs": len(jobs), "actions": len(actions), "artifacts": len(provisional)}))

    repair_status, repair_body = signed_node_json(
        n2_token, f"/api/nodes/agent/deployments/{deployment_id}/import-preflight", {})
    check("E4 the retry repairs rather than failing", repair_status == 200, f"got {repair_status}")
    check("E5 the retry returns the same artifact id",
          (repair_body or {}).get("replacementArtifactId") == reserved_artifact,
          json.dumps({"reserved": reserved_artifact,
                      "retry": (repair_body or {}).get("replacementArtifactId")}))
    jobs, actions, provisional = import_reservation(deployment_id)
    check("E6 converged to exactly one job, action and provisional artifact",
          len(jobs) == 1 and len(actions) == 1 and len(provisional) == 1,
          json.dumps({"jobs": len(jobs), "actions": len(actions), "artifacts": len(provisional)}))
    check("E7 no second artifact id was minted",
          bool(provisional) and provisional[0]["id"] == reserved_artifact)

    # F2: two nodes' worth of retries at once must converge on one reservation.
    both_pre = concurrently(lambda _: signed_node_json(
        n2_token, f"/api/nodes/agent/deployments/{deployment_id}/import-preflight", {}))
    check("F2 both concurrent preflights succeed", all(item[0] == 200 for item in both_pre),
          json.dumps([item[0] for item in both_pre]))
    check("F3 both name the same reservation",
          len({(item[1] or {}).get("replacementArtifactId") for item in both_pre}) == 1)
    jobs, actions, provisional = import_reservation(deployment_id)
    check("F4 concurrency created no duplicates",
          len(jobs) == 1 and len(actions) == 1 and len(provisional) == 1,
          json.dumps({"jobs": len(jobs), "actions": len(actions), "artifacts": len(provisional)}))

    # =======================================================================
    # H. Make the preferred port genuinely unavailable on the replacement node.
    #
    # A real second controlled deployment on N2 takes P1 through ordinary
    # Product behaviour -- no faked ownership row, no netsh, no Windows change.
    # If the allocator hands it a different port, the run says so and the port
    # collision claim is reported as not exercised rather than fabricated.
    # =======================================================================
    print("\n=== H. preferred port taken on the replacement node ===", flush=True)
    # `nextPort` hands out the lowest free port on a node and smart-deploy takes
    # no port hint, so a second real deployment cannot be made to land on P1 on
    # purpose. Rather than hope, this uses the established acceptance-only
    # holder: one controlled row that genuinely owns (N2, P1) in the same
    # predicate the allocator and the negotiator both read. The Product
    # allocator, the Agent, and Windows are all untouched.
    port_holder_created = reserve_specific_port(REPO, replacement_node_id, port, int(time.time() * 1000))
    holder = port_holder_row(REPO, replacement_node_id, port)
    check("H1 the preferred port is genuinely taken on the replacement node",
          holder is not None and holder["state"] != "blocked",
          json.dumps({"port": port, "holder": holder, "createdByThisRun": port_holder_created}))
    occupied_port = port if holder else None

    # =======================================================================
    # G. A corrupted bundle must install nothing, then the real one must work.
    # =======================================================================
    print("\n=== G. verify-before-install, then the real import ===", flush=True)
    truncated = external / f"ysd-phase22-truncated-{RUN}.ysdbak"
    raw = bundle.read_bytes()
    truncated.write_bytes(raw[: len(raw) // 2])
    bad = run_agent_on(second_home, second_config,
                       ["artifact", "backup", "import", str(truncated)])
    check("G1 a truncated bundle is refused", bad.returncode != 0, (bad.stderr or "").strip()[-160:])
    check("G2 the failed attempt published no artifact",
          artifact_row(reserved_artifact).get("state") == "building",
          json.dumps(artifact_row(reserved_artifact)))
    check("G3 the failed attempt left the current artifact alone",
          deployment_detail(operator, deployment_id).get("currentArtifactId") == source_artifact_id)
    truncated.unlink(missing_ok=True)
    check("G4 the real bundle was not damaged", bundle.exists() and sha256_file(bundle) == bundle_sha)

    github_before = len(operations(deployment_id, "deploy")) + len(operations(deployment_id, "redeploy"))
    imported = run_agent_on(second_home, second_config,
                            ["artifact", "backup", "import", str(bundle)])
    check("G5 the import succeeded", imported.returncode == 0, (imported.stderr or "").strip()[-300:])
    import_result = last_json(imported)
    new_artifact_id = (import_result or {}).get("artifactId")
    check("G6 a new artifact id was used",
          new_artifact_id and new_artifact_id != source_artifact_id,
          json.dumps({"A1": source_artifact_id, "A2": new_artifact_id}))
    a2 = artifact_row(new_artifact_id)
    check("G7 A2 is verified and present on N2",
          a2.get("state") == "verified" and a2.get("availabilityState") == "present"
          and a2.get("nodeId") == replacement_node_id, json.dumps(a2))
    check("G8 A2 carries the source checksum", a2.get("checksum") == baseline_checksum,
          json.dumps({"expected": baseline_checksum, "got": a2.get("checksum")}))
    check("G9 A1 is unchanged and still belongs to N1",
          artifact_row(source_artifact_id).get("nodeId") == source_node_id
          and artifact_row(source_artifact_id).get("checksum") == baseline_checksum)
    after_import = deployment_detail(operator, deployment_id)
    check("G10 currentArtifactId moved A1 -> A2",
          after_import.get("currentArtifactId") == new_artifact_id)
    check("G11 the command claims integrity, never health",
          "verified" in imported.stdout.lower() and "healthy" not in imported.stdout.lower())

    # =======================================================================
    # H (continued). The port the replacement node actually got.
    # =======================================================================
    final_port = after_import.get("localPort")
    check("H2 the taken preferred port was not retained",
          occupied_port == port and final_port != port,
          json.dumps({"preferred": port, "heldOnN2": occupied_port, "final": final_port}))
    check("H3 the control plane recorded an authoritative replacement port",
          isinstance(final_port, int) and final_port > 0, json.dumps({"final": final_port}))

    # =======================================================================
    # I. Recovery, with no operator command at all.
    # =======================================================================
    print("\n=== I. reconciliation brings it back ===", flush=True)
    recovered = wait_recovered(operator, deployment_id, limit=180)
    if (recovered or {}).get("state") != "healthy":
        # Whatever went wrong lives on the replacement node, and `finally` is
        # about to delete its home. Capture it here or lose it -- which is
        # exactly what happened last run.
        replacement_diagnostic(recovered or {})
    check("I1 the deployment is healthy on the replacement node",
          (recovered or {}).get("state") == "healthy"
          and (recovered or {}).get("nodeId") == replacement_node_id,
          json.dumps({k: (recovered or {}).get(k) for k in ("state", "nodeId", "localPort")}))
    check("I2 the marker is served again from the replacement node",
          MARKER in body_at((recovered or {}).get("localPort") or final_port))
    check("I3 the artifact serving it is A2 with the original checksum",
          (recovered or {}).get("currentArtifactId") == new_artifact_id
          and artifact_row(new_artifact_id).get("checksum") == baseline_checksum)
    check("I4 no operator Start was ever issued", len(operations(deployment_id, "start")) == 0)
    check("I5 no source acquisition happened during recovery",
          len(operations(deployment_id, "deploy")) + len(operations(deployment_id, "redeploy"))
          == github_before,
          json.dumps({"before": github_before,
                      "after": len(operations(deployment_id, "deploy"))
                      + len(operations(deployment_id, "redeploy"))}))
    check("I6 exactly one import artifact was created for this deployment",
          len([row for row in artifact_rows(deployment_id)
               if row["nodeId"] == replacement_node_id]) == 1,
          json.dumps(artifact_rows(deployment_id)))
    check("I7 the Agent log shows no install or build during import",
          not re.search(r"npm (install|ci)|running build|git clone",
                        agent2_log.read_text(encoding="utf8", errors="replace"), re.I))

    # =======================================================================
    # J. Replaying the confirmation must change nothing.
    # =======================================================================
    print("\n=== J. import-complete replay ===", flush=True)
    before_replay = deployment_detail(operator, deployment_id)
    rows_before = artifact_rows(deployment_id)
    jobs_before = len(app_runtime_jobs(deployment_id))
    replay_status, replay_body = signed_node_json(
        n2_token, f"/api/nodes/agent/deployments/{deployment_id}/import-complete",
        {"artifactId": new_artifact_id, "sourceArtifactId": source_artifact_id,
         "checksum": baseline_checksum,
         "sizeBytes": (import_result or {}).get("payloadBytes", 0),
         "expectedDesiredRevision": before_replay.get("desiredRevision")})
    check("J1 the replay is accepted as a no-op", replay_status == 200,
          f"got {replay_status}: {json.dumps(replay_body)[:200]}")
    after_replay = deployment_detail(operator, deployment_id)
    check("J2 nothing moved", after_replay.get("currentArtifactId") == new_artifact_id
          and after_replay.get("desiredRevision") == before_replay.get("desiredRevision"))
    check("J3 no artifact row was added", len(artifact_rows(deployment_id)) == len(rows_before))
    check("J4 no job was added", len(app_runtime_jobs(deployment_id)) == jobs_before)
    check("J5 still no Start", len(operations(deployment_id, "start")) == 0)

    # =======================================================================
    # K. The same path for a deployment that is meant to stay stopped.
    # =======================================================================
    print("\n=== K. desired stopped ===", flush=True)
    status, _ = operator.request("POST", f"/api/deployments/{deployment_id}/actions",
                                 {"operation": "stop"},
                                 {"Idempotency-Key": f"phase22-stop-{RUN}"})
    check("K0 a controlled stop is queued", status == 202, f"got {status}")
    stopped = wait_deployment(operator, deployment_id, {"stopped", "failed"}, limit=90)
    check("K1 the deployment is stopped and desired stopped",
          (stopped or {}).get("desiredState") == "stopped", json.dumps({
              "state": (stopped or {}).get("state"),
              "desiredState": (stopped or {}).get("desiredState")}))
    stopped_jobs = len(operations(deployment_id, "recover"))
    stopped_again = run_agent_on(second_home, second_config,
                                 ["artifact", "backup", "import", str(bundle)])
    check("K2 a second import of a stopped deployment does not start it",
          stopped_again.returncode != 0
          or "healthy" not in (stopped_again.stdout or "").lower(),
          (stopped_again.stderr or "").strip()[-160:])
    time.sleep(8)
    check("K3 no recovery job was created while desired stopped",
          len(operations(deployment_id, "recover")) == stopped_jobs)
    check("K4 the private port is closed",
          not port_open((stopped or {}).get("localPort") or final_port))
    check("K5 desired state was never mutated by the import path",
          deployment_detail(operator, deployment_id).get("desiredState") == "stopped")

    # =======================================================================
    # L. What the operator actually sees.
    # =======================================================================
    print("\n=== L. rendered UI ===", flush=True)
    page = body_at_path(operator, "/nodes")
    check("L1 a lost node does not read as merely revoked",
          "Lost, credential permanently revoked" in page or "permanently lost" in page,
          page[:200])
    check("L0 the authenticated page rendered", len(page) > 200, f"{len(page)} bytes")
    # A node id is a public resource identifier -- the recovery card renders one
    # on purpose so an operator can see which machine is which. The secrets are
    # credentials, headers and sealed material.
    check("L2 the page renders no secret material",
          not re.search(r"ysdp_|Authorization|Set-Cookie|agent\.key|environmentCiphertext"
                        r"|\bcookie\b|tokenCiphertext", page, re.I))
    print("PHASE22_SUMMARY=" + json.dumps({
        "deployment": deployment_id,
        "sourceNode": source_node_id, "replacementNode": replacement_node_id,
        "sourceArtifact": source_artifact_id, "replacementArtifact": new_artifact_id,
        "checksum": baseline_checksum,
        "preferredPort": port, "authoritativePort": final_port,
        "crashInjected": injected,
    }), flush=True)

finally:
    release_reserved_ports(REPO)
    n2_token = None

    if agent2 is not None:
        stop_agent(agent2)
    if agent2_log_handle is not None:
        agent2_log_handle.close()
    for controlled_port in {p for p in (port, final_port if "final_port" in dir() else None) if p}:
        stray = pid_on_port(controlled_port)
        if stray:
            subprocess.run(["taskkill.exe", "/PID", str(stray), "/F"], capture_output=True)
    for controlled_node in (replacement_node_id,):
        if controlled_node:
            try:
                operator.request("DELETE", f"/api/nodes/{controlled_node}")
            except OSError:
                pass
    for path in (second_home, agent2_log):
        for _ in range(10):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
                break
            except FileNotFoundError:
                break
            except OSError:
                time.sleep(0.5)
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
            operator.request("DELETE", f"/api/nodes/{node_id}")
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
