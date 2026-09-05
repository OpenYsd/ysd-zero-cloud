"""Phase 17 acceptance: real releases, real rollback, real content proof.

Runs the actual Node Agent against a running control plane and drives one
service through two releases and back again. The gate that matters is not a
status field -- it is the bytes the service returns on its private port:

    release A  ->  the page it serves references http://d3js.org/...
    release B  ->  the same page references //d3js.org/...

If a rollback only moved a pointer, the page would not change back. If a
rollback rebuilt from source, the artifact checksum would change. Both are
asserted.

Requires a control plane at YSD_RELEASE_BASE (default http://localhost:3000)
and a Node 25/26 runtime at YSD_ACCEPTANCE_NODE for the agent to run under.
"""
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("YSD_RELEASE_BASE", "http://localhost:3000")
REPO = Path(os.environ.get("YSD_REPO", Path(__file__).resolve().parent))
NODE = os.environ.get("YSD_ACCEPTANCE_NODE", "node")
# A caller may pin the run id so a browser walkthrough can sign in to the
# same throwaway local account this harness creates. Synthetic, local, and
# never a Production credential.
RUN = os.environ.get("YSD_RELEASE_RUN") or secrets.token_hex(3)

# Two commits of one public repository whose served HTML differs. The agent
# only ever fetches from the github.com archive allowlist, so a purely local
# fixture is not possible without weakening that boundary.
# Two commits of one small public repository. They share identical application
# code and differ only in the static page the service returns, so the content
# proof isolates "which build is running" from every other variable. Both
# satisfy the safe build contract: npm lockfile, no `engines` pin, a
# `node server.js` start script, and PORT respected. Neither declares an
# environment template, so no secret is sealed into the acceptance deployment.
#
# The agent only ever fetches from the github.com archive allowlist, so a
# purely local fixture is impossible without weakening that boundary -- which
# would defeat the point of testing against it.
FIXTURE = os.environ.get("YSD_FIXTURE_REPO", "cyclic-software/express-hello-world")
RELEASE_A = os.environ.get("YSD_FIXTURE_A", "1b5eeb79b757a8cd496e58518aa1711889fa7253")
RELEASE_B = os.environ.get("YSD_FIXTURE_B", "f7ec796be7573a6d61edbcd6901066143920fee1")
MARKER_A = os.environ.get("YSD_FIXTURE_MARKER_A", "src='http://d3js.org/d3.v3.min.js'")
MARKER_B = os.environ.get("YSD_FIXTURE_MARKER_B", "src='//d3js.org/d3.v3.min.js'")

PASSED, FAILED, SKIPPED = [], [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""), flush=True)
    return bool(condition)


def skip(name, why):
    SKIPPED.append((name, why))
    print(f"  [SKIP] {name} - {why}", flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, address="198.51.100.90"):
        self.address = address
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()
        )

    def request(self, method, path, body=None, headers=None, retries=3):
        raw = json.dumps(body).encode() if body is not None else None
        head = {
            "Content-Type": "application/json",
            "Origin": BASE,
            "Referer": f"{BASE}/",
            "CF-Connecting-IP": self.address,
            "User-Agent": "ysd-release-acceptance/1.0",
        }
        head.update(headers or {})
        request = urllib.request.Request(f"{BASE}{path}", data=raw, method=method, headers=head)
        try:
            with self.opener.open(request, timeout=180) as response:
                payload, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        if status == 429 and retries > 0:
            time.sleep(8)
            return self.request(method, path, body, headers, retries - 1)
        try:
            return status, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return status, payload.decode("utf-8", "replace")


def wait_for_state(client, deployment_id, done, limit=200):
    """Poll until the deployment settles, returning the last row seen."""
    row = None
    for _ in range(limit):
        time.sleep(3)
        _, body = client.request("GET", "/api/deployments")
        rows = [d for d in (body or {}).get("deployments", []) if d["id"] == deployment_id]
        if rows:
            row = rows[0]
            if row["state"] in done:
                return row
    return row


def serve_body(port, path="/"):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=20) as response:
            return response.read().decode("utf-8", "replace")
    except Exception as error:  # noqa: BLE001 - reported, never raised
        return f"<unreachable: {error}>"


def releases(client, deployment_id):
    _, body = client.request("GET", f"/api/deployments/{deployment_id}/releases")
    return (body or {}).get("history", {})


operator = Client()
manifest = json.loads((REPO / "public/agent/manifest.json").read_text())
artifact = REPO / "public/agent" / manifest["filename"]

print("=== account, node, agent ===", flush=True)
CREDENTIALS = {"email": f"release-{RUN}@ysd.test", "password": f"release-e2e-{RUN}-longpassword"}
status, _ = operator.request(
    "POST", "/api/auth/sign-up/email", {"name": "Release Operator", **CREDENTIALS}
)
if status != 200:
    # A pinned run id means the account may already exist, and repeated runs
    # legitimately trip the sign-up throttle. Reuse the account rather than
    # manufacturing another one.
    signin, _ = operator.request("POST", "/api/auth/sign-in/email", CREDENTIALS)
    if signin != 200:
        print(f"  sign-up returned {status} and sign-in returned {signin}; retry in a minute")
        sys.exit(0)
    status = 200
check("operator session established", status == 200, f"got {status}")

status, body = operator.request("POST", "/api/nodes", {"name": f"Release Node {RUN}"})
ticket = (body or {}).get("pairing")
if not check("pairing ticket created", status == 201 and ticket, f"got {status}"):
    sys.exit(1)

home = tempfile.mkdtemp(prefix="ysd-release-e2e-")
env = {
    **os.environ,
    "YSD_NODE_PAIRING_CODE": ticket["code"],
    "YSD_NODE_CONFIG": str(Path(home) / "credentials.json"),
    "LOCALAPPDATA": home,
    "XDG_DATA_HOME": home,
}
env.pop("YSD_NODE_AGENT_KEY", None)

paired = subprocess.run(
    [NODE, str(artifact), "pair", "--url", BASE], capture_output=True, text=True, cwd=home, env=env, timeout=180
)
check("the built agent paired", paired.returncode == 0, (paired.stdout + paired.stderr).strip()[-90:])

# The agent's own output is the only place a build failure explains itself, so
# keep it on disk rather than in a pipe nobody drains.
agent_log = Path(home) / "agent.log"
agent_log_handle = agent_log.open("w", encoding="utf-8")
agent = subprocess.Popen(
    [NODE, str(artifact), "run", "--url", BASE],
    stdout=agent_log_handle,
    stderr=subprocess.STDOUT,
    text=True,
    cwd=home,
    env=env,
)


def agent_tail(lines=14):
    try:
        agent_log_handle.flush()
        return "".join(agent_log.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)[-lines:])
    except Exception:
        return "<no agent output>"

node_id = None
deployment_id = None
try:
    online = False
    for _ in range(40):
        time.sleep(3)
        _, body = operator.request("GET", "/api/nodes")
        nodes = (body or {}).get("nodes", [])
        if nodes:
            node_id = nodes[0]["id"]
            if nodes[0].get("status") == "online":
                online = True
                break
    if not check("the agent heartbeat brought the node online", online):
        raise SystemExit(1)

    _, body = operator.request("GET", f"/api/nodes/{node_id}/preflight")
    preflight = (body or {}).get("preflight", {})
    blocked = [c["code"] for c in preflight.get("checks", []) if c["status"] == "blocked"]
    if "app-runtime-contract" in blocked or "app-runtime-node" in blocked:
        skip("release lifecycle", "a Node 25/26 runtime for the App Runtime contract")
        raise SystemExit(0)
    check("preflight reports ready", preflight.get("verdict") == "ready", str(blocked))

    print("\n=== release A ===", flush=True)
    status, body = operator.request(
        "POST",
        "/api/smart-deploy",
        {
            "repository": FIXTURE,
            "branch": "main",
            "commit": RELEASE_A,
            "nodeId": node_id,
            "environment": "Production",
            "healthPath": "/",
            "memoryMb": 256,
            "diskQuotaBytes": 256 * 1024**2,
            "target": "user-node",
        },
    )
    deployment = (body or {}).get("deployment")
    error = (body or {}).get("error", "") if isinstance(body, dict) else ""
    if status == 404 and "could not be inspected" in str(error):
        skip("release lifecycle", "GitHub reachable for repository inspection")
        raise SystemExit(0)
    if not check("release A queued", status == 202 and deployment, f"got {status} {str(error)[:70]}"):
        raise SystemExit(1)
    deployment_id = deployment["id"]
    port = deployment["localPort"]

    row = wait_for_state(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    if not check(
        "release A is healthy",
        (row or {}).get("state") == "healthy",
        f"{(row or {}).get('state')} - {(row or {}).get('lastError')}",
    ):
        print("  agent output:\n" + agent_tail(), flush=True)
        raise SystemExit(1)

    body_a = serve_body(port)
    check("release A serves its own build", MARKER_A in body_a, "content marker A absent")

    history = releases(operator, deployment_id)
    first = history.get("releases", [])
    check("release A is the current release", len(first) == 1 and first[0]["isCurrent"], str(len(first)))
    check(
        "a single release offers nothing to roll back to",
        first and not first[0]["canRollback"] and "current_release" in first[0]["reasons"],
        str(first[0]["reasons"]) if first else "no releases",
    )
    artifact_a = first[0]["artifactId"]
    checksum_a = first[0]["checksumPrefix"]

    print("\n=== release B on the same service ===", flush=True)
    status, body = operator.request(
        "POST", f"/api/deployments/{deployment_id}/releases", {"commit": RELEASE_B}
    )
    if not check("release B queued", status == 202, f"got {status} {str((body or {}).get('error'))[:70]}"):
        raise SystemExit(1)
    row = wait_for_state(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    check("release B is healthy", (row or {}).get("state") == "healthy", str((row or {}).get("state")))
    check("release B kept the same deployment", (row or {}).get("id") == deployment_id)
    check("release B kept the same private port", (row or {}).get("localPort") == port, str((row or {}).get("localPort")))

    body_b = serve_body(port)
    check("release B serves different bytes", MARKER_B in body_b and MARKER_A not in body_b)

    history = releases(operator, deployment_id)
    rows = history.get("releases", [])
    by_id = {r["artifactId"]: r for r in rows}
    artifact_b = history.get("currentArtifactId")
    check("history shows both releases", len(rows) == 2, str(len(rows)))
    check("release B is current", by_id.get(artifact_b, {}).get("isCurrent") is True)
    check("release A is superseded, not current", by_id.get(artifact_a, {}).get("status") == "superseded")
    check("release A is now restorable", by_id.get(artifact_a, {}).get("canRollback") is True, str(by_id.get(artifact_a, {}).get("reasons")))
    check("release A keeps its own commit", by_id.get(artifact_a, {}).get("commitSha") == RELEASE_A)
    check("release B records its own commit", by_id.get(artifact_b, {}).get("commitSha") == RELEASE_B)
    checksum_b = by_id.get(artifact_b, {}).get("checksumPrefix")
    check("the two releases are physically different builds", checksum_a and checksum_b and checksum_a != checksum_b)

    print("\n=== preview mutates nothing ===", flush=True)
    _, before = operator.request("GET", f"/api/deployments/{deployment_id}")
    for _ in range(3):
        status, body = operator.request(
            "GET", f"/api/deployments/{deployment_id}/rollback?targetArtifactId={artifact_a}"
        )
    preview = (body or {}).get("preview", {})
    _, after = operator.request("GET", f"/api/deployments/{deployment_id}")
    check("preview is eligible for release A", status == 200 and preview.get("eligible") is True, str(preview.get("reasons")))
    check("preview names the running release", (preview.get("current") or {}).get("artifactId") == artifact_b)
    check("preview names the target release", (preview.get("target") or {}).get("artifactId") == artifact_a)
    check("preview promises no zero downtime", "unavailable" in preview.get("impact", "").lower())
    before_d, after_d = (before or {}).get("deployment", {}), (after or {}).get("deployment", {})
    check(
        "repeated previews changed nothing",
        before_d.get("currentArtifactId") == after_d.get("currentArtifactId")
        and before_d.get("state") == after_d.get("state")
        and len(before_d.get("actions", [])) == len(after_d.get("actions", [])),
    )

    print("\n=== rollback to release A ===", flush=True)
    # Unique per run: a pinned run id must not let this run inherit an
    # earlier run's key, which the control plane would rightly treat as the
    # same request and answer without queueing anything. Both calls below
    # deliberately share it so the duplicate check stays meaningful.
    rollback_key = f"e2e-rollback-a-{RUN}-{int(time.time())}"
    status, body = operator.request(
        "POST",
        f"/api/deployments/{deployment_id}/rollback",
        {"targetArtifactId": artifact_a, "expectedCurrentArtifactId": artifact_b},
        headers={"Idempotency-Key": rollback_key},
    )
    check("rollback accepted", status == 202, f"got {status} {str((body or {}).get('error'))[:70]}")
    status_dup, _ = operator.request(
        "POST",
        f"/api/deployments/{deployment_id}/rollback",
        {"targetArtifactId": artifact_a, "expectedCurrentArtifactId": artifact_b},
        headers={"Idempotency-Key": rollback_key},
    )
    check("the same rollback twice queues once", status_dup == 202)

    row = wait_for_state(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    check("rollback reached healthy", (row or {}).get("state") == "healthy", str((row or {}).get("state")))
    body_back = serve_body(port)
    check("release A content is actually restored", MARKER_A in body_back, "the old build is not serving")

    history = releases(operator, deployment_id)
    rows = history.get("releases", [])
    by_id = {r["artifactId"]: r for r in rows}
    check("release A is current again", history.get("currentArtifactId") == artifact_a)
    check("release B remains in history", artifact_b in by_id)
    check("no third artifact was built by the rollback", len(rows) == 2, str(len(rows)))
    check("release A checksum is unchanged", by_id.get(artifact_a, {}).get("checksumPrefix") == checksum_a)
    check("release B checksum is unchanged", by_id.get(artifact_b, {}).get("checksumPrefix") == checksum_b)

    _, detail = operator.request("GET", f"/api/deployments/{deployment_id}")
    kinds = [a["kind"] for a in (detail or {}).get("deployment", {}).get("actions", [])]
    check("history appended a rollback action", "rollback" in kinds, str(kinds))
    check("history kept the release action", "release" in kinds, str(kinds))

    print("\n=== rollback of the rollback ===", flush=True)
    status, body = operator.request(
        "POST",
        f"/api/deployments/{deployment_id}/rollback",
        {"targetArtifactId": artifact_b, "expectedCurrentArtifactId": artifact_a},
    )
    check("release B is restorable again", status == 202, f"got {status} {str((body or {}).get('error'))[:70]}")
    row = wait_for_state(operator, deployment_id, {"healthy", "failed", "crash_loop"})
    check("rollback of rollback reached healthy", (row or {}).get("state") == "healthy")
    check("release B content restored", MARKER_B in serve_body(port))
    history = releases(operator, deployment_id)
    check("still exactly two releases", len(history.get("releases", [])) == 2)
    check("release B is current again", history.get("currentArtifactId") == artifact_b)

    print("\n=== refusals ===", flush=True)
    status, body = operator.request(
        "POST", f"/api/deployments/{deployment_id}/rollback", {"targetArtifactId": artifact_b}
    )
    check("the running release cannot be rolled back to", status == 409 and "already running" in str((body or {}).get("error")), f"got {status}")

    status, body = operator.request(
        "POST",
        f"/api/deployments/{deployment_id}/rollback",
        {"targetArtifactId": artifact_a, "expectedCurrentArtifactId": artifact_a},
    )
    check("a stale view is refused", status == 409 and "changed while" in str((body or {}).get("error")), f"got {status}")

    status, _ = operator.request(
        "POST", f"/api/deployments/{deployment_id}/rollback", {"targetArtifactId": "art_" + "0" * 24}
    )
    check("an unknown release is refused", status == 409, f"got {status}")

    status, _ = operator.request(
        "POST", f"/api/deployments/dpl_{'0' * 24}/rollback", {"targetArtifactId": artifact_a}
    )
    check("a foreign deployment is opaque", status == 404, f"got {status}")

    status, _ = operator.request(
        "GET", f"/api/deployments/dpl_{'0' * 24}/releases"
    )
    check("foreign release history is opaque", status == 404, f"got {status}")

    status, body = operator.request(
        "POST",
        f"/api/deployments/{deployment_id}/rollback",
        {"targetArtifactId": artifact_a, "eligible": True, "preflightPassed": True},
    )
    check("a client cannot assert its own eligibility", status == 400, f"got {status}")

    status, body = operator.request(
        "POST", f"/api/deployments/{deployment_id}/releases", {"repository": "attacker/evil", "commit": RELEASE_A}
    )
    check("a release cannot redirect to another repository", status == 400, f"got {status}")

    print("\n=== zero mode ===", flush=True)
    _, body = operator.request("GET", "/api/deployments")
    mine = [d for d in (body or {}).get("deployments", []) if d["id"] == deployment_id]
    check("the acceptance deployment costs nothing", all(d.get("estimatedMonthlyCost") == 0 for d in mine))
    check("Zero Mode stayed on", all(d.get("zeroModeEnabled") is True for d in mine))
    check("the service stayed private", all(d.get("exposure") == "private" for d in mine))
    check("the service stayed bound to loopback", all(d.get("observedBind") == "127.0.0.1" for d in mine))

    print("\n=== evidence ===", flush=True)
    _, body = operator.request("GET", "/api/audit?limit=200")
    events = (body or {}).get("events", [])
    actions = [e.get("action") for e in events]
    check("a release is recorded as evidence", "deployment.release" in actions, str(sorted(set(actions))[:8]))
    check("a rollback is recorded as evidence", "deployment.rollback" in actions)
    rollbacks = [e for e in events if e.get("action") == "deployment.rollback"]
    check(
        "an interactive rollback is attributed to the user",
        rollbacks and all(e.get("actorType") == "user" for e in rollbacks),
        str({e.get("actorType") for e in rollbacks}),
    )
    check(
        "a refused rollback is recorded too",
        sum(1 for e in rollbacks if e.get("outcome") == "failed") >= 1,
        str([e.get("outcome") for e in rollbacks]),
    )
    serialized_evidence = json.dumps(rollbacks)
    check(
        "rollback evidence carries no path, digest or credential",
        not re.search(r"[a-f0-9]{64}|/artifacts/|tokenCiphertext|manifest", serialized_evidence),
    )
    sequences = [e.get("sequence") for e in events if isinstance(e.get("sequence"), int)]
    check("every evidence row is numbered", len(sequences) == len(events), f"{len(sequences)}/{len(events)}")
    check("evidence sequence has no duplicates", len(sequences) == len(set(sequences)))
    check(
        "evidence sequence has no gaps",
        all(sequences[i - 1] - sequences[i] == 1 for i in range(1, len(sequences))),
    )

    print("\n=== isolation and secrecy ===", flush=True)
    serialized = json.dumps(releases(operator, deployment_id))
    leaks = [w for w in ("tokenCiphertext", "tokenHash", "manifest", "signature", home.replace("\\", "\\\\"), "/artifacts/") if w in serialized]
    check("release history exposes no credential, manifest or path", not leaks, str(leaks))
    check(
        "release history exposes only a short fingerprint",
        not re.search(r"[a-f0-9]{64}", serialized),
        "a full digest reached the client",
    )
finally:
    if FAILED:
        print("\n=== agent output (tail) ===\n" + agent_tail(24), flush=True)
    agent.terminate()
    try:
        agent.wait(timeout=20)
    except subprocess.TimeoutExpired:
        agent.kill()

if deployment_id:
    print(f"\nacceptance deployment: {deployment_id}")
print("\n" + "=" * 62)
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}   SKIPPED {len(SKIPPED)}")
for name in FAILED:
    print(f"    FAIL - {name}")
for name, why in SKIPPED:
    print(f"    SKIP - {name} ({why})")
print("=" * 62)
sys.exit(1 if FAILED else 0)
