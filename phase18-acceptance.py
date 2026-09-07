"""Phase 18 runtime-recovery control-plane acceptance against local D1 only.

The real process/artifact path is covered independently by the portable Node 26
suite in ``tests/app-runtime.test.ts``. This script proves the signed HTTP and D1
flow, state/revision authority, reconciliation idempotency, audit actors, and
legacy-agent compatibility without touching Production or any paid service.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("YSD_PHASE18_ACCEPTANCE_BASE", "http://localhost:3000")
RUN = secrets.token_hex(5)
PASSED: list[str] = []
FAILED: list[str] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class Client:
    def __init__(self, address: str) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )
        self.address = address

    def request(self, method: str, path: str, body=None, headers=None):
        raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request = urllib.request.Request(
            f"{BASE}{path}", data=raw, method=method, headers={
                "Content-Type": "application/json", "Origin": BASE,
                "Referer": f"{BASE}/", "CF-Connecting-IP": self.address,
                "User-Agent": "ysd-phase18-local-acceptance/1.0", **(headers or {}),
            },
        )
        try:
            with self.opener.open(request, timeout=90) as response:
                payload, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        try:
            return status, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return status, payload.decode("utf-8", "replace")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def section(name: str) -> None:
    print(f"\n=== {name} ===")


def agent_request(token: str, path: str, body: dict):
    raw = json.dumps(body, separators=(",", ":"))
    nonce = b64url(secrets.token_bytes(18))
    timestamp = int(time.time() * 1000)
    body_hash = b64url(hashlib.sha256(raw.encode()).digest())
    message = "\n".join(["ysd-node-request-v1", "POST", path, str(timestamp), nonce, body_hash])
    signature = b64url(hmac.new(token.encode(), message.encode(), hashlib.sha256).digest())
    request = urllib.request.Request(
        f"{BASE}{path}", data=raw.encode(), method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {token}",
            "X-YSD-Timestamp": str(timestamp), "X-YSD-Nonce": nonce,
            "X-YSD-Signature": signature,
            "User-Agent": "ysd-phase18-local-agent/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    return status, json.loads(payload) if payload else None


def claim(token: str):
    status, body = agent_request(token, "/api/nodes/agent/claim", {})
    return status, body.get("job") if isinstance(body, dict) else None


def complete(token: str, job: dict, *, state="succeeded", result=None, error=None):
    body = {
        "leaseId": job["claim"]["leaseId"], "claim": job["claim"],
        "claimSignature": job["signature"], "status": state,
    }
    if result is not None:
        body["result"] = result
    if error is not None:
        body["error"] = error
        body["retryable"] = False
    return agent_request(
        token, f'/api/nodes/agent/jobs/{job["claim"]["jobId"]}/complete', body
    )


CAPABILITIES = {
    "cpu": {"cores": 8, "model": "Phase 18 CPU"},
    "memory": {"totalBytes": 16 * 1024**3, "freeBytes": 12 * 1024**3},
    "gpu": {"available": False, "model": None, "vramBytes": None},
    "disk": {"totalBytes": 100 * 1024**3, "freeBytes": 80 * 1024**3},
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
METRICS = {
    "cpuLoadPercent": 4, "memoryUsedBytes": 2 * 1024**3,
    "memoryTotalBytes": 16 * 1024**3, "runningJobs": 0,
}


def heartbeat(token: str, generation: str | None, deployments=None, *, agent="0.5.0"):
    body = {
        "agentVersion": agent, "capabilities": CAPABILITIES, "metrics": METRICS,
        "gameServers": [], "appDeployments": deployments or [],
    }
    if generation is not None:
        body["runtimeGeneration"] = generation
    return agent_request(token, "/api/nodes/agent/heartbeat", body)


client_octet = 20 + (int(RUN[:6], 16) % 220)
operator = Client(f"198.51.100.{client_octet}")
anonymous = Client(f"203.0.113.{client_octet}")
email = f"phase18-{RUN}@ysd.test"
password = f"Phase18-local-{RUN}!"

section("real Better Auth and Agent 0.5.0")
status, _ = operator.request("POST", "/api/auth/sign-up/email", {
    "name": "Phase 18 Operator", "email": email, "password": password,
})
check("operator signed up through Better Auth", status == 200, f"got {status}")
status, pairing_body = operator.request("POST", "/api/nodes", {"name": "Phase 18 Node 26"})
pairing = pairing_body.get("pairing") if isinstance(pairing_body, dict) else None
check("pairing ticket created", status == 201 and pairing is not None, f"got {status}")
status, paired = anonymous.request("POST", "/api/nodes/agent/pair", {
    "code": pairing["code"], "agentVersion": "0.5.0", "protocolVersion": 1,
    "platform": "win32", "architecture": "x64", "capabilities": CAPABILITIES,
})
token = paired.get("token") if isinstance(paired, dict) else None
node_id = paired.get("nodeId") if isinstance(paired, dict) else None
check("Agent 0.5.0 paired on Protocol 1", status == 201 and token and node_id, f"got {status}")
generation_a = "gen_" + secrets.token_urlsafe(18)
status, _ = heartbeat(token, generation_a)
check("generation-aware heartbeat accepted", status == 200, f"got {status}")

section("initial deployment")
request = {
    "repository": "cyclic-software/express-hello-world", "branch": "main",
    "commit": "1b5eeb79b757a8cd496e58518aa1711889fa7253",
    "nodeId": node_id, "environment": "Production", "healthPath": "/",
    "memoryMb": 256, "diskQuotaBytes": 256 * 1024**2, "target": "user-node",
}
status, created = operator.request(
    "POST", "/api/smart-deploy", request, {"Idempotency-Key": f"phase18-deploy-{RUN}"}
)
deployment = created.get("deployment") if isinstance(created, dict) else None
deployment_id = deployment.get("id") if isinstance(deployment, dict) else None
check("zero-cost deployment queued", status == 202 and deployment_id, f"got {status}")
status, deploy_job = claim(token)
deploy_payload = deploy_job["claim"]["payload"] if deploy_job else {}
check("new Agent receives revision and retention protection", status == 200 and
      isinstance(deploy_payload.get("expectedDesiredRevision"), int) and
      isinstance(deploy_payload.get("protectedArtifactIds"), list))
artifact_id = deploy_payload.get("artifactId")
checksum = "sha256:" + "b" * 64
success = {
    "deploymentId": deployment_id, "state": "running", "checksum": checksum,
    "sizeBytes": 8192, "localAddress": deployment["localAddress"],
    "bind": "127.0.0.1", "exposure": "private", "networkGuard": True,
    "restartCount": 0, "crashLoop": False, "buildDurationMs": 1200,
    "deployDurationMs": 1500, "healthState": "healthy", "logs": ["[runtime] ready"],
}
status, done = complete(token, deploy_job, result=success)
check("initial deployment completed", status == 200 and done.get("state") == "succeeded")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
detail = detail_body.get("deployment", {})
check("desired and observed state are distinct and healthy", status == 200 and
      detail.get("desiredState") == "running" and detail.get("observedState") == "healthy")
initial_revision = detail.get("desiredRevision")
initial_count = len(detail.get("artifacts", []))

section("fresh-generation automatic recovery")
generation_b = "gen_" + secrets.token_urlsafe(18)
status, _ = heartbeat(token, generation_b, [])
check("fresh Agent reports missing managed runtime", status == 200, f"got {status}")
status, recovering_body = operator.request("GET", f"/api/deployments/{deployment_id}")
recovering = recovering_body.get("deployment", {})
check("control plane exposes Recovering", recovering.get("observedState") == "recovering" and
      recovering.get("recoveryStatus") == "pending")
status, recovery_job = claim(token)
recovery_payload = recovery_job["claim"]["payload"] if recovery_job else {}
check("one automatic recovery lease queued", status == 200 and recovery_payload.get("operation") == "recover")
check("recovery pins same deployment/node/port/artifact", recovery_payload.get("deploymentId") == deployment_id and
      recovery_job["claim"].get("nodeId") == node_id and
      recovery_payload.get("port") == deployment.get("localPort") and
      recovery_payload.get("artifactId") == artifact_id)
check("recovery has no source/build path", recovery_payload.get("source") is None and
      recovery_payload.get("targetArtifactId") is None and
      recovery_payload.get("expectedDesiredRevision") == initial_revision)
recovery_success = {
    **success, "phase": "health", "reasonCode": "recovery_succeeded",
    "observedState": "healthy", "availabilityState": "present", "restarted": True,
}
status, recovered = complete(token, recovery_job, result=recovery_success)
check("automatic recovery completed with health proof", status == 200 and recovered.get("state") == "succeeded")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
detail = detail_body.get("deployment", {})
check("recovery kept exact artifact count and identity", len(detail.get("artifacts", [])) == initial_count and
      detail.get("currentArtifactId") == artifact_id)
check("observed state returned Healthy", detail.get("observedState") == "healthy" and
      detail.get("recoveryStatus") == "succeeded")
status, _ = heartbeat(token, generation_b, [])
status, repeat = claim(token)
check("same generation/revision does not create a recovery storm", status == 200 and repeat is None)

section("blocked and failed recovery evidence")
generation_c = "gen_" + secrets.token_urlsafe(18)
heartbeat(token, generation_c, [])
status, port_job = claim(token)
check("new generation permits one bounded reconciliation", status == 200 and
      port_job and port_job["claim"]["payload"].get("operation") == "recover")
status, blocked = complete(token, port_job, state="failed", error="Port check failed.", result={
    "deploymentId": deployment_id, "state": "blocked", "checksum": checksum,
    "phase": "start", "reasonCode": "port_in_use", "observedState": "blocked",
    "availabilityState": "present", "artifactId": artifact_id, "restarted": False,
})
check("port conflict is a bounded blocked recovery", status == 200 and blocked.get("state") == "failed")
heartbeat(token, generation_c, [])
status, repeat = claim(token)
check("blocked recovery does not repeat on heartbeat", status == 200 and repeat is None)
generation_after_block = "gen_" + secrets.token_urlsafe(18)
heartbeat(token, generation_after_block, [])
status, repeat = claim(token)
check("blocked recovery does not retry after Agent restart", status == 200 and repeat is None)
status, manual = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "recover"},
    {"Idempotency-Key": f"phase18-manual-{RUN}"},
)
check("manual user recovery may retry after remediation", status == 202, f"got {status}")
status, manual_job = claim(token)
status, failed = complete(token, manual_job, state="failed", error="Health check failed.", result={
    "deploymentId": deployment_id, "state": "failed", "checksum": checksum,
    "phase": "health", "reasonCode": "health_failed", "observedState": "unhealthy",
    "availabilityState": "present", "artifactId": artifact_id, "restarted": False,
})
check("health failure remains non-healthy", status == 200 and failed.get("state") == "failed")

section("intentional Stop authority")
status, stop = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "stop"},
    {"Idempotency-Key": f"phase18-stop-{RUN}"},
)
check("Stop intent queued", status == 202, f"got {status}")
status, stop_job = claim(token)
status, stopped = complete(token, stop_job, result={
    "deploymentId": deployment_id, "state": "stopped", "logs": [],
})
check("Stop completed", status == 200 and stopped.get("state") == "succeeded")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
detail = detail_body.get("deployment", {})
check("Stop committed desired state and revision", detail.get("desiredState") == "stopped" and
      detail.get("desiredRevision") == initial_revision + 1 and detail.get("observedState") == "stopped")
generation_d = "gen_" + secrets.token_urlsafe(18)
heartbeat(token, generation_d, [])
status, after_stop = claim(token)
check("fresh Agent never recovers intentional Stop", status == 200 and after_stop is None)

section("legacy Agent compatibility")
status, legacy_pairing_body = operator.request("POST", "/api/nodes", {"name": "Phase 18 Legacy Node"})
legacy_pairing = legacy_pairing_body.get("pairing") if isinstance(legacy_pairing_body, dict) else None
status, legacy = anonymous.request("POST", "/api/nodes/agent/pair", {
    "code": legacy_pairing["code"], "agentVersion": "0.4.2", "protocolVersion": 1,
    "platform": "win32", "architecture": "x64", "capabilities": CAPABILITIES,
})
legacy_token = legacy.get("token") if isinstance(legacy, dict) else None
status, _ = heartbeat(legacy_token, None, [], agent="0.4.2")
check("Agent 0.4.2 legacy heartbeat remains accepted", status == 200, f"got {status}")
status, legacy_job = claim(legacy_token)
check("legacy Agent receives no recovery job", status == 200 and legacy_job is None)

section("recovery audit integrity")
status, audit_body = operator.request("GET", "/api/audit?action=deployment.recovery&limit=100")
events = audit_body.get("events", []) if isinstance(audit_body, dict) else []
automatic = [event for event in events if event.get("actorType") == "system"]
manual_events = [event for event in events if event.get("actorType") == "user"]
check("recovery success/blocked/failed evidence exists", status == 200 and
      any(event.get("outcome") == "success" for event in events) and
      any(event.get("metadata", {}).get("reasonCode") == "port_in_use" for event in events) and
      any(event.get("metadata", {}).get("reasonCode") == "health_failed" for event in events))
check("automatic recovery actor is system", bool(automatic))
check("manual recovery actor is user", bool(manual_events))
sequences = [event.get("sequence") for event in events]
check("recovery evidence is numbered without duplicates", all(isinstance(value, int) for value in sequences) and
      len(sequences) == len(set(sequences)))
serialized = json.dumps(events)
check("audit metadata contains no token/path/PID/secret", token not in serialized and
      "\\Users\\" not in serialized and '"pid"' not in serialized.lower() and "Phase18-local" not in serialized)

print(f"\nBROWSER_EMAIL={email}")
print(f"BROWSER_PASSWORD={password}")
print("\n" + "=" * 60)
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
if FAILED:
    for failure in FAILED:
        print(f"    - {failure}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
