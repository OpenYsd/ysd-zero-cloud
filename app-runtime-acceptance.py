"""App Runtime control-plane acceptance against a real Worker and D1.

The actual Node.js build/process sandbox is exercised by tests/app-runtime.test.ts
under the verified portable Node 26 runtime. This script independently proves
the HTTP control plane: tenancy, strict request shapes, signed leases, replay,
idempotency, lifecycle transitions, artifact integrity, cancellation, Shield
events, and revocation. It never creates a paid or public resource.
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

BASE = os.environ.get("YSD_APP_RUNTIME_ACCEPTANCE_BASE", "http://localhost:3000")
RUN = secrets.token_hex(4)
PASSED: list[str] = []
FAILED: list[str] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class Client:
    def __init__(self, address: str) -> None:
        self.address = address
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def request(self, method: str, path: str, body=None, headers=None):
        raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request = urllib.request.Request(
            f"{BASE}{path}", data=raw, method=method, headers={
                "Content-Type": "application/json",
                "Origin": BASE,
                "Referer": f"{BASE}/",
                "CF-Connecting-IP": self.address,
                "User-Agent": "ysd-app-runtime-acceptance/1.0",
                **(headers or {}),
            }
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


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def section(name: str) -> None:
    print(f"\n=== {name} ===")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def agent_request(token: str, path: str, body: dict, *, nonce=None, timestamp=None,
                  signature=None):
    raw = json.dumps(body, separators=(",", ":"))
    nonce = nonce or b64url(secrets.token_bytes(18))
    timestamp = timestamp or int(time.time() * 1000)
    body_hash = b64url(hashlib.sha256(raw.encode()).digest())
    message = "\n".join([
        "ysd-node-request-v1", "POST", path, str(timestamp), nonce, body_hash
    ])
    signature = signature or b64url(
        hmac.new(token.encode(), message.encode(), hashlib.sha256).digest()
    )
    request = urllib.request.Request(
        f"{BASE}{path}", data=raw.encode(), method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-YSD-Timestamp": str(timestamp),
            "X-YSD-Nonce": nonce,
            "X-YSD-Signature": signature,
            "User-Agent": "ysd-app-runtime-acceptance-agent/1.0",
        }
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    return status, json.loads(payload) if payload else None, {
        "nonce": nonce, "timestamp": timestamp, "signature": signature
    }


def complete(token: str, job: dict, status_value="succeeded", result=None, error=None):
    body = {
        "leaseId": job["claim"]["leaseId"],
        "claim": job["claim"],
        "claimSignature": job["signature"],
        "status": status_value,
    }
    if result is not None:
        body["result"] = result
    if error is not None:
        body["error"] = error
        body["retryable"] = False
    return agent_request(
        token, f'/api/nodes/agent/jobs/{job["claim"]["jobId"]}/complete', body
    )


def claim(token: str):
    status, body, _ = agent_request(token, "/api/nodes/agent/claim", {})
    return status, body.get("job") if isinstance(body, dict) else None


operator = Client("198.51.100.10")
other = Client("198.51.100.11")
anonymous = Client("198.51.100.12")

section("accounts and private API")
for index, client in enumerate((operator, other), start=1):
    status, _ = client.request("POST", "/api/auth/sign-up/email", {
        "name": f"App Operator {index}",
        "email": f"app-{index}-{RUN}@ysd.test",
        "password": f"app-runtime-acceptance-{index}-{RUN}",
    })
    check(f"operator {index} signed up", status == 200, f"got {status}")
status, _ = anonymous.request("GET", "/api/deployments")
check("anonymous deployment inventory is closed", status == 401, f"got {status}")

section("offline and capable node selection")
status, pairing_body = operator.request("POST", "/api/nodes", {"name": "App Runtime Node 26"})
pairing = pairing_body.get("pairing") if isinstance(pairing_body, dict) else None
check("pairing ticket created", status == 201 and pairing, f"got {status}")

capabilities = {
    "cpu": {"cores": 8, "model": "Acceptance CPU"},
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
        "packageManagers": ["npm"], "activeDeployments": 0,
        "maxDeployments": 12,
    },
    "contracts": {"ai": False, "gameServers": False, "appRuntime": True},
}
status, paired = anonymous.request("POST", "/api/nodes/agent/pair", {
    "code": pairing["code"], "agentVersion": "0.4.0", "protocolVersion": 1,
    "platform": "acceptance", "architecture": "x64", "capabilities": capabilities,
})
token = paired.get("token") if isinstance(paired, dict) else None
node_id = paired.get("nodeId") if isinstance(paired, dict) else None
check("Node 26 App Runtime agent paired", status == 201 and token and node_id, f"got {status}")

deploy_request = {
    "repository": "heroku/node-js-getting-started",
    "branch": "main",
    "nodeId": node_id,
    "environment": "Production",
    "healthPath": "/",
    "memoryMb": 256,
    "diskQuotaBytes": 256 * 1024**2,
    "target": "user-node",
}
status, _ = operator.request("POST", "/api/smart-deploy", deploy_request)
check("offline node is refused", status == 409, f"got {status}")

heartbeat = {
    "agentVersion": "0.4.0", "capabilities": capabilities,
    "metrics": {
        "cpuLoadPercent": 10, "memoryUsedBytes": 2 * 1024**3,
        "memoryTotalBytes": 16 * 1024**3, "runningJobs": 0,
    },
    "gameServers": [], "appDeployments": [],
}
status, _, replay_proof = agent_request(token, "/api/nodes/agent/heartbeat", heartbeat)
check("signed App Runtime heartbeat accepted", status == 200, f"got {status}")
status, _, _ = agent_request(
    token, "/api/nodes/agent/heartbeat", heartbeat,
    nonce=replay_proof["nonce"], timestamp=replay_proof["timestamp"],
    signature=replay_proof["signature"],
)
check("heartbeat replay rejected", status == 401, f"got {status}")

low_capabilities = json.loads(json.dumps(capabilities))
low_capabilities["memory"]["freeBytes"] = 128 * 1024**2
low_capabilities["disk"]["freeBytes"] = 256 * 1024**2
status, _, _ = agent_request(token, "/api/nodes/agent/heartbeat", {
    **heartbeat, "capabilities": low_capabilities,
})
status, _ = operator.request("POST", "/api/smart-deploy", deploy_request)
check("insufficient RAM and disk are refused", status == 409, f"got {status}")
agent_request(token, "/api/nodes/agent/heartbeat", heartbeat)

section("strict Smart Deploy input and repository policy")
for name, mutation in [
    ("arbitrary command", {"command": "whoami"}),
    ("executable path", {"executablePath": "C:\\Windows\\System32\\cmd.exe"}),
    ("paid provider", {"provider": "paid"}),
    ("paid tunnel", {"tunnel": "argo"}),
    ("Zero Mode bypass", {"zeroMode": False}),
]:
    status, _ = operator.request("POST", "/api/smart-deploy", {**deploy_request, **mutation})
    check(f"{name} is rejected", status == 400, f"got {status}")

status, blocked = operator.request("POST", "/api/smart-deploy", {
    **deploy_request, "repository": "OpenYsd/ysd-zero-cloud",
})
check(
    "unsupported repository without a safe Node lock contract is blocked",
    status == 409 and isinstance(blocked, dict) and blocked.get("deployment", {}).get("state") == "blocked",
    f"got {status}",
)

section("valid pinned Node.js deploy and idempotency")
key = f"app-deploy-{RUN}"
status, created = operator.request(
    "POST", "/api/smart-deploy", deploy_request, {"Idempotency-Key": key}
)
deployment = created.get("deployment") if isinstance(created, dict) else None
deployment_id = deployment.get("id") if isinstance(deployment, dict) else None
check("valid Express deploy queued", status == 202 and deployment_id, f"got {status}")
check(
    "plan is private on the selected user node",
    created.get("plan", {}).get("target") == "user-node"
    and created.get("plan", {}).get("exposure") == "private"
    and created.get("plan", {}).get("protection", {}).get("estimatedMonthlyCost") == 0,
)
status, duplicate = operator.request(
    "POST", "/api/smart-deploy", deploy_request, {"Idempotency-Key": key}
)
check(
    "duplicate deploy is idempotent",
    status == 200 and duplicate.get("duplicate") is True
    and duplicate.get("deployment", {}).get("id") == deployment_id,
    f"got {status}",
)

status, other_inventory = other.request("GET", "/api/deployments")
check("second workspace sees no deployment", status == 200 and not other_inventory["deployments"])
status, _ = other.request("GET", f"/api/deployments/{deployment_id}")
check("cross-workspace deployment detail is refused", status == 404, f"got {status}")

status, job = claim(token)
check("signed App Runtime deploy lease issued", status == 200 and job and job["claim"]["type"] == "app-runtime.action")
claim_signature = b64url(hmac.new(
    token.encode(), ("ysd-node-job-v1\n" + stable(job["claim"])).encode(), hashlib.sha256
).digest())
check("App Runtime claim signature verifies", hmac.compare_digest(claim_signature, job["signature"]))
status, empty = claim(token)
check("leased deploy cannot be claimed twice", status == 200 and empty is None)

completion_path = f'/api/nodes/agent/jobs/{job["claim"]["jobId"]}/complete'
forged_completion = {
    "leaseId": job["claim"]["leaseId"], "claim": job["claim"],
    "claimSignature": "forged", "status": "succeeded",
    "result": {"checksum": "sha256:" + "a" * 64},
}
status, _, _ = agent_request(token, completion_path, forged_completion)
check("forged deploy completion rejected", status == 403, f"got {status}")

success_result = {
    "deploymentId": deployment_id, "state": "running",
    "checksum": "sha256:" + "a" * 64, "sizeBytes": 8192,
    "localAddress": deployment["localAddress"], "bind": "127.0.0.1",
    "exposure": "private", "networkGuard": True,
    "restartCount": 0, "crashLoop": False,
    "buildDurationMs": 1234, "deployDurationMs": 1600,
    "logs": ["[runtime] API_TOKEN=acceptance-secret", "[runtime] ready"],
}
status, completed, completion_proof = complete(token, job, result=success_result)
check("signed deploy completion accepted", status == 200 and completed["state"] == "succeeded")
status, _, _ = agent_request(
    token, completion_path, {
        "leaseId": job["claim"]["leaseId"], "claim": job["claim"],
        "claimSignature": job["signature"], "status": "succeeded",
        "result": success_result,
    }, nonce=completion_proof["nonce"], timestamp=completion_proof["timestamp"],
    signature=completion_proof["signature"],
)
check("deploy completion replay rejected", status == 401, f"got {status}")

status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
detail = detail_body.get("deployment") if isinstance(detail_body, dict) else None
serialised = json.dumps(detail)
artifacts = detail.get("artifacts", []) if isinstance(detail, dict) else []
check("healthy private deployment is recorded", status == 200 and detail["state"] == "healthy" and detail["exposure"] == "private")
check("verified signed artifact is recorded", any(item["state"] == "verified" and item["checksum"] == "sha256:" + "a" * 64 for item in artifacts))
check("environment-shaped log is redacted", "acceptance-secret" not in serialised and "REDACTED" in serialised)
check("no fabricated public URL exists", detail["localAddress"].startswith("http://127.0.0.1:") and "publicUrl" not in serialised)

section("lifecycle, health failure, crash loop, rollback, and cancellation")
status, stopped = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "stop"},
    {"Idempotency-Key": f"stop-{RUN}"},
)
check("stop action queued", status == 202, f"got {status}")
status, stop_job = claim(token)
status, stop_done, _ = complete(token, stop_job, result={
    "deploymentId": deployment_id, "state": "stopped", "logs": [],
})
check("stop completion is deterministic", status == 200 and stop_done["state"] == "succeeded")

artifact_id = artifacts[0]["id"]
status, _ = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions",
    {"operation": "rollback", "targetArtifactId": "art_" + "f" * 24},
)
check("rollback to unknown artifact is refused", status == 409, f"got {status}")
status, rollback = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions",
    {"operation": "rollback", "targetArtifactId": artifact_id},
    {"Idempotency-Key": f"rollback-{RUN}"},
)
check("rollback to verified local artifact queued", status == 202, f"got {status}")
status, rollback_job = claim(token)
status, rollback_done, _ = complete(token, rollback_job, result={
    **success_result, "checksum": "sha256:" + "a" * 64, "rolledBack": True,
})
check("verified rollback succeeds", status == 200 and rollback_done["state"] == "succeeded")

status, restart = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "restart"},
    {"Idempotency-Key": f"restart-fail-{RUN}"},
)
status, health_job = claim(token)
status, health_done, _ = complete(
    token, health_job, status_value="failed",
    error="The localhost health check failed: HTTP 503.",
)
check("health check failure is recorded", status == 200 and health_done["state"] == "failed")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
check("failed health state is visible", detail_body["deployment"]["state"] == "failed")

status, restart = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "restart"},
    {"Idempotency-Key": f"restart-crash-{RUN}"},
)
status, crash_job = claim(token)
status, crash_done, _ = complete(token, crash_job, result={
    "deploymentId": deployment_id, "state": "crash_loop", "bind": "127.0.0.1",
    "restartCount": 3, "crashLoop": True, "networkGuard": True, "logs": [],
})
check("bounded crash-loop state is accepted", status == 200 and crash_done["state"] == "succeeded")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
check("crash-loop protection is visible", detail_body["deployment"]["state"] == "crash_loop")

status, redeploy = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "redeploy"},
    {"Idempotency-Key": f"redeploy-cancel-{RUN}"},
)
check("redeploy queued for cancellation", status == 202, f"got {status}")
status, redeploy_job = claim(token)
status, cancel_body = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "cancel"}
)
check("leased build cancellation requested", status == 200 and cancel_body["state"] == "cancelling")
status, lease_state, _ = agent_request(
    token, f'/api/nodes/agent/jobs/{redeploy_job["claim"]["jobId"]}/status',
    {"leaseId": redeploy_job["claim"]["leaseId"]},
)
check("agent observes cancellation", status == 200 and lease_state["cancelRequested"] is True)
status, cancelled, _ = complete(
    token, redeploy_job, status_value="cancelled", error="The build was cancelled."
)
check("cancelled completion is final", status == 200 and cancelled["state"] == "cancelled")

section("revocation during runtime")
status, start = operator.request(
    "POST", f"/api/deployments/{deployment_id}/actions", {"operation": "start"},
    {"Idempotency-Key": f"start-revoke-{RUN}"},
)
status, start_job = claim(token)
check("start lease claimed before revocation", status == 200 and start_job)
status, _ = operator.request("DELETE", f"/api/nodes/{node_id}")
check("node revoked", status == 200, f"got {status}")
status, _, _ = agent_request(token, "/api/nodes/agent/heartbeat", heartbeat)
check("revoked agent cannot heartbeat", status == 401, f"got {status}")
status, _, _ = complete(token, start_job, result=success_result)
check("revoked App Runtime completion is refused", status == 401, f"got {status}")
status, detail_body = operator.request("GET", f"/api/deployments/{deployment_id}")
check("deployment records node revocation", detail_body["deployment"]["state"] == "node_revoked")
status, node_state = operator.request("GET", "/api/nodes")
check(
    "revocation security event is auditable",
    any(event["type"] == "revoked-node-app-activity" for event in node_state["securityEvents"]),
)

print("\n" + "=" * 60)
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
if FAILED:
    for failure in FAILED:
        print(f"    - {failure}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
