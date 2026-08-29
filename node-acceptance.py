"""End-to-end Compute Nodes acceptance run.

Runs against the real Worker+D1 API, usually the local dev server where the
interactive Turnstile challenge is deliberately unconfigured. The script
proves pairing, signed outbound traffic, job leases, tenant isolation,
idempotency, replay rejection, malicious payload refusal, and revocation.
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

BASE = os.environ.get("YSD_NODE_ACCEPTANCE_BASE", "http://localhost:3000")
RUN = secrets.token_hex(4)
PASSED: list[str] = []
FAILED: list[str] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def request(self, method: str, path: str, body=None, headers=None):
        raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request_headers = {
            "Content-Type": "application/json",
            "Origin": BASE,
            "Referer": f"{BASE}/",
            "User-Agent": "ysd-node-acceptance/1.0",
            **(headers or {}),
        }
        request = urllib.request.Request(
            f"{BASE}{path}", data=raw, method=method, headers=request_headers
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            payload = error.read()
            status = error.code
        try:
            return status, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return status, payload.decode("utf-8", "replace")


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def agent_request(token: str, path: str, body: dict, *, nonce: str | None = None,
                  timestamp: int | None = None, signature: str | None = None):
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
            "User-Agent": "ysd-node-acceptance-agent/1.0",
        }
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        payload = error.read()
        status = error.code
    parsed = json.loads(payload) if payload else None
    return status, parsed, {"nonce": nonce, "timestamp": timestamp, "signature": signature}


def section(name: str) -> None:
    print(f"\n=== {name} ===")


one = Client()
two = Client()
anonymous = Client()

section("accounts and workspaces")
for index, client in enumerate((one, two), start=1):
    status, body = client.request("POST", "/api/auth/sign-up/email", {
        "name": f"Node Operator {index}",
        "email": f"node-{index}-{RUN}@ysd.test",
        "password": f"node-acceptance-password-{index}-{RUN}",
    })
    check(f"operator {index} signed up", status == 200, f"got {status}: {body}")

status, _ = anonymous.request("GET", "/api/nodes")
check("anonymous node inventory is closed", status == 401, f"got {status}")

section("one-time pairing")
status, body = one.request("POST", "/api/nodes", {"name": "Acceptance node"})
pairing = body.get("pairing") if isinstance(body, dict) else None
check("pairing ticket created", status == 201 and pairing, f"got {status}")

capabilities = {
    "cpu": {"cores": 4, "model": "Acceptance CPU"},
    "memory": {"totalBytes": 8 * 1024**3, "freeBytes": 6 * 1024**3},
    "gpu": {"available": False, "model": None, "vramBytes": None},
    "disk": {"totalBytes": 20 * 1024**3, "freeBytes": 15 * 1024**3},
    "docker": {"available": True},
    "ai": {"runtimes": [], "cachedModels": [], "maxConcurrentJobs": 1},
    "contracts": {"ai": False, "gameServers": True},
}
pair_body = {
    "code": pairing["code"],
    "agentVersion": "0.2.0",
    "protocolVersion": 1,
    "platform": "acceptance",
    "architecture": "x64",
    "capabilities": capabilities,
}
status, body = anonymous.request("POST", "/api/nodes/agent/pair", pair_body)
token = body.get("token") if isinstance(body, dict) else None
node_id = body.get("nodeId") if isinstance(body, dict) else None
check("agent paired", status == 201 and token and node_id, f"got {status}")

status, _ = anonymous.request("POST", "/api/nodes/agent/pair", pair_body)
check("pairing ticket cannot be replayed", status in (401, 409), f"got {status}")

section("signed heartbeat and replay protection")
heartbeat = {
    "agentVersion": "0.2.0",
    "capabilities": capabilities,
    "metrics": {
        "cpuLoadPercent": 12.5,
        "memoryUsedBytes": 2 * 1024**3,
        "memoryTotalBytes": 8 * 1024**3,
        "runningJobs": 0,
    },
}
status, _, proof = agent_request(token, "/api/nodes/agent/heartbeat", heartbeat)
check("signed heartbeat accepted", status == 200, f"got {status}")

status, _, _ = agent_request(
    token, "/api/nodes/agent/heartbeat", heartbeat,
    nonce=proof["nonce"], timestamp=proof["timestamp"], signature=proof["signature"]
)
check("heartbeat replay rejected", status == 401, f"got {status}")

status, _, _ = agent_request(
    token, "/api/nodes/agent/heartbeat", {**heartbeat, "metrics": {**heartbeat["metrics"], "cpuLoadPercent": 99}},
    signature=proof["signature"]
)
check("forged heartbeat rejected", status == 401, f"got {status}")

status, state = one.request("GET", "/api/nodes")
serialised = json.dumps(state)
check("node is online", status == 200 and state["summary"]["online"] == 1)
check("node credentials never leave the API", token not in serialised and "tokenCiphertext" not in serialised)

section("strict job allowlist and idempotency")
status, _ = one.request("POST", "/api/nodes/jobs", {
    "type": "diagnostic.ping", "payload": {"shell": "whoami"}
})
check("shell-shaped payload rejected", status == 400, f"got {status}")

status, _ = one.request("POST", "/api/nodes/jobs", {
    "type": "ai.inference", "payload": {"prompt": "run"}
})
check("AI work cannot bypass AI Center", status == 400, f"got {status}")

idempotency = f"node-job-{RUN}"
job_body = {
    "type": "diagnostic.ping",
    "targetNodeId": node_id,
    "payload": {"message": "signed hello"},
}
status, first = one.request("POST", "/api/nodes/jobs", job_body,
                            {"Idempotency-Key": idempotency})
job_id = first.get("job", {}).get("id") if isinstance(first, dict) else None
check("diagnostic job queued", status == 201 and job_id, f"got {status}")
status, duplicate = one.request("POST", "/api/nodes/jobs", job_body,
                                {"Idempotency-Key": idempotency})
check("duplicate job de-duplicated", status == 200 and duplicate["job"]["id"] == job_id
      and duplicate["duplicate"] is True, f"got {status}")

section("tenant isolation")
status, other_state = two.request("GET", "/api/nodes")
check("second workspace sees no nodes", status == 200 and not other_state["nodes"])
check("second workspace sees no jobs", status == 200 and not other_state["jobs"])
status, _ = two.request("DELETE", f"/api/nodes/{node_id}")
check("cross-tenant revocation is refused", status == 404, f"got {status}")

section("signed claims and completion")
status, claimed, _ = agent_request(token, "/api/nodes/agent/claim", {})
job = claimed.get("job") if isinstance(claimed, dict) else None
check("job claimed once", status == 200 and job and job["claim"]["jobId"] == job_id)

claim_text = "ysd-node-job-v1\n" + stable(job["claim"])
expected_claim_signature = b64url(
    hmac.new(token.encode(), claim_text.encode(), hashlib.sha256).digest()
)
check("control-plane claim signature verifies",
      hmac.compare_digest(expected_claim_signature, job["signature"]))

status, empty_claim, _ = agent_request(token, "/api/nodes/agent/claim", {})
check("leased job is not claimed twice", status == 200 and empty_claim["job"] is None)

completion_path = f"/api/nodes/agent/jobs/{job_id}/complete"
completion = {
    "leaseId": job["claim"]["leaseId"],
    "claim": job["claim"],
    "claimSignature": "forged",
    "status": "succeeded",
    "result": {"reply": "pong"},
}
status, _, _ = agent_request(token, completion_path, completion)
check("forged job completion rejected", status == 403, f"got {status}")

completion["claimSignature"] = job["signature"]
status, body, completion_proof = agent_request(token, completion_path, completion)
check("signed job completion accepted", status == 200 and body["state"] == "succeeded")
status, _, _ = agent_request(
    token, completion_path, completion,
    nonce=completion_proof["nonce"], timestamp=completion_proof["timestamp"],
    signature=completion_proof["signature"]
)
check("completion replay rejected", status == 401, f"got {status}")

section("revocation")
status, _ = one.request("DELETE", f"/api/nodes/{node_id}")
check("owner revokes node", status == 200, f"got {status}")
status, _, _ = agent_request(token, "/api/nodes/agent/heartbeat", heartbeat)
check("revoked token cannot heartbeat", status == 401, f"got {status}")

status, state = one.request("GET", "/api/nodes")
check("revoked status is visible", status == 200 and state["summary"]["revoked"] == 1)
check("completed job remains auditable", any(
    item["id"] == job_id and item["state"] == "succeeded" for item in state["jobs"]
))
check("anomalous activity is visible", len(state["securityEvents"]) >= 3)

print("\n" + "=" * 60)
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
if FAILED:
    for failure in FAILED:
        print(f"    - {failure}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
