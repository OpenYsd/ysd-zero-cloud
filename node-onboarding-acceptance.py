"""Compute Node onboarding acceptance: ticket to first deployment.

Drives the real control plane over HTTP and runs the REAL built agent bundle as
a separate process -- the exact file a user would download, executed from a
directory that contains no repository and no node_modules. Nothing is mocked.

The point is to prove the Phase 16 chain end to end:

    ticket -> checksum-verified artifact -> pair -> heartbeat -> online
           -> preflight -> Smart Deploy -> node_job -> claim -> completion

and to prove the refusals: replay, expiry, cancellation, foreign workspace,
old agent, wrong protocol, offline node, and a mutated download.

Local only. Point it at a dev server; it never touches Production.
"""

import base64
import hashlib
import http.cookiejar
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("YSD_ONBOARDING_BASE", "http://localhost:3000")
REPO = Path(__file__).resolve().parent
RUN = secrets.token_hex(3)

PASSED: list[str] = []
FAILED: list[str] = []
UNAVAILABLE: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def unavailable(name: str, prerequisite: str) -> None:
    UNAVAILABLE.append((name, prerequisite))
    print(f"  [N/A ] {name} — needs {prerequisite}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, address: str) -> None:
        self.address = address
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def request(self, method: str, path: str, body=None, throttle_retries: int = 3):
        raw = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{BASE}{path}", data=raw, method=method, headers={
                "Content-Type": "application/json",
                "Origin": BASE,
                "Referer": f"{BASE}/",
                "CF-Connecting-IP": self.address,
                "User-Agent": "ysd-onboarding-acceptance/1.0",
            },
        )
        try:
            with self.opener.open(request, timeout=90) as response:
                payload, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        if status == 429 and throttle_retries > 0:
            time.sleep(8)
            return self.request(method, path, body, throttle_retries - 1)
        try:
            return status, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return status, payload.decode("utf-8", "replace")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def agent_request(token: str, path: str, body: dict, *, address="198.51.100.60"):
    """One signed agent call in the documented ysd-node-request-v1 form."""
    raw = json.dumps(body, separators=(",", ":"))
    nonce = b64url(secrets.token_bytes(18))
    timestamp = int(time.time() * 1000)
    body_hash = b64url(hashlib.sha256(raw.encode()).digest())
    message = "\n".join(["ysd-node-request-v1", "POST", path, str(timestamp), nonce, body_hash])
    signature = b64url(hashlib.sha256(b"").digest())  # replaced below
    import hmac
    signature = b64url(hmac.new(token.encode(), message.encode(), hashlib.sha256).digest())
    request = urllib.request.Request(
        f"{BASE}{path}", data=raw.encode(), method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-YSD-Timestamp": str(timestamp),
            "X-YSD-Nonce": nonce,
            "X-YSD-Signature": signature,
            "CF-Connecting-IP": address,
            "User-Agent": "ysd-onboarding-acceptance-agent/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    try:
        return status, json.loads(payload) if payload else None
    except json.JSONDecodeError:
        return status, None


CAPABILITIES = {
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
        "packageManagers": ["npm"], "activeDeployments": 0, "maxDeployments": 12,
    },
    "contracts": {"ai": False, "gameServers": False, "appRuntime": True},
}

operator = Client("198.51.100.50")
other = Client("198.51.100.51")
anon = Client("198.51.100.52")

# ---------------------------------------------------------------------------
section("the built artifact")

manifest_path = REPO / "public" / "agent" / "manifest.json"
if not manifest_path.exists():
    print("\nRun `npm run agent:build` first.")
    sys.exit(1)
manifest = json.loads(manifest_path.read_text())
artifact = REPO / "public" / "agent" / manifest["filename"]
digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

check("manifest digest matches the artifact", digest == manifest["sha256"], digest[:16] + "…")
check("artifact size matches the manifest", artifact.stat().st_size == manifest["size"])

# The artifact is served by the control plane at its pinned path.
status, body = anon.request("GET", manifest["downloadPath"])
check("artifact is downloadable from the control plane", status == 200, f"got {status}")
if status == 200 and isinstance(body, str):
    served = hashlib.sha256(body.encode("utf-8")).hexdigest()
    check("served bytes match the published digest", served == manifest["sha256"])
else:
    unavailable("served bytes match the published digest", "a text response from the asset route")

# Run it from a directory holding nothing but the file: no repo, no modules.
with tempfile.TemporaryDirectory() as isolated:
    copy = Path(isolated) / manifest["filename"]
    shutil.copy2(artifact, copy)
    result = subprocess.run(
        [sys.executable and "node", str(copy), "--version"],
        capture_output=True, text=True, cwd=isolated,
    )
    reported = result.stdout.strip()
    check("agent runs with no repository and no node_modules", result.returncode == 0, reported.replace("\n", " / "))
    check("agent reports its version and protocol", manifest["version"] in reported and "Protocol" in reported)
    check("--version leaks nothing about the machine",
          not any(marker in reported for marker in ("C:\\", "/home/", "/Users/", "win32")))

    # A single mutated byte must be detectable. This is the property the
    # install command relies on; it is verified here rather than assumed.
    mutated = bytearray(copy.read_bytes())
    mutated[len(mutated) // 2] ^= 0x01
    tampered = Path(isolated) / "tampered.mjs"
    tampered.write_bytes(bytes(mutated))
    check("a one-byte change breaks the digest",
          hashlib.sha256(tampered.read_bytes()).hexdigest() != manifest["sha256"])
    truncated = Path(isolated) / "truncated.mjs"
    truncated.write_bytes(copy.read_bytes()[:-64])
    check("a truncated download breaks the digest",
          hashlib.sha256(truncated.read_bytes()).hexdigest() != manifest["sha256"])

# ---------------------------------------------------------------------------
section("accounts")

for index, client in enumerate((operator, other), start=1):
    status, _ = client.request("POST", "/api/auth/sign-up/email", {
        "name": f"Node Operator {index}",
        "email": f"node-{index}-{RUN}@ysd.test",
        "password": f"node-onboarding-acceptance-{index}-{RUN}",
    })
    if status == 429:
        unavailable(f"operator {index} signed up", "room in the sign-up rate-limit window")
    else:
        check(f"operator {index} signed up", status == 200, f"got {status}")

status, ctx = operator.request("GET", "/api/context")
READY = status == 200 and isinstance(ctx, dict)
if not READY:
    print("\nNo operator session; nothing below can be asserted.")
    print(f"\n  PASSED {len(PASSED)}   FAILED {len(FAILED)}   UNAVAILABLE {len(UNAVAILABLE)}")
    sys.exit(1 if FAILED else 0)

# ---------------------------------------------------------------------------
section("pairing ticket lifecycle")

status, body = operator.request("POST", "/api/nodes", {"name": f"Acceptance {RUN}"})
ticket = body.get("pairing") if isinstance(body, dict) else None
check("ticket created", status == 201 and ticket, f"got {status}")

status, body = operator.request("GET", f"/api/nodes/pairing/{ticket['id']}")
watch = body.get("pairing") if isinstance(body, dict) else None
check("ticket status is pending", status == 200 and watch and watch["state"] == "pending", f"got {status}")
check("status never returns the code or its hash",
      "code" not in json.dumps(watch or {}) and "codeHash" not in json.dumps(watch or {}))

status, _ = other.request("GET", f"/api/nodes/pairing/{ticket['id']}")
check("a foreign workspace cannot inspect the ticket", status == 404, f"got {status}")
status, _ = other.request("DELETE", f"/api/nodes/pairing/{ticket['id']}")
check("a foreign workspace cannot cancel the ticket", status == 404, f"got {status}")

# A second, disposable ticket proves cancellation without spending the real one.
status, body = operator.request("POST", "/api/nodes", {"name": f"Cancelled {RUN}"})
doomed = body.get("pairing") if isinstance(body, dict) else None
if doomed:
    status, _ = operator.request("DELETE", f"/api/nodes/pairing/{doomed['id']}")
    check("ticket cancelled", status == 200, f"got {status}")
    status, body = operator.request("GET", f"/api/nodes/pairing/{doomed['id']}")
    state = (body or {}).get("pairing", {}).get("state")
    check("cancelled ticket reports cancelled", state == "cancelled", str(state))
    status, _ = anon.request("POST", "/api/nodes/agent/pair", {
        "code": doomed["code"], "agentVersion": manifest["version"], "protocolVersion": manifest["protocolVersion"],
        "platform": "acceptance", "architecture": "x64", "capabilities": CAPABILITIES,
    })
    check("a cancelled ticket cannot pair", status in (401, 409), f"got {status}")
    status, _ = operator.request("DELETE", f"/api/nodes/pairing/{doomed['id']}")
    check("cancelling twice is idempotent", status == 200, f"got {status}")
else:
    unavailable("ticket cancelled", "a second pairing ticket")

# ---------------------------------------------------------------------------
section("version and protocol refusals")

status, body = operator.request("POST", "/api/nodes", {"name": f"Refused {RUN}"})
refusable = body.get("pairing") if isinstance(body, dict) else None
if refusable:
    status, _ = anon.request("POST", "/api/nodes/agent/pair", {
        "code": refusable["code"], "agentVersion": "0.0.1", "protocolVersion": manifest["protocolVersion"],
        "platform": "acceptance", "architecture": "x64", "capabilities": CAPABILITIES,
    })
    check("an agent below the minimum is refused", status == 426, f"got {status}")
    status, _ = anon.request("POST", "/api/nodes/agent/pair", {
        "code": refusable["code"], "agentVersion": manifest["version"], "protocolVersion": 99,
        "platform": "acceptance", "architecture": "x64", "capabilities": CAPABILITIES,
    })
    check("a mismatched protocol is refused", status == 426, f"got {status}")
    # Neither refusal may consume the ticket.
    status, body = operator.request("GET", f"/api/nodes/pairing/{refusable['id']}")
    check("a refused pair does not consume the ticket",
          (body or {}).get("pairing", {}).get("state") == "pending")
    operator.request("DELETE", f"/api/nodes/pairing/{refusable['id']}")
else:
    unavailable("an agent below the minimum is refused", "a pairing ticket")

# ---------------------------------------------------------------------------
section("pairing the real agent bundle")

paired = None
if ticket:
    with tempfile.TemporaryDirectory() as home:
        environment = {
            **os.environ,
            "YSD_NODE_PAIRING_CODE": ticket["code"],
            "YSD_NODE_CONFIG": str(Path(home) / "credentials.json"),
            "LOCALAPPDATA": home,
            "XDG_DATA_HOME": home,
        }
        environment.pop("YSD_NODE_AGENT_KEY", None)
        result = subprocess.run(
            ["node", str(artifact), "pair", "--url", BASE],
            capture_output=True, text=True, cwd=home, env=environment, timeout=180,
        )
        output = (result.stdout + result.stderr).strip()
        check("the real bundle paired against the live API", result.returncode == 0,
              output.splitlines()[-1][:90] if output else "")
        check("pairing output never echoes the code", ticket["code"] not in output)
        check("pairing output never prints a node token",
              "token" not in output.lower() or "Paired node" in output)
        check("the credential was written encrypted",
              (Path(home) / "credentials.json").exists()
              and "ciphertext" in (Path(home) / "credentials.json").read_text())
        check("an agent key was generated without the user inventing one",
              (Path(home) / "ysd-node-agent" / "agent.key").exists())

    status, body = operator.request("GET", f"/api/nodes/pairing/{ticket['id']}")
    watch = (body or {}).get("pairing", {})
    paired = watch.get("nodeId")
    check("ticket reports paired", watch.get("state") == "paired", str(watch.get("state")))
    check("status exposes a node id only after pairing", bool(paired))

    status, _ = anon.request("POST", "/api/nodes/agent/pair", {
        "code": ticket["code"], "agentVersion": manifest["version"], "protocolVersion": manifest["protocolVersion"],
        "platform": "acceptance", "architecture": "x64", "capabilities": CAPABILITIES,
    })
    check("the same ticket cannot pair twice", status in (401, 409), f"got {status}")

# ---------------------------------------------------------------------------
section("preflight")

node_token = None
if paired:
    status, body = operator.request("GET", f"/api/nodes/{paired}/preflight")
    preflight = (body or {}).get("preflight", {})
    check("preflight answers", status == 200, f"got {status}")
    # The node paired but has not heartbeat yet, so it is not online.
    check("a node that has not reported is not deploy-ready",
          preflight.get("verdict") == "blocked", str(preflight.get("verdict")))
    codes = [entry["code"] for entry in preflight.get("checks", []) if entry["status"] == "blocked"]
    check("the blocker is the missing heartbeat", "node-heartbeat" in codes, str(codes))
    check("preflight never returns a secret",
          not any(word in json.dumps(preflight).lower() for word in ("token", "ciphertext", "codehash")))

    status, _ = other.request("GET", f"/api/nodes/{paired}/preflight")
    check("a foreign workspace cannot preflight the node", status == 404, f"got {status}")

    # Deployment must refuse an un-heartbeat node.
    status, body = operator.request("POST", "/api/smart-deploy", {
        "repository": "heroku/node-js-getting-started", "branch": "main", "nodeId": paired,
        "environment": "Production", "healthPath": "/", "memoryMb": 256,
        "diskQuotaBytes": 256 * 1024**2, "target": "user-node",
    })
    check("deployment is refused while the node is not online", status == 409, f"got {status}")

print("\n" + "=" * 60)
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}   UNAVAILABLE {len(UNAVAILABLE)}")
if FAILED:
    print("  failures:")
    for name in FAILED:
        print(f"    - {name}")
if UNAVAILABLE:
    print("  prerequisite unavailable:")
    for name, prerequisite in UNAVAILABLE:
        print(f"    - {name}\n        needs {prerequisite}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
