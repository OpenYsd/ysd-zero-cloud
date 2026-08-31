"""Read-only Phase 9 acceptance checks against the deployed Worker.

This suite never creates an account, bypasses Turnstile, changes Zero Mode, or
writes tenant data. Authenticated workflow mutations remain covered by the D1
integration suite and are deliberately not simulated with a forged session.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request


BASE = os.environ.get(
    "YSD_ACCEPTANCE_BASE", "https://ysd-zero-cloud.ysd-zero-cloud.workers.dev"
).rstrip("/")
PASSED: list[str] = []
FAILED: list[str] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect())


def request(method: str, path: str, body=None, origin: str | None = BASE):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": "ysd-workflow-acceptance/1.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if origin is not None:
        headers["Origin"] = origin
        headers["Referer"] = f"{origin}/"
    last_error: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(f"{BASE}{path}", data=data, method=method, headers=headers)
        try:
            with OPENER.open(req, timeout=30) as response:
                raw, status, response_headers = response.read(), response.status, dict(response.headers)
            break
        except urllib.error.HTTPError as error:
            raw, status, response_headers = error.read(), error.code, dict(error.headers)
            break
        except (TimeoutError, OSError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(2)
    else:
        raise RuntimeError(f"{method} {path} failed after 3 attempts: {last_error}")
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode("utf-8", "replace")
    return status, parsed, response_headers


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


print("\n=== authenticated APIs remain closed ===")
for path in (
    "/api/projects",
    "/api/deployments",
    "/api/nodes",
    "/api/ai",
    "/api/game-servers",
    "/api/shield",
    "/api/organizations",
    "/api/exposures",
    "/api/secrets",
    "/api/logs",
    "/api/usage",
    "/api/database/tables",
    "/api/workflows",
):
    status, _, _ = request("GET", path)
    check(f"401 on {path}", status == 401, f"got {status}")

workflow_id = "wf_" + "0" * 24
execution_id = "wfexec_" + "0" * 24
notification_id = "notif_" + "0" * 24
for method, path, body in (
    ("PATCH", f"/api/workflows/{workflow_id}", {"operation": "pause"}),
    ("POST", f"/api/workflows/executions/{execution_id}", {"operation": "cancel"}),
    ("PATCH", f"/api/notifications/{notification_id}", {"read": True}),
):
    status, _, _ = request(method, path, body)
    check(f"401 on {method} {path}", status == 401, f"got {status}")

print("\n=== pages and workflow navigation ===")
for path in ("/", "/workflows"):
    status, _, headers = request("GET", path)
    location = headers.get("Location", headers.get("location", ""))
    check(f"{path} redirects to sign-in", status in (302, 303, 307, 308) and "/sign-in" in location, f"got {status} {location}")
for path in ("/sign-in", "/sign-up"):
    status, body, _ = request("GET", path)
    check(f"{path} renders", status == 200 and isinstance(body, str) and "YSD" in body, f"got {status}")

print("\n=== no client event-ingestion or arbitrary action surface ===")
for path in ("/api/workflow-events", "/api/workflows/events", "/api/events/workflows"):
    status, _, _ = request("POST", path, {"type": "node.revoked", "trusted": True})
    check(f"no raw endpoint at {path}", status in (404, 405), f"got {status}")
for label, body in (
    ("arbitrary URL", {"url": "http://127.0.0.1/latest/meta-data"}),
    ("shell", {"command": "echo blocked"}),
    ("expression", {"condition": "globalThis.constructor"}),
    ("Zero Mode bypass", {"zeroMode": False, "provider": "paid"}),
):
    status, _, _ = request("POST", "/api/workflows", body)
    check(f"unauthenticated {label} payload is rejected", status == 401, f"got {status}")

print("\n=== response hardening ===")
status, html, headers = request("GET", "/sign-in")
lower = {key.lower(): value for key, value in headers.items()}
for name in (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
):
    check(f"serves {name}", status == 200 and name in lower)
csp = lower.get("content-security-policy", "")
check("CSP forbids framing", "frame-ancestors 'none'" in csp)
check("CSP forbids plugins and base tampering", "object-src 'none'" in csp and "base-uri 'none'" in csp)

auth_body = {"email": "nobody@ysd.test", "password": "not-a-real-password"}
for label, origin in (("missing Origin", None), ("foreign Origin", "https://evil.example")):
    status, _, _ = request("POST", "/api/auth/sign-in/email", auth_body, origin=origin)
    check(f"{label} is refused", status == 403, f"got {status}")

status, session, _ = request("GET", "/api/auth/get-session")
check("anonymous session is empty", status == 200 and session is None, f"got {status}")
serialised = html if isinstance(html, str) else json.dumps(html)
check("public HTML contains no secret material", all(token not in serialised for token in ("BETTER_AUTH_SECRET", "TURNSTILE_SECRET_KEY", "GITHUB_CLIENT_SECRET")))

print(f"\nTOTAL: {len(PASSED) + len(FAILED)}  PASS: {len(PASSED)}  FAIL: {len(FAILED)}")
if FAILED:
    print("FAILED CHECKS:")
    for name in FAILED:
        print(f"- {name}")
    sys.exit(1)
