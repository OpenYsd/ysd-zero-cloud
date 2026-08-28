"""Production checks for the security hardening.

Exercises the controls that guard the unauthenticated surface — rate limiting,
brute-force lockout, role gating, and admin management — against the deployed
Worker. Every account it creates is on the reserved @ysd.test domain and is
purged afterwards by the caller.
"""

import http.cookiejar
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("YSD_ACCEPTANCE_BASE", "https://ysd-zero-cloud.ysd-zero-cloud.workers.dev")
RUN = secrets.token_hex(3)

PASSED: list[str] = []
FAILED: list[str] = []


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def request(self, method: str, path: str, body=None, attempts: int = 3):
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        # A read timeout against the edge is transient and would otherwise abort
        # the whole run; an HTTP status is a real answer and is never retried.
        for _ in range(attempts):
            request = urllib.request.Request(
                f"{BASE}{path}",
                data=data,
                method=method,
                headers={
                    "Content-Type": "application/json",
                    "Origin": BASE,
                    "Referer": f"{BASE}/",
                    "User-Agent": "ysd-security/1.0",
                },
            )
            try:
                with self.opener.open(request, timeout=60) as response:
                    raw, status, headers = response.read(), response.status, dict(response.headers)
                break
            except urllib.error.HTTPError as error:
                raw, status, headers = error.read(), error.code, dict(error.headers)
                break
            except (TimeoutError, OSError) as error:
                last = error
                time.sleep(2)
        else:
            raise RuntimeError(f"{method} {path} failed after {attempts} attempts: {last}")
        try:
            return status, (json.loads(raw) if raw else None), headers
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace"), headers


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def signup(client: Client, tag: str):
    return client.request(
        "POST",
        "/api/auth/sign-up/email",
        {
            "name": f"Sec {tag}",
            "email": f"sec-{tag}-{RUN}@ysd.test",
            "password": "a-long-enough-security-password",
        },
    )


section("CSRF origin validation")
req = urllib.request.Request(
    f"{BASE}/api/auth/sign-in/email",
    data=json.dumps(
        {"email": f"cookie-{RUN}@ysd.test", "password": "a-long-enough-cookie-password"}
    ).encode(),
    method="POST",
    headers={"Content-Type": "application/json", "User-Agent": "ysd-security/1.0"},
)
try:
    with urllib.request.build_opener().open(req, timeout=60) as r:
        status = r.status
except urllib.error.HTTPError as e:
    status = e.code
check("a request with no Origin is refused", status == 403, f"got {status}")

hostile = urllib.request.Request(
    f"{BASE}/api/auth/sign-in/email",
    data=json.dumps({"email": f"x-{RUN}@ysd.test", "password": "y"}).encode(),
    method="POST",
    headers={
        "Content-Type": "application/json",
        "Origin": "https://evil.example.com",
        "User-Agent": "ysd-security/1.0",
    },
)
try:
    with urllib.request.build_opener().open(hostile, timeout=60) as r:
        hostile_status = r.status
except urllib.error.HTTPError as e:
    hostile_status = e.code
check("a request from a foreign origin is refused", hostile_status == 403, f"got {hostile_status}")

section("new accounts are members, not admins")
alice = Client()
status, body, alice_signup_headers = signup(alice, "alice")
check("sign-up succeeds", status == 200, f"got {status}")

status, body, _ = alice.request("GET", "/api/admin/users")
check("a fresh account cannot read the admin list", status == 403, f"got {status}")

status, body, _ = alice.request("PATCH", "/api/admin/users", {"userId": "anyone", "role": "owner"})
check("a fresh account cannot grant itself a role", status == 403, f"got {status}")

status, body, _ = alice.request("POST", "/api/database/query", {"sql": "SELECT 1 AS n"})
check("a fresh account cannot use the SQL Editor", status == 403, f"got {status}")

section("admin surface is hidden from members")
status, body, _ = alice.request("GET", "/admin")
check("member gets 404 on the admin page", status == 404, f"got {status}")

section("brute-force lockout targets the account")
# Runs before the rate-limit section on purpose: the account threshold (5) is
# below the per-address budget (10), so the lockout is only observable while
# that address still has budget left.
locked = None
bob = Client()
status, _, _ = signup(bob, "bob")
check("second account created", status == 200, f"got {status}")
bob_email = f"sec-bob-{RUN}@ysd.test"
for i in range(8):
    attacker = Client()
    status, body, _ = attacker.request(
        "POST", "/api/auth/sign-in/email", {"email": bob_email, "password": "wrong-password-here"}
    )
    if isinstance(body, dict) and body.get("code") == "ACCOUNT_LOCKED":
        locked = i + 1
        break
check(
    "the account is locked after repeated failures",
    locked is not None,
    f"locked after {locked} attempts" if locked else "never locked",
)

section("the real password is refused while locked")
if locked:
    probe = Client()
    status, body, _ = probe.request(
        "POST",
        "/api/auth/sign-in/email",
        {"email": bob_email, "password": "a-long-enough-security-password"},
    )
    code = body.get("code") if isinstance(body, dict) else None
    check(
        "a locked account is refused even with correct credentials",
        status in (429, 403) or code == "ACCOUNT_LOCKED",
        f"status {status} code {code}",
    )
else:
    print("  SKIPPED — lockout did not engage")

section("rate limiting on sign-in")
# Both this section and the lockout above spend the same per-address budget, so
# the position of the first 429 depends on what ran before it. What matters is
# that a real budget exists, that it is generous enough for genuine retries, and
# that exceeding it is refused.
statuses = []
advertised = None
for _ in range(14):
    probe = Client()
    status, _, headers = probe.request(
        "POST",
        "/api/auth/sign-in/email",
        {"email": f"nobody-{RUN}@ysd.test", "password": "definitely-the-wrong-password"},
    )
    statuses.append(status)
    lowered = {k.lower(): v for k, v in headers.items()}
    if advertised is None and "ratelimit-limit" in lowered:
        advertised = int(lowered["ratelimit-limit"])

check(
    "repeated sign-in attempts are refused with 429",
    429 in statuses,
    f"statuses: {sorted(set(statuses))}",
)
check(
    "the advertised budget leaves room for genuine retries",
    advertised is not None and advertised >= 5,
    f"RateLimit-Limit={advertised}",
)

section("rate-limit headers are advertised")
probe = Client()
status, _, headers = probe.request(
    "POST",
    "/api/auth/sign-in/email",
    {"email": f"nobody2-{RUN}@ysd.test", "password": "wrong-password"},
)
lowered = {k.lower() for k in headers}
check("responses carry RateLimit headers", "ratelimit-limit" in lowered, str(sorted(lowered))[:120])

section("security response headers")
# Proven from outside the Worker, which is the only place delivery can be
# observed reliably: a Worker fetching its own origin is not guaranteed to be
# routed back through the middleware that sets these.
probe = Client()
_, _, headers = probe.request("GET", "/sign-in")
lowered = {k.lower() for k in headers}
for name in (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
):
    check(f"serves {name}", name in lowered)

csp = {k.lower(): v for k, v in headers.items()}.get("content-security-policy", "")
check("CSP forbids framing", "frame-ancestors 'none'" in csp, csp[:60])
check(
    "CSP forbids plugins and base tampering",
    "object-src 'none'" in csp and "base-uri 'none'" in csp,
)

section("session cookie flags")
# Reuses the sign-up already performed above rather than spending another slot
# of the per-address sign-up budget.
cookie = alice_signup_headers.get("Set-Cookie") or alice_signup_headers.get("set-cookie") or ""
check("session cookie is HttpOnly", "httponly" in cookie.lower(), cookie[:60])
check("session cookie is Secure", "secure" in cookie.lower())
check("session cookie is SameSite=Lax", "samesite=lax" in cookie.lower())

section("session revocation")
# Reuses alice, who is already signed in, for the same budget reason.
revoker = alice
status, _, _ = revoker.request("GET", "/api/projects")
check("the session works before revocation", status == 200, f"got {status}")
status, _, _ = revoker.request("POST", "/api/auth/revoke-sessions", {})
check("revoke-sessions is available", status == 200, f"got {status}")
status, _, _ = revoker.request("GET", "/api/projects")
check("every session is dead after revoke-all", status == 401, f"got {status}")

print(f"\n{'=' * 60}")
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
for name in FAILED:
    print(f"    - {name}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
