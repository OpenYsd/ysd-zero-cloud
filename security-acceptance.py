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

    def request(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
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
            with self.opener.open(request, timeout=90) as response:
                raw, status, headers = response.read(), response.status, dict(response.headers)
        except urllib.error.HTTPError as error:
            raw, status, headers = error.read(), error.code, dict(error.headers)
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


section("new accounts are members, not admins")
alice = Client()
status, body, _ = signup(alice, "alice")
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
    "POST", "/api/auth/sign-up/email", {"email": f"hdr-{RUN}@ysd.test", "password": "x"}
)
lowered = {k.lower() for k in headers}
check("responses carry RateLimit headers", "ratelimit-limit" in lowered, str(sorted(lowered))[:120])

print(f"\n{'=' * 60}")
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
for name in FAILED:
    print(f"    - {name}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
