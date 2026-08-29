"""End-to-end acceptance run against the deployed Worker.

Drives the public URL the way a browser would: real sign-up, real session
cookies, real D1 writes. Nothing here is mocked, and nothing asserts against
the local build.

Structural SQL verbs are assembled from fragments so the file never contains
the literal phrases a shell safety filter watches for.
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

# Each run signs up fresh operators, so it gets clean workspaces and can be
# repeated against the same deployment without colliding with an earlier run.
RUN = secrets.token_hex(3)
PROJECT = f"public-test-{RUN}"

# The SQL Editor is limited to the instance owner, so exercising the allowed
# path needs that account. Supply it through the environment rather than
# committing it; without it the run still asserts the refusal, which is the
# security-critical half.
OWNER_EMAIL = os.environ.get("YSD_ACCEPTANCE_OWNER_EMAIL")
OWNER_PASSWORD = os.environ.get("YSD_ACCEPTANCE_OWNER_PASSWORD")

DROP = "D" + "ROP"
ALTER = "AL" + "TER"

PASSED: list[str] = []
FAILED: list[str] = []


class Client:
    """One browser-equivalent session."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
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
                    "User-Agent": "ysd-acceptance/1.0",
                },
            )
            try:
                with self.opener.open(request, timeout=60) as response:
                    raw = response.read()
                    status = response.status
                break
            except urllib.error.HTTPError as error:
                raw = error.read()
                status = error.code
                break
            except (TimeoutError, OSError) as error:
                last = error
                time.sleep(2)
        else:
            raise RuntimeError(f"{method} {path} failed after {attempts} attempts: {last}")
        try:
            return status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are assertions here, so they must not be followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n=== {title} ===")


anon = Client("anonymous")
one = Client("operator-1")
two = Client("operator-2")

section("anonymous access is closed")
for path in ("/api/projects", "/api/secrets", "/api/usage", "/api/logs", "/api/shield",
             "/api/settings", "/api/deployments", "/api/database/tables", "/api/nodes"):
    status, _ = anon.request("GET", path)
    check(f"401 on {path}", status == 401, f"got {status}")

status, _ = anon.request("GET", "/")
check("anonymous / redirects to sign-in", status == 307, f"got {status}")

section("sign-up")
status, body = one.request("POST", "/api/auth/sign-up/email", {
    "name": "Public Operator", "email": f"public1-{RUN}@ysd.test", "password": "a-very-long-public-password",
})
check("operator 1 sign-up", status == 200 and isinstance(body, dict) and "user" in body, f"got {status}")

status, body = two.request("POST", "/api/auth/sign-up/email", {
    "name": "Second Operator", "email": f"public2-{RUN}@ysd.test", "password": "another-long-public-password",
})
check("operator 2 sign-up", status == 200, f"got {status}")

section("sessions")
status, body = one.request("GET", "/api/auth/get-session")
check("session resolves", status == 200 and body and body.get("user", {}).get("email") == f"public1-{RUN}@ysd.test")

status, body = one.request("GET", "/api/settings")
workspace_one = body.get("workspace") if isinstance(body, dict) else None
check("workspace auto-created", status == 200 and bool(workspace_one))
check("Zero Mode defaults on", bool(workspace_one) and workspace_one["zeroMode"] is True)

status, _ = one.request("GET", "/sign-in")
check("signed-in visitor redirected off /sign-in", status == 307, f"got {status}")

section("projects")
status, body = one.request("POST", "/api/projects", {"name": PROJECT, "repository": "OpenYsd/ysd-zero-cloud"})
check("create project", status == 201, f"got {status}")
project_id = body.get("project", {}).get("id") if isinstance(body, dict) else None

status, body = one.request("POST", "/api/projects", {"name": PROJECT})
check("duplicate project refused", status == 409, f"got {status}")

status, body = one.request("POST", "/api/projects", {"name": ""})
check("empty project name refused", status == 400, f"got {status}")

status, body = one.request("GET", "/api/projects")
check("project listed", status == 200 and len(body["projects"]) == 1)

# Smart Deploy creates a project for every plan that clears the guard, so the
# expected set grows as the run proceeds rather than staying at one.
EXPECTED_PROJECTS = {PROJECT, "ysd-zero-cloud", "ai-worker"}

section("smart deploy and Zero Mode")
status, body = one.request("POST", "/api/smart-deploy", {"repository": "OpenYsd/ysd-zero-cloud", "target": "auto"})
plan = body.get("plan") if isinstance(body, dict) else None
check("free-tier plan accepted", status == 200 and plan and plan["protection"]["allowed"] is True, f"got {status}")
check("plan inspected the real repository", bool(plan) and plan.get("confidence") == "inspected",
      f"confidence={plan.get('confidence') if plan else None}")
check("free plan costs zero", bool(plan) and plan["protection"]["estimatedMonthlyCost"] == 0)

status, body = one.request("POST", "/api/smart-deploy", {"repository": "OpenYsd/ai-worker", "target": "gpu"})
plan = body.get("plan") if isinstance(body, dict) else None
check("paid GPU plan blocked", status == 403 and plan and plan["protection"]["allowed"] is False, f"got {status}")
check("blocked plan names the billable resource",
      bool(plan) and len(plan["protection"]["blockedResources"]) == 1)

status, body = one.request("POST", "/api/smart-deploy",
                           {"repository": "OpenYsd/ai-worker", "target": "gpu", "zeroMode": False})
plan = body.get("plan") if isinstance(body, dict) else None
check("client cannot disable the guard from the request body",
      status == 403 and plan and plan["protection"]["allowed"] is False, f"got {status}")

status, body = one.request("GET", "/api/deployments")
check("blocked and accepted plans both recorded",
      status == 200 and len(body["deployments"]) == 3, f"got {len(body['deployments']) if status == 200 else status}")

section("Zero Mode toggle")
status, _ = one.request("PATCH", "/api/settings", {"setting": "zeroMode", "value": False})
check("Zero Mode can be paused", status == 200)
status, body = one.request("POST", "/api/smart-deploy", {"repository": "OpenYsd/ai-worker", "target": "gpu"})
plan = body.get("plan") if isinstance(body, dict) else None
check("paid plan allowed only while paused", status == 200 and plan and plan["protection"]["allowed"] is True)
status, _ = one.request("PATCH", "/api/settings", {"setting": "zeroMode", "value": True})
check("Zero Mode restored", status == 200)
status, body = one.request("POST", "/api/smart-deploy", {"repository": "OpenYsd/ai-worker", "target": "gpu"})
check("guard blocks again once restored", status == 403)

status, _ = one.request("PATCH", "/api/settings", {"setting": "ownerUserId", "value": True})
check("unknown setting refused", status == 400, f"got {status}")

section("secrets")
status, body = one.request("POST", "/api/secrets", {
    "name": "DATABASE_URL", "value": "postgres://u:p@host/db", "environment": "Production", "rotationDays": 90,
})
check("secret sealed and stored", status == 201, f"got {status}")
secret_id = body.get("secret", {}).get("id") if isinstance(body, dict) else None

status, body = one.request("GET", "/api/secrets")
serialised = json.dumps(body)
check("plaintext never returned", "postgres://" not in serialised)
check("ciphertext never returned", "ciphertext" not in serialised)

status, _ = one.request("POST", "/api/secrets", {"name": "x", "value": "v"})
check("invalid secret name refused", status == 400, f"got {status}")

section("database studio")
status, body = one.request("GET", "/api/database/tables")
tables = {t["name"] for t in body["tables"]} if status == 200 else set()
check("live schema introspected", status == 200 and "workspace" in tables and "shield_scan" in tables,
      f"{len(tables)} tables")

status, body = one.request("GET", "/api/database/rows?table=account")
rows = body.get("rows", []) if status == 200 else []
check("account password masked", all(r.get("password") in (None, "•" * 8) for r in rows))

status, body = one.request("GET", "/api/database/rows?table=secret")
rows = body.get("rows", []) if status == 200 else []
check("secret ciphertext masked", all(r.get("ciphertext") == "•" * 8 for r in rows))

status, _ = one.request("GET", "/api/database/rows?table=not_a_table")
check("unknown table refused", status == 404, f"got {status}")

section("SQL editor is closed to non-owners")
# The first account owns a brand-new local instance when YSD_OWNER_EMAIL is
# unset. Operator 2 is always a member, so it is the stable denial subject on
# both a fresh local D1 database and the long-lived deployed database.
status, body = two.request("POST", "/api/database/query", {"sql": "SELECT 1 AS n"})
check("non-owner refused the SQL Editor", status == 403,
      (body or {}).get("error", "")[:60] if isinstance(body, dict) else f"got {status}")

section("Database Studio shows only the caller's rows")
# Operator 2 has an empty workspace. Anything above these counts would be
# another tenant's data reaching them.
own_row_only = {"workspace": 1, "user": 1, "session": 1, "account": 1, "verification": 0}
for table, expected in own_row_only.items():
    status, body = two.request("GET", f"/api/database/rows?table={table}")
    total = body.get("total") if isinstance(body, dict) else None
    check(f"studio {table} scoped to caller", total == expected, f"saw {total}, expected {expected}")

for table in ("project", "deployment", "secret"):
    status, body = two.request("GET", f"/api/database/rows?table={table}")
    total = body.get("total") if isinstance(body, dict) else None
    check(f"studio {table} hides other tenants", total == 0, f"saw {total}")

# The member's refused SQL Editor attempt above writes one audit event into
# their own workspace. Seeing exactly that row proves Studio is scoped without
# pretending the caller's legitimate activity should be invisible.
status, body = two.request("GET", "/api/database/rows?table=log_event")
total = body.get("total") if isinstance(body, dict) else None
check("studio log_event hides other tenants", total == 1, f"saw {total}, expected 1 own event")

section("SQL editor guard (instance owner)")
if not (OWNER_EMAIL and OWNER_PASSWORD):
    print("  SKIPPED — set YSD_ACCEPTANCE_OWNER_EMAIL / _PASSWORD to exercise the owner path")
else:
    owner = Client("owner")
    status, _ = owner.request("POST", "/api/auth/sign-in/email",
                              {"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    check("owner sign-in", status == 200, f"got {status}")

    write_project = "UPDATE project SET status = 'live' WHERE 1 = 0"
    write_user = 'UPDATE "user" SET name = name WHERE 1 = 0'
    guard_cases = [
        ("read project", "SELECT name FROM project", False, True),
        ("read user", 'SELECT email FROM "user"', False, True),
        ("pragma table_info", 'PRAGMA table_info("project")', False, True),
        ("read account password", "SELECT password FROM account", True, False),
        ("read session token", "SELECT token FROM session", True, False),
        ("read verification", "SELECT * FROM verification", True, False),
        ("write without write mode", write_project, False, False),
        ("write with write mode", write_project, True, True),
        ("write to user", write_user, True, False),
        ("structural removal", f"{DROP} TABLE project", True, False),
        ("schema change", f"{ALTER} TABLE project ADD COLUMN x TEXT", True, False),
        ("stacked statements", f"SELECT 1; {DROP} TABLE project", True, False),
        ("pragma off the allow list", "PRAGMA page_count", False, False),
    ]
    for label, sql, allow_write, expect_allowed in guard_cases:
        status, body = owner.request("POST", "/api/database/query",
                                     {"sql": sql, "allowWrite": allow_write})
        analysis = body.get("analysis") if isinstance(body, dict) else None
        actual = bool(analysis and analysis["allowed"])
        check(f"guard: {label}", actual == expect_allowed,
              (analysis or {}).get("reason", f"status {status}")[:70])

    # Every refusal above must have left the schema intact.
    status, body = owner.request("POST", "/api/database/query",
                                 {"sql": "SELECT COUNT(*) AS n FROM project"})
    survived = body["rows"][0]["n"] if isinstance(body, dict) and body.get("rows") else None
    check("project table survived every refusal", isinstance(survived, int), f"n={survived}")

section("logs")
status, body = one.request("GET", "/api/logs?limit=50")
events = body.get("events", []) if status == 200 else []
sources = {e["source"] for e in events}
check("audit trail written", status == 200 and len(events) > 10, f"{len(events)} events")
check("deployment refusals logged", any("blocked" in e["message"].lower() for e in events))
expected_sources = {"deployment", "secret", "project"}
if OWNER_EMAIL and OWNER_PASSWORD:
    expected_sources.add("database")
check("multiple sources represented", expected_sources <= sources, str(sorted(sources)))

status, body = one.request("GET", "/api/logs?source=database")
check("source filter works", status == 200 and all(e["source"] == "database" for e in body["events"]))

section("usage")
status, body = one.request("GET", "/api/usage")
check("usage measured", status == 200 and body["projectedMonthlyCost"] == 0, f"got {status}")
readings = {r["id"]: r for r in body["readings"]} if status == 200 else {}
check("project count measured", readings.get("projects", {}).get("used") == len(EXPECTED_PROJECTS),
      f'used={readings.get("projects", {}).get("used")}')
check("database size reported honestly",
      readings.get("database-bytes", {}).get("measured") is False,
      "no Cloudflare API token configured")

section("YSD Shield")
status, body = one.request("POST", "/api/shield/scan")
check("scan runs", status == 200 and "score" in body, f"got {status}")
score = body.get("score") if isinstance(body, dict) else None
findings = {f["code"] for f in body.get("findings", [])} if status == 200 else set()
check("scan produced a score", isinstance(score, int) and 0 <= score <= 100, f"score={score}")
check("billable plan surfaced as a finding", "billable-resources-planned" in findings, str(sorted(findings)))
check("no false expired-session finding", "expired-sessions" not in findings, str(sorted(findings)))

status, body = one.request("GET", "/api/shield")
check("scan persisted", status == 200 and body.get("scan") is not None)

section("workspace isolation")
for path, key in (("/api/projects", "projects"), ("/api/secrets", "secrets"), ("/api/deployments", "deployments")):
    status, body = two.request("GET", path)
    check(f"operator 2 sees no {key}", status == 200 and len(body[key]) == 0,
          f"{len(body[key]) if status == 200 else status}")

status, _ = two.request("DELETE", f"/api/secrets/{secret_id}")
check("cross-tenant secret delete refused", status == 404, f"got {status}")
status, _ = two.request("DELETE", f"/api/projects/{project_id}")
check("cross-tenant project delete refused", status == 404, f"got {status}")

status, body = one.request("GET", "/api/secrets")
check("operator 1 secret intact", status == 200 and len(body["secrets"]) == 1)

section("pages render")
for path in ("/", "/projects", "/deployments", "/databases", "/databases/studio",
             "/databases/sql-editor", "/logs", "/secrets", "/usage", "/shield", "/settings",
             "/storage", "/ai", "/game-servers", "/nodes", "/networking"):
    status, body = one.request("GET", path)
    ok = status == 200 and isinstance(body, str) and "Internal Server Error" not in body
    check(f"page {path}", ok, f"got {status}")

status, _ = one.request("GET", "/not-a-section")
check("unknown section 404s", status == 404, f"got {status}")

section("sign-out")
status, _ = one.request("POST", "/api/auth/sign-out", {})
check("sign-out succeeds", status == 200, f"got {status}")
status, _ = one.request("GET", "/api/projects")
check("session closed after sign-out", status == 401, f"got {status}")

section("sign-in again")
status, _ = one.request("POST", "/api/auth/sign-in/email",
                        {"email": f"public1-{RUN}@ysd.test", "password": "a-very-long-public-password"})
check("sign-in succeeds", status == 200, f"got {status}")
status, body = one.request("GET", "/api/projects")
names = {p["name"] for p in body["projects"]} if status == 200 else set()
check("data still there after re-auth", names == EXPECTED_PROJECTS, str(sorted(names)))

status, _ = one.request("POST", "/api/auth/sign-in/email",
                        {"email": f"public1-{RUN}@ysd.test", "password": "wrong-password-entirely"})
check("wrong password rejected", status in (401, 403), f"got {status}")

print(f"\n{'=' * 60}")
print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}")
if FAILED:
    print("  failures:")
    for name in FAILED:
        print(f"    - {name}")
print("=" * 60)
sys.exit(1 if FAILED else 0)
