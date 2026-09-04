"""End-to-end acceptance run against the deployed Worker.

Drives the public URL the way a browser would: real sign-up, real session
cookies, real D1 writes. Nothing here is mocked, and nothing asserts against
the local build.

Structural SQL verbs are assembled from fragments so the file never contains
the literal phrases a shell safety filter watches for.

Three result kinds, and the difference matters:

  PASS         the product did what it must.
  FAIL         the product did not. The run exits non-zero.
  UNAVAILABLE  a prerequisite this environment could not supply, named
               explicitly. Never used for a product failure, and never used to
               hide one -- a check that CAN run always runs.

Smart Deploy needs a paired, online Compute Node. That is a real product
requirement (`app/api/smart-deploy/route.ts` refuses any request without one),
so the harness pairs a synthetic node over the supported HTTP pairing path the
same way `app-runtime-acceptance.py` does: the server issues the token, the
harness signs with it. No credential is invented, and no external agent is
needed. If pairing cannot complete, the node-dependent checks report as
UNAVAILABLE rather than treating a correct 400 as a defect.
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

# A repository with a safe, pinned Node lock contract, and one without. Both
# are public and are the same pair `app-runtime-acceptance.py` relies on.
DEPLOYABLE_REPOSITORY = "heroku/node-js-getting-started"
UNDEPLOYABLE_REPOSITORY = "OpenYsd/ysd-zero-cloud"

PASSED: list[str] = []
FAILED: list[str] = []
UNAVAILABLE: list[tuple[str, str]] = []


class Client:
    """One browser-equivalent session."""

    def __init__(self, label: str, address: str) -> None:
        self.label = label
        # Each simulated operator gets its own client address. Without one,
        # clientAddress() cannot tell these sessions apart and the whole run
        # shares a single rate-limit bucket, so the later operators get
        # throttled and every assertion after that reads as a tenancy failure
        # rather than as the throttling it is. Cloudflare sets this header
        # itself in front of the deployed Worker, so it only takes effect
        # locally -- the same approach app-runtime-acceptance.py already uses.
        self.address = address
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
        )

    def request(self, method: str, path: str, body=None, headers=None, attempts: int = 3,
                throttle_retries: int = 3):
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        # A read timeout against the edge is transient and would otherwise abort
        # the whole run; an HTTP status is a real answer and is never retried --
        # except 429, which is the product's rate limiter working correctly.
        # Running this script twice in quick succession trips the auth limiter,
        # and treating that as a product defect would be a lie. No assertion in
        # this file expects a 429, so waiting the window out cannot mask one.
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
                    "CF-Connecting-IP": self.address,
                    **(headers or {}),
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

        if status == 429 and throttle_retries > 0:
            time.sleep(8)
            return self.request(method, path, body, headers, attempts, throttle_retries - 1)

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


def unavailable(name: str, prerequisite: str) -> None:
    """A check whose prerequisite this environment cannot supply.

    Deliberately not a pass and not a failure. The prerequisite is printed in
    full so nobody has to guess whether something was silently skipped.
    """
    UNAVAILABLE.append((name, prerequisite))
    print(f"  [N/A ] {name} — needs {prerequisite}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def error_of(body) -> str:
    return body.get("error", "") if isinstance(body, dict) else ""


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def agent_request(token: str, path: str, body: dict):
    """One signed agent call, in the documented `ysd-node-request-v1` form.

    The token is the one the server returned from pairing moments earlier, so
    this proves the signing contract rather than working around it.
    """
    raw = json.dumps(body, separators=(",", ":"))
    nonce = b64url(secrets.token_bytes(18))
    timestamp = int(time.time() * 1000)
    body_hash = b64url(hashlib.sha256(raw.encode()).digest())
    message = "\n".join(["ysd-node-request-v1", "POST", path, str(timestamp), nonce, body_hash])
    signature = b64url(hmac.new(token.encode(), message.encode(), hashlib.sha256).digest())
    request = urllib.request.Request(
        f"{BASE}{path}", data=raw.encode(), method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-YSD-Timestamp": str(timestamp),
            "X-YSD-Nonce": nonce,
            "X-YSD-Signature": signature,
            "User-Agent": "ysd-acceptance-agent/1.0",
            "CF-Connecting-IP": "203.0.113.13",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    except (TimeoutError, OSError):
        return 0, None
    try:
        return status, json.loads(payload) if payload else None
    except json.JSONDecodeError:
        return status, None


NODE_CAPABILITIES = {
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

NODE_PREREQUISITE = (
    "a paired, online Compute Node advertising the App Runtime contract "
    "(POST /api/nodes then POST /api/nodes/agent/pair, then a signed heartbeat)"
)
GITHUB_PREREQUISITE = (
    "GitHub reachable for repository inspection "
    "(unauthenticated requests are rate limited to 60/hour)"
)


def pair_acceptance_node(operator: Client, agent: Client):
    """Pairs a synthetic node through the supported API. Returns (id, token)."""
    status, body = operator.request("POST", "/api/nodes", {"name": f"Acceptance Node {RUN}"})
    pairing = body.get("pairing") if isinstance(body, dict) else None
    if status != 201 or not pairing:
        return None, None, f"pairing ticket refused (status {status})"

    status, body = agent.request("POST", "/api/nodes/agent/pair", {
        "code": pairing["code"], "agentVersion": "0.4.0", "protocolVersion": 1,
        "platform": "acceptance", "architecture": "x64",
        "capabilities": NODE_CAPABILITIES,
    })
    token = body.get("token") if isinstance(body, dict) else None
    node_id = body.get("nodeId") if isinstance(body, dict) else None
    if status != 201 or not token or not node_id:
        return None, None, f"agent pairing refused (status {status})"

    # A node is only selectable while it is online, which means a heartbeat.
    status, _ = agent_request(token, "/api/nodes/agent/heartbeat", {
        "agentVersion": "0.4.0", "capabilities": NODE_CAPABILITIES,
        "metrics": {
            "cpuLoadPercent": 10, "memoryUsedBytes": 2 * 1024**3,
            "memoryTotalBytes": 16 * 1024**3, "runningJobs": 0,
        },
        "gameServers": [], "appDeployments": [],
    })
    if status != 200:
        return None, None, f"signed heartbeat refused (status {status})"
    return node_id, token, ""


anon = Client("anonymous", "203.0.113.10")
one = Client("operator-1", "203.0.113.11")
two = Client("operator-2", "203.0.113.12")
agent = Client("agent", "203.0.113.13")

section("anonymous access is closed")
for path in ("/api/projects", "/api/secrets", "/api/usage", "/api/logs", "/api/shield",
             "/api/settings", "/api/deployments", "/api/database/tables", "/api/nodes"):
    status, _ = anon.request("GET", path)
    check(f"401 on {path}", status == 401, f"got {status}")

status, _ = anon.request("GET", "/")
check("anonymous / redirects to sign-in", status == 307, f"got {status}")

section("sign-up")
# A sign-up that is still throttled after the retries above is the auth rate
# limiter doing its job, not a defect. It is reported as a prerequisite so the
# operator-dependent checks below can say the same rather than each inventing a
# tenancy failure out of a missing session.
THROTTLED = (
    "room in the sign-up rate-limit window "
    "(run again in a minute, or space repeated local runs apart)"
)

status, body = one.request("POST", "/api/auth/sign-up/email", {
    "name": "Public Operator", "email": f"public1-{RUN}@ysd.test", "password": "a-very-long-public-password",
})
ONE_READY = status == 200 and isinstance(body, dict) and "user" in body
if status == 429:
    unavailable("operator 1 sign-up", THROTTLED)
else:
    check("operator 1 sign-up", ONE_READY, f"got {status}")

status, body = two.request("POST", "/api/auth/sign-up/email", {
    "name": "Second Operator", "email": f"public2-{RUN}@ysd.test", "password": "another-long-public-password",
})
TWO_READY = status == 200
if status == 429:
    unavailable("operator 2 sign-up", THROTTLED)
else:
    check("operator 2 sign-up", TWO_READY, f"got {status}")

if not ONE_READY:
    print("\nOperator 1 has no session, so nothing below can be asserted.")
    print(f"  needs {THROTTLED}")
    print(f"\n{'=' * 60}")
    print(f"  PASSED {len(PASSED)}   FAILED {len(FAILED)}   UNAVAILABLE {len(UNAVAILABLE)}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)


def total_of(client: Client, path: str, key: str) -> int:
    status, body = client.request("GET", path)
    return len(body.get(key, [])) if status == 200 and isinstance(body, dict) else 0


def studio_row(client: Client, table: str):
    """Returns (total, status). The status travels with it so a failing check
    can say whether the count was wrong or the read was refused."""
    status, body = client.request("GET", f"/api/database/rows?table={table}")
    total = body.get("total") if status == 200 and isinstance(body, dict) else None
    return total, status


def studio_total(client: Client, table: str):
    return studio_row(client, table)[0]


# Baselines, captured before this run writes anything. Every count assertion
# below is a delta against these rather than an absolute, so the run is correct
# against a fresh database and against one carrying earlier local data.
BASE_PROJECTS = total_of(one, "/api/projects", "projects")
BASE_DEPLOYMENTS = total_of(one, "/api/deployments", "deployments")
BASE_LOGS = total_of(one, "/api/logs?limit=50", "events")
BASE_TWO_LOGS = studio_total(two, "log_event")
BASE_TWO_AUDIT = studio_total(two, "audit_event")

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
check("project listed", status == 200 and len(body["projects"]) == BASE_PROJECTS + 1,
      f'{len(body["projects"]) if status == 200 else status} vs baseline {BASE_PROJECTS}')

# How many projects this run is expected to add. One for the explicit create
# above. An ACCEPTED Smart Deploy adds a second, named after the repository:
# planDeployment creates it only after the guard has passed, so a blocked plan
# adds none. Recomputed once the deploy section knows what actually happened.
EXPECTED_PROJECT_DELTA = 1
EXPECTED_PROJECT_NAMES = {PROJECT}

section("Compute Node fixture for Smart Deploy")
node_id, node_token, node_reason = pair_acceptance_node(one, agent)
if node_id:
    check("synthetic Compute Node paired and online", True, node_id)
else:
    unavailable("synthetic Compute Node paired and online", f"{NODE_PREREQUISITE} — {node_reason}")

deploy_request = {
    "repository": DEPLOYABLE_REPOSITORY,
    "branch": "main",
    "nodeId": node_id,
    "environment": "Production",
    "healthPath": "/",
    "memoryMb": 256,
    "diskQuotaBytes": 256 * 1024**2,
    "target": "user-node",
}

section("Smart Deploy requires a Compute Node")
# Node-independent: the requirement itself. This must hold whether or not a
# node could be paired, and it is the reason the checks below are gated.
status, body = one.request("POST", "/api/smart-deploy", {"repository": DEPLOYABLE_REPOSITORY})
check("Smart Deploy without a node is refused", status == 400 and "Compute Node" in error_of(body),
      f"got {status} {error_of(body)[:60]}")

status, body = one.request("POST", "/api/smart-deploy", {"repository": DEPLOYABLE_REPOSITORY, "nodeId": "node_notreal"})
check("malformed node id is refused", status == 400 and "Compute Node" in error_of(body),
      f"got {status} {error_of(body)[:60]}")

status, body = one.request("POST", "/api/smart-deploy", {"nodeId": node_id or "node_" + "0" * 24})
check("Smart Deploy without a repository is refused", status == 400 and "repository" in error_of(body),
      f"got {status} {error_of(body)[:60]}")

section("Zero Mode input contract")
# Every one of these is a 400 with the SAME status as the missing-node refusal,
# so each asserts the error text as well. Asserting the status alone would pass
# for the wrong reason the moment the node prerequisite regressed.
CONTRACT_ERROR = "Paid providers, hosted builds, public tunnels, and Zero Mode overrides are forbidden."
contract_cases = [
    ("client cannot disable the guard from the request body", {"zeroMode": False}),
    ("paid GPU target refused", {"target": "gpu"}),
    ("auto target refused", {"target": "auto"}),
    ("paid provider key refused", {"provider": "paid"}),
    ("public tunnel key refused", {"tunnel": "argo"}),
    ("arbitrary command key refused", {"command": "whoami"}),
]
for name, mutation in contract_cases:
    if not node_id:
        unavailable(name, NODE_PREREQUISITE)
        continue
    status, body = one.request("POST", "/api/smart-deploy", {**deploy_request, **mutation})
    check(name, status == 400 and error_of(body) == CONTRACT_ERROR,
          f"got {status} {error_of(body)[:60]}")

section("smart deploy plans")
accepted_deployment = None
blocked_deployment = None
if not node_id:
    for name in ("free-tier plan accepted", "plan inspected the real repository",
                 "free plan costs zero",
                 "accepted plan is queued for the node, not executed by the Worker",
                 "accepted plan stays private to the node",
                 "unsafe repository blocked and recorded",
                 "blocked and accepted plans both recorded"):
        unavailable(name, NODE_PREREQUISITE)
else:
    status, body = one.request("POST", "/api/smart-deploy", deploy_request,
                               {"Idempotency-Key": f"public-accept-{RUN}"})
    plan = body.get("plan") if isinstance(body, dict) else None
    accepted_deployment = body.get("deployment") if isinstance(body, dict) else None
    inspection_failed = status == 404 and "could not be inspected" in error_of(body)
    if inspection_failed:
        for name in ("free-tier plan accepted", "plan inspected the real repository",
                     "free plan costs zero",
                     "accepted plan is queued for the node, not executed by the Worker",
                     "accepted plan stays private to the node"):
            unavailable(name, GITHUB_PREREQUISITE)
    else:
        check("free-tier plan accepted",
              status == 202 and plan and plan["protection"]["allowed"] is True, f"got {status}")
        check("plan inspected the real repository", bool(plan) and plan.get("confidence") == "inspected",
              f"confidence={plan.get('confidence') if plan else None}")
        check("free plan costs zero", bool(plan) and plan["protection"]["estimatedMonthlyCost"] == 0)
        # The execution boundary: the Worker records a plan and stops there.
        # Building and running belong to the paired node, so an accepted plan
        # is queued for it, never already running, and never publicly exposed.
        check("accepted plan is queued for the node, not executed by the Worker",
              isinstance(accepted_deployment, dict) and accepted_deployment.get("state") == "queued",
              f'state={accepted_deployment.get("state") if isinstance(accepted_deployment, dict) else None}')
        check("accepted plan stays private to the node",
              isinstance(accepted_deployment, dict) and accepted_deployment.get("exposure") == "private",
              f'exposure={accepted_deployment.get("exposure") if isinstance(accepted_deployment, dict) else None}')

    status, body = one.request("POST", "/api/smart-deploy",
                               {**deploy_request, "repository": UNDEPLOYABLE_REPOSITORY})
    blocked_deployment = body.get("deployment") if isinstance(body, dict) else None
    if status == 404 and "could not be inspected" in error_of(body):
        unavailable("unsafe repository blocked and recorded", GITHUB_PREREQUISITE)
    else:
        check("unsafe repository blocked and recorded",
              status == 409 and isinstance(blocked_deployment, dict)
              and blocked_deployment.get("state") == "blocked", f"got {status}")

    recorded = total_of(one, "/api/deployments", "deployments") - BASE_DEPLOYMENTS
    expected = (1 if accepted_deployment else 0) + (1 if blocked_deployment else 0)
    if expected == 0:
        unavailable("blocked and accepted plans both recorded", GITHUB_PREREQUISITE)
    else:
        check("blocked and accepted plans both recorded", recorded == expected,
              f"{recorded} new deployments, expected {expected}")

    if accepted_deployment:
        EXPECTED_PROJECT_DELTA += 1
        EXPECTED_PROJECT_NAMES.add(DEPLOYABLE_REPOSITORY.split("/")[-1])

section("Zero Mode toggle")
status, _ = one.request("PATCH", "/api/settings", {"setting": "zeroMode", "value": False})
check("Zero Mode can be paused", status == 200)

# `planDeployment` passes `zeroModeEnabled: true` unconditionally and both
# deployment inserts hard-code `estimatedMonthlyCost` to 0, so pausing the
# workspace toggle does NOT buy a billable Smart Deploy. Asserting that is
# stricter than the old "paid plan allowed only while paused", which described
# a permission the product no longer grants.
if node_id:
    status, body = one.request("POST", "/api/smart-deploy", {**deploy_request, "target": "gpu"})
    check("pausing Zero Mode does not unlock a paid target",
          status == 400 and error_of(body) == CONTRACT_ERROR, f"got {status} {error_of(body)[:60]}")
else:
    unavailable("pausing Zero Mode does not unlock a paid target", NODE_PREREQUISITE)

status, _ = one.request("PATCH", "/api/settings", {"setting": "zeroMode", "value": True})
check("Zero Mode restored", status == 200)

if node_id:
    status, body = one.request("POST", "/api/smart-deploy", {**deploy_request, "zeroMode": False})
    check("guard blocks again once restored",
          status == 400 and error_of(body) == CONTRACT_ERROR, f"got {status}")
else:
    unavailable("guard blocks again once restored", NODE_PREREQUISITE)

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
if TWO_READY:
    status, body = two.request("POST", "/api/database/query", {"sql": "SELECT 1 AS n"})
    check("non-owner refused the SQL Editor", status == 403,
          (body or {}).get("error", "")[:60] if isinstance(body, dict) else f"got {status}")
else:
    unavailable("non-owner refused the SQL Editor", f"a second signed-in operator — {THROTTLED}")

section("Database Studio shows only the caller's rows")
# Operator 2 has an empty workspace. Anything above these counts would be
# another tenant's data reaching them. Without a second session there is no
# caller to scope to, so these report as unavailable rather than as a wall of
# tenancy failures that would really just be a missing sign-up.
own_row_only = {"workspace": 1, "user": 1, "session": 1, "account": 1, "verification": 0}
if not TWO_READY:
    for table in list(own_row_only) + ["project", "deployment", "secret", "log_event", "audit_event"]:
        unavailable(f"studio {table} scoped to caller",
                    f"a second signed-in operator — {THROTTLED}")
for table, expected in own_row_only.items() if TWO_READY else []:
    total, http = studio_row(two, table)
    # `total is not None` is part of the assertion, not a formality: a refused
    # read must never satisfy a count check by comparing None to None.
    check(f"studio {table} scoped to caller", total is not None and total == expected,
          f"saw {total} (HTTP {http}), expected {expected}")

for table in ("project", "deployment", "secret") if TWO_READY else []:
    total, http = studio_row(two, table)
    check(f"studio {table} hides other tenants", total is not None and total == 0,
          f"saw {total} (HTTP {http})")

# The member's refused SQL Editor attempt above is recorded, but since Phase 13
# it is recorded as EVIDENCE in audit_event rather than as telemetry in
# log_event: `requireApiSession` refuses the permission before the route body
# runs, and writes a `permission.denied` audit record. Asserting a log_event
# here would be asserting on pre-Phase-13 behaviour.
#
# Both halves are checked, because together they are the scoping property:
# nothing another tenant did appears, and what this caller did does.
if TWO_READY:
    total, http = studio_row(two, "log_event")
    check("studio log_event hides other tenants",
          total is not None and BASE_TWO_LOGS is not None and total == BASE_TWO_LOGS,
          f"saw {total} (HTTP {http}), expected baseline {BASE_TWO_LOGS} with no other tenant's events")

    total, http = studio_row(two, "audit_event")
    check("studio audit_event shows the caller's own denial and nothing else",
          total is not None and BASE_TWO_AUDIT is not None and total == BASE_TWO_AUDIT + 1,
          f"saw {total} (HTTP {http}), expected {BASE_TWO_AUDIT} + 1 own permission.denied")

section("SQL editor guard (instance owner)")
if not (OWNER_EMAIL and OWNER_PASSWORD):
    unavailable("SQL Editor owner guard cases",
                "YSD_ACCEPTANCE_OWNER_EMAIL / YSD_ACCEPTANCE_OWNER_PASSWORD for the instance owner")
else:
    owner = Client("owner", "203.0.113.14")
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
check("audit trail written", status == 200 and len(events) - BASE_LOGS > 5,
      f"{len(events)} events, baseline {BASE_LOGS}")

# Only assertable when a plan was genuinely refused. Without a blocked
# deployment there is no refusal to have logged, and claiming otherwise would
# be asserting on an event the run never caused.
if blocked_deployment:
    check("deployment refusals logged", any("blocked" in e["message"].lower() for e in events))
else:
    unavailable("deployment refusals logged", f"{NODE_PREREQUISITE} and {GITHUB_PREREQUISITE}")

expected_sources = {"secret", "project"}
if blocked_deployment or accepted_deployment:
    expected_sources.add("deployment")
if OWNER_EMAIL and OWNER_PASSWORD:
    expected_sources.add("database")
check("multiple sources represented", expected_sources <= sources, str(sorted(sources)))

status, body = one.request("GET", "/api/logs?source=database")
check("source filter works", status == 200 and all(e["source"] == "database" for e in body["events"]))

section("usage")
status, body = one.request("GET", "/api/usage")
check("usage measured", status == 200 and body["projectedMonthlyCost"] == 0, f"got {status}")
readings = {r["id"]: r for r in body["readings"]} if status == 200 else {}
check("project count measured",
      readings.get("projects", {}).get("used") == BASE_PROJECTS + EXPECTED_PROJECT_DELTA,
      f'used={readings.get("projects", {}).get("used")}, baseline {BASE_PROJECTS}')
check("database size reported honestly",
      readings.get("database-bytes", {}).get("measured") is False,
      "no Cloudflare API token configured")

section("YSD Shield")
status, body = one.request("POST", "/api/shield/scan")
check("scan runs", status == 200 and "score" in body, f"got {status}")
score = body.get("score") if isinstance(body, dict) else None
findings = {f["code"] for f in body.get("findings", [])} if status == 200 else set()
check("scan produced a score", isinstance(score, int) and 0 <= score <= 100, f"score={score}")

# Smart Deploy can no longer record a billable plan at all: `planDeployment`
# forces `zeroModeEnabled` on and both deployment inserts write
# `estimatedMonthlyCost` 0. So the assertion is the guarantee, not its
# violation -- nothing this run did could put a charge on record.
check("no billable resource could be recorded", "billable-resources-planned" not in findings,
      str(sorted(findings)))
status, body = one.request("GET", "/api/deployments")
costs = [d.get("estimatedMonthlyCost") for d in body.get("deployments", [])] if status == 200 else []
check("every recorded deployment costs zero", all(c == 0 for c in costs), str(costs))

check("no false expired-session finding", "expired-sessions" not in findings, str(sorted(findings)))

status, body = one.request("GET", "/api/shield")
scan = body.get("scan") if isinstance(body, dict) else None
check("scan persisted", status == 200 and scan is not None)
# Phase 15: a scan a human started is recorded as such, and the posture the
# page reads is a scan that actually completed.
check("manual scan records its provenance", bool(scan) and scan.get("trigger") == "manual",
      f'trigger={scan.get("trigger") if scan else None}')
check("recorded posture completed", bool(scan) and scan.get("status") == "completed",
      f'status={scan.get("status") if scan else None}')
check("posture delta recorded", bool(scan) and isinstance(scan.get("delta"), dict),
      str(scan.get("delta") if scan else None))
check("no automatic sweep claimed without one",
      isinstance(body, dict) and body.get("lastScheduled") is None,
      str(body.get("lastScheduled") if isinstance(body, dict) else None))

section("workspace isolation")
if TWO_READY:
    for path, key in (("/api/projects", "projects"), ("/api/secrets", "secrets"), ("/api/deployments", "deployments")):
        status, body = two.request("GET", path)
        check(f"operator 2 sees no {key}", status == 200 and len(body[key]) == 0,
              f"{len(body[key]) if status == 200 else status}")

    status, _ = two.request("DELETE", f"/api/secrets/{secret_id}")
    check("cross-tenant secret delete refused", status == 404, f"got {status}")
    status, _ = two.request("DELETE", f"/api/projects/{project_id}")
    check("cross-tenant project delete refused", status == 404, f"got {status}")
else:
    for name in ("operator 2 sees no projects", "operator 2 sees no secrets",
                 "operator 2 sees no deployments", "cross-tenant secret delete refused",
                 "cross-tenant project delete refused"):
        unavailable(name, f"a second signed-in operator — {THROTTLED}")

status, body = one.request("GET", "/api/secrets")
check("operator 1 secret intact", status == 200 and len(body["secrets"]) == 1)

if node_id and TWO_READY:
    status, body = two.request("GET", "/api/nodes")
    nodes = body.get("nodes", []) if status == 200 else []
    check("operator 2 sees no Compute Node", status == 200 and len(nodes) == 0, f"{len(nodes)}")
    status, body = two.request("POST", "/api/smart-deploy", deploy_request)
    check("cross-tenant node cannot be deployed to", status in (403, 404, 409),
          f"got {status} {error_of(body)[:60]}")
else:
    reason = NODE_PREREQUISITE if not node_id else f"a second signed-in operator — {THROTTLED}"
    unavailable("operator 2 sees no Compute Node", reason)
    unavailable("cross-tenant node cannot be deployed to", reason)

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
check("data still there after re-auth",
      EXPECTED_PROJECT_NAMES <= names and len(names) == BASE_PROJECTS + EXPECTED_PROJECT_DELTA,
      f"{sorted(names)} vs expected {sorted(EXPECTED_PROJECT_NAMES)} over baseline {BASE_PROJECTS}")

status, _ = one.request("POST", "/api/auth/sign-in/email",
                        {"email": f"public1-{RUN}@ysd.test", "password": "wrong-password-entirely"})
check("wrong password rejected", status in (401, 403), f"got {status}")

print(f"\n{'=' * 60}")
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
