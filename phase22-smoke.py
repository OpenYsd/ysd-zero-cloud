"""Behavioural smoke tests for every Phase 22 harness primitive that does real work.

Four expensive runs were lost to harness defects that a minute of isolated
execution would have caught. This is that minute. Offline primitives run
always; the three that need a control plane run when invoked with `--online`.

It tests the harness, not the Product.
"""
import json
import os
import pathlib
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
ONLINE = "--online" in sys.argv

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""),
          flush=True)
    return bool(condition)


# The harness defines its helpers above its `try:`; executing just that prefix
# gives us the real functions without running the acceptance flow.
source = (REPO / "phase22-recovery-acceptance.py").read_text(encoding="utf8")
H = {"__name__": "harness", "__file__": str(REPO / "phase22-recovery-acceptance.py")}
exec(compile(source.split("\ntry:\n", 1)[0], "phase22-helpers", "exec"), H)

from acceptance_ports import (
    d1_database,
    port_holder_row,
    release_reserved_ports,
    reserve_specific_port,
)

control_plane = None
log_handle = None
smoke_home = pathlib.Path(tempfile.mkdtemp(prefix="ysd-phase22-smoke-"))
smoke_config = smoke_home / "credentials.json"
smoke_key = "ysd-smoke-" + secrets.token_hex(16)
RUN = secrets.token_hex(3)
node_id = None
holder_node = None
fixture = None

try:
    print("\n=== credential reader ===", flush=True)
    sealer = smoke_home / "seal.cjs"
    sealer.write_text(
        "const { writeFileSync } = require('node:fs');\n"
        "const { scryptSync, createCipheriv, randomBytes } = require('node:crypto');\n"
        "const salt = randomBytes(16), iv = randomBytes(12);\n"
        "const key = scryptSync(process.argv[3], salt, 32, "
        "{ N: 16384, r: 8, p: 1, maxmem: 64*1024*1024 });\n"
        "const cipher = createCipheriv('aes-256-gcm', key, iv);\n"
        "const plain = Buffer.from(JSON.stringify({ origin: 'http://127.0.0.1:1',\n"
        "  nodeId: 'node_' + 'a'.repeat(24), workspaceId: 'ws_1', token: process.argv[4],\n"
        "  createdAt: 1 }));\n"
        "const ct = Buffer.concat([cipher.update(plain), cipher.final()]);\n"
        "writeFileSync(process.argv[2], JSON.stringify({ version: 1,\n"
        "  salt: salt.toString('base64url'), iv: iv.toString('base64url'),\n"
        "  tag: cipher.getAuthTag().toString('base64url'),\n"
        "  ciphertext: ct.toString('base64url') }));\n", encoding="utf8")
    sealed_fixture = smoke_home / "sealed.json"
    expected = "smoke-" + secrets.token_hex(12)
    subprocess.run([H["NODE"], str(sealer), str(sealed_fixture), smoke_key, expected],
                   check=True, capture_output=True, timeout=120)
    recovered = H["read_sealed_credentials"](sealed_fixture, smoke_key)
    check("credential round-trip returns the sealed identity",
          recovered.get("nodeId") == "node_" + "a" * 24)
    check("credential round-trip returns the sealed token", recovered.get("token") == expected)
    wrong = None
    try:
        H["read_sealed_credentials"](sealed_fixture, "ysd-smoke-wrong-key-value-here")
    except RuntimeError as error:
        wrong = str(error)
    check("a wrong key fails loudly with a cause", wrong is not None and len(wrong) > 40)
    sealed_fixture.unlink(missing_ok=True)
    sealer.unlink(missing_ok=True)
    del expected, recovered

    print("\n=== local D1 readers ===", flush=True)
    check("the local acceptance database is found", H["local_d1_path"]() is not None)
    any_node = H["d1_read"]("SELECT id, workspaceId FROM compute_node LIMIT 1")
    holder_node = any_node[0]["id"] if any_node else None
    workspace_id = any_node[0]["workspaceId"] if any_node else None
    check("d1_read returns dict rows", isinstance(any_node, list))
    check("compute_node_row handles an absent row",
          H["compute_node_row"]("node_" + "0" * 24) == {})
    if holder_node:
        check("compute_node_row returns a real row",
              H["compute_node_row"](holder_node).get("id") == holder_node)
    for name, args in [("artifact_rows", ("dpl_" + "0" * 24,)),
                       ("app_runtime_jobs", ("dpl_" + "0" * 24,)),
                       ("operations", ("dpl_" + "0" * 24, "start"))]:
        check(f"{name} executes and returns a list", isinstance(H[name](*args), list))
    jobs, actions, provisional = H["import_reservation"]("dpl_" + "0" * 24)
    check("import_reservation returns three lists",
          all(isinstance(v, list) for v in (jobs, actions, provisional)))
    check("artifact_row handles an absent artifact", H["artifact_row"]("art_" + "0" * 24) == {})

    print("\n=== crash injection helper ===", flush=True)
    if not holder_node:
        check("a paired node exists to scope the fixture to", False,
              "no compute_node row in the local acceptance database")
    else:
        deployment = "dpl_" + "5e" * 12
        fixture = {"job": "job_" + "5e" * 12, "action": "dact_" + "5e" * 12,
                   "artifact": "art_" + "5e" * 12, "sentinel": "art_" + "5f" * 12}
        database = sqlite3.connect(d1_database(REPO), timeout=30)
        try:
            database.execute(
                "INSERT INTO node_job (id, workspaceId, type, payload, payloadHash, state,"
                " priority, idempotencyKey, attempts, maxAttempts, createdBy, createdAt, updatedAt)"
                " VALUES (?, ?, 'app-runtime.action', '{}', 'x', 'queued', 0, ?, 0, 3,"
                " 'smoke', 1, 1)",
                (fixture["job"], workspace_id, f"app:import:{deployment}:2"))
            # Distinct versions: app_artifact is UNIQUE (projectId, nodeId, version).
            for artifact, state, version in ((fixture["artifact"], "building", 1),
                                             (fixture["sentinel"], "verified", 2)):
                database.execute(
                    "INSERT INTO app_artifact (id, workspaceId, deploymentId, projectId, nodeId,"
                    " commitSha, version, state, manifest, sizeBytes, createdAt)"
                    " VALUES (?, ?, ?, 'prj_smoke', ?, '0', ?, ?, '{}', 0, 1)",
                    (artifact, workspace_id, deployment, holder_node, version, state))
            database.execute(
                "INSERT INTO app_deployment_action (id, workspaceId, deploymentId, projectId,"
                " nodeId, jobId, kind, state, idempotencyKey, requestedBy, createdAt, updatedAt)"
                " VALUES (?, ?, ?, 'prj_smoke', ?, ?, 'import', 'queued', ?, 'smoke', 1, 1)",
                (fixture["action"], workspace_id, deployment, holder_node, fixture["job"],
                 f"import:{deployment}:2"))
            database.commit()
        finally:
            database.close()

        jobs, actions, provisional = H["import_reservation"](deployment)
        check("the fixture reservation reads as exactly 1/1/1",
              len(jobs) == 1 and len(actions) == 1 and len(provisional) == 1,
              json.dumps({"jobs": len(jobs), "actions": len(actions),
                          "artifacts": len(provisional)}))
        refused = None
        try:
            H["inject_reservation_crash"](deployment, "art_" + "0" * 24)
        except RuntimeError as error:
            refused = str(error)
        check("the helper refuses an artifact it was not asked to assert", refused is not None,
              (refused or "")[:80])
        injected = H["inject_reservation_crash"](deployment, fixture["artifact"])
        check("the helper reports what it removed", injected.get("artifact") == fixture["artifact"])
        jobs, actions, provisional = H["import_reservation"](deployment)
        check("only the action and provisional artifact were removed",
              len(jobs) == 1 and len(actions) == 0 and len(provisional) == 0,
              json.dumps({"jobs": len(jobs), "actions": len(actions),
                          "artifacts": len(provisional)}))
        check("an unrelated sentinel artifact is untouched",
              H["artifact_row"](fixture["sentinel"]).get("state") == "verified")

    print("\n=== port holder ===", flush=True)
    if holder_node:
        holder_port = H["free_loopback_port"]()
        check("no holder before reserving", port_holder_row(REPO, holder_node, holder_port) is None)
        created = reserve_specific_port(REPO, holder_node, holder_port, int(time.time() * 1000))
        observed = port_holder_row(REPO, holder_node, holder_port)
        check("reserving creates an observable holder", bool(created) and observed is not None)
        check("the holder sits inside the allocator's taken predicate",
              (observed or {}).get("state") not in (None, "blocked"), json.dumps(observed))
        released = release_reserved_ports(REPO)
        check("releasing removes it",
              released >= 1 and port_holder_row(REPO, holder_node, holder_port) is None,
              f"released {released}")
        check("a second release is safe and idempotent", release_reserved_ports(REPO) == 0)

    print("\n=== concurrency helper ===", flush=True)

    def worker(index):
        time.sleep(0.4)
        return index

    started = time.time()
    results = H["concurrently"](worker, 2)
    elapsed = time.time() - started
    check("both workers ran", sorted(results) == [0, 1], json.dumps(results))
    check("they overlapped rather than queued", elapsed < 0.75, f"{elapsed:.2f}s")

    def boom(_index):
        raise ValueError("smoke")

    raised = False
    try:
        H["concurrently"](boom, 2)
    except ValueError:
        raised = True
    check("worker exceptions propagate rather than vanish", raised)

    if ONLINE:
        print("\n=== cheap local control plane ===", flush=True)
        port = H["free_loopback_port"]()
        H["BASE"] = f"http://127.0.0.1:{port}"
        log_path = smoke_home / "control-plane.log"
        log_handle = log_path.open("w", encoding="utf8")
        control_plane = subprocess.Popen(
            ["node.exe", str(REPO / "node_modules/vinext/dist/cli.js"), "dev",
             "--hostname", "127.0.0.1", "--port", str(port)],
            cwd=REPO, stdout=log_handle, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        H["wait_control_plane"](control_plane, log_path)
        check("control plane is live", control_plane.poll() is None)

        Client = H["Client"]
        email = f"smoke-{RUN}@ysd.test"
        password = f"smoke-local-{RUN}-longpassword"
        operator = Client()
        status, _ = operator.request("POST", "/api/auth/sign-up/email",
                                     {"name": "Smoke", "email": email, "password": password})
        check("operator session established", status == 200, f"got {status}")

        print("\n=== operator clients ===", flush=True)
        a = H["authenticated_operator"](email, password)
        b = H["authenticated_operator"](email, password)
        check("client A authenticated", a is not None)
        check("client B authenticated", b is not None)
        anonymous = Client()
        anon_status, _ = anonymous.request("GET", "/api/nodes")
        check("an unauthenticated client is refused the protected read",
              anon_status in (401, 403), f"got {anon_status}")

        print("\n=== authenticated HTML ===", flush=True)
        page = H["body_at_path"](a, "/nodes")
        check("authenticated page returns HTML", isinstance(page, str) and len(page) > 200,
              f"{len(page)} bytes")
        anon_page = H["body_at_path"](anonymous, "/nodes")
        check("an unauthenticated read is not mistaken for the real page",
              len(anon_page) < len(page) or "sign" in anon_page.lower(),
              f"{len(anon_page)} bytes")

        print("\n=== signed node requests ===", flush=True)
        status, body = operator.request("POST", "/api/nodes", {"name": f"Smoke Node {RUN}"})
        pairing = (body or {}).get("pairing")
        check("pairing ticket issued", status == 201 and bool(pairing), f"got {status}")
        manifest = json.loads((REPO / "public/agent/manifest.json").read_text(encoding="utf8"))
        bundle = REPO / "public/agent" / manifest["filename"]
        paired = subprocess.run(
            [H["NODE"], str(bundle), "pair", "--url", H["BASE"], "--config", str(smoke_config)],
            cwd=smoke_home,
            env={**os.environ, "YSD_NODE_AGENT_HOME": str(smoke_home),
                 "YSD_NODE_CONFIG": str(smoke_config), "LOCALAPPDATA": str(smoke_home),
                 "XDG_DATA_HOME": str(smoke_home), "YSD_NODE_AGENT_KEY": smoke_key,
                 "YSD_NODE_PAIRING_CODE": pairing["code"]},
            capture_output=True, text=True, timeout=180)
        check("throwaway node pairs", paired.returncode == 0, paired.stderr.strip()[-160:])
        sealed = H["read_sealed_credentials"](smoke_config, smoke_key)
        node_id = sealed["nodeId"]
        token = sealed["token"]
        check("a really-paired node's sealed credential reads back", bool(node_id and token))
        check("a valid signed request is accepted",
              H["assert_signed_node_identity"](node_id, token))
        check("an invalid token is rejected",
              not H["assert_signed_node_identity"](node_id, "not-" + "x" * 40))
        foreign = H["signed_node_post"](
            token, "/api/nodes/agent/deployments/dpl_" + "9" * 24 + "/restore-preflight", {})
        check("a deployment this node does not own is refused",
              foreign in (400, 404, 409), f"got {foreign}")
        shape_status, shape_body = H["signed_node_json"](
            token, "/api/nodes/agent/heartbeat",
            {"agentVersion": H["CURRENT_AGENT_VERSION"], "protocolVersion": 1,
             "capabilities": {}, "metrics": None})
        check("signed_node_json returns (int, parsed body or None)",
              isinstance(shape_status, int)
              and (shape_body is None or isinstance(shape_body, (dict, list))))
        check("signed_node_post returns a bare int", isinstance(foreign, int))
        del token, sealed

finally:
    print("\n=== cleanup ===", flush=True)
    if fixture:
        database = sqlite3.connect(d1_database(REPO), timeout=30)
        try:
            database.execute("DELETE FROM app_deployment_action WHERE id = ?", (fixture["action"],))
            database.execute("DELETE FROM app_artifact WHERE id IN (?, ?)",
                             (fixture["artifact"], fixture["sentinel"]))
            database.execute("DELETE FROM node_job WHERE id = ?", (fixture["job"],))
            database.commit()
        finally:
            database.close()
    release_reserved_ports(REPO)
    # Executing the harness prefix runs its module-level mkdtemp calls, so this
    # script owns those directories too and must not leave them behind.
    for leaked in (H.get("home"), H.get("external"), H.get("second_home")):
        if leaked is not None:
            shutil.rmtree(leaked, ignore_errors=True)
    if node_id and control_plane is not None:
        try:
            H["Client"]().request("DELETE", f"/api/nodes/{node_id}")
        except OSError:
            pass
    if control_plane is not None:
        subprocess.run(["taskkill.exe", "/PID", str(control_plane.pid), "/T", "/F"],
                       capture_output=True)
        try:
            control_plane.wait(timeout=20)
        except subprocess.TimeoutExpired:
            control_plane.kill()
    if log_handle is not None:
        log_handle.close()
    for _ in range(10):
        try:
            shutil.rmtree(smoke_home)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.5)

check("temporary smoke home removed", not smoke_home.exists())
if fixture:
    check("smoke fixture rows removed", H["artifact_row"](fixture["sentinel"]) == {})
print(f"\nPASSED {len(PASSED)}  FAILED {len(FAILED)}")
for failure in FAILED:
    print("  FAIL - " + failure)
sys.exit(1 if FAILED else 0)
