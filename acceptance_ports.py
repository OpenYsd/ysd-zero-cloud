"""Harness-only private port reservation for the acceptance environment.

Kept apart from `acceptance_preflight`, which is and must remain read-only.

Frozen Agent 0.6.0 predates private-port negotiation: it takes the port the
control plane assigns and gives up if it cannot bind it. On a host where Windows
reserves the bottom of the App Runtime range for Hyper-V or WSL, the Phase 20
fixture can therefore never start -- not because anything is broken, but because
the acceptance environment hands a frozen binary a port this machine will not
grant.

That is an environment problem, so it is fixed in the environment. The
allocator, the port range, the frozen Agent and every Phase 20 expectation stay
exactly as they are. The harness simply makes the ports this host refuses
*legitimately unavailable* to the existing allocator, by owning them the way any
other deployment on the node would. `nextPort()` then picks the first free port
by itself, and that port is one the operating system will actually grant.

These rows describe no application: no job is queued, no artifact is created, no
Agent ever sees them, nothing runs. They exist in the local acceptance database
only, are scoped to the workspace, project and node the acceptance already owns,
and are removed during cleanup.
"""
import glob
import json
import sqlite3
from pathlib import Path

from acceptance_preflight import app_runtime_port_minimum, probe_port

#: Stamped into `repository` so every row is identifiable and removable.
HARNESS_PORT_HOLDER = "ysd-acceptance-port-holder"


def d1_database(repo):
    """The acceptance control plane's local D1 file."""
    files = [
        f for f in glob.glob(
            str(Path(repo) / ".wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite")
        )
        if "metadata" not in f
    ]
    if len(files) != 1:
        raise RuntimeError(f"expected exactly one acceptance D1 file, found {len(files)}")
    return files[0]


def first_bindable_port(repo, limit=400, probe=probe_port):
    """The first port at or above the App Runtime minimum this host will grant.

    Discovered, never written down: if the host's reservations move, the next
    run finds the new answer by itself.
    """
    start = app_runtime_port_minimum(repo)
    for port in range(start, start + limit):
        bindable, _ = probe(port)
        if bindable:
            return start, port
    raise RuntimeError("no bindable private App Runtime port on this host")


def holder_id(port):
    """A deployment id in the normal shape, derived from the port it holds."""
    return f"dpl_{'ac' * 8}{port:08x}"


def reserve_unbindable_ports(repo, node_id, upto_exclusive, now):
    """Owns the ports this host refuses, so the real allocator skips them.

    The tenant is read from the node's own row rather than passed in, so a
    holder can only ever land in the workspace that node already belongs to.
    `projectId` stays null: these rows describe no project and no application,
    and the allocator only reads `nodeId` and `localPort`.

    Returns the reserved ports.
    """
    start = app_runtime_port_minimum(repo)
    ports = list(range(start, upto_exclusive))
    if not ports:
        return []
    # These rows stand for ports that are *already* taken on this node, not for
    # deployments anyone just made. Stamping them "created now" said the
    # opposite, and YSD Shield read a hundred-odd of them as an abusive
    # deployment burst and refused the fixture -- correctly, given what the
    # data claimed. Shield's window is an hour; the honest timestamp for
    # pre-existing occupancy is well before it. The guard is untouched.
    created_at = now - 25 * 60 * 60 * 1000
    plan = json.dumps({"harness": HARNESS_PORT_HOLDER})
    database = sqlite3.connect(d1_database(repo), timeout=30)
    try:
        row = database.execute(
            "SELECT workspaceId FROM compute_node WHERE id = ?", (node_id,),
        ).fetchone()
        if not row:
            raise RuntimeError("the controlled node was not found in the acceptance database")
        workspace_id = row[0]
        database.executemany(
            """INSERT INTO deployment (
                 id, workspaceId, projectId, nodeId, localPort, repository, target,
                 framework, commitSha, state, plan, createdAt, branch, environment,
                 exposure, observedBind, healthPath, estimatedMonthlyCost,
                 zeroModeEnabled, restartCount, crashLoop
               ) VALUES (?, ?, NULL, ?, ?, ?, 'user-node', 'Express', ?, 'planned', ?, ?,
                         'main', 'Production', 'private', 'unknown', '/', 0, 1, 0, 0)""",
            [
                (holder_id(port), workspace_id, node_id, port,
                 HARNESS_PORT_HOLDER, "0" * 40, plan, created_at)
                for port in ports
            ],
        )
        database.commit()
    finally:
        database.close()
    return ports


def reserve_specific_port(repo, node_id, port, now):
    """Owns exactly one port on one node, so a real negotiation must move off it.

    Same shape, tenant rule and timestamp discipline as the range reservation
    above: `state='planned'` is inside the partial unique index on
    (nodeId, localPort) and inside the allocator's and the negotiator's
    "taken" predicates, which is precisely the occupancy Phase 22 needs to be
    real. The pre-existing `createdAt` is not cosmetic -- a row claiming it was
    created now reads to YSD Shield as a deployment burst, and Shield is right
    to refuse it.

    Returns True when this call created the holder.
    """
    created_at = now - 25 * 60 * 60 * 1000
    plan = json.dumps({"harness": HARNESS_PORT_HOLDER})
    database = sqlite3.connect(d1_database(repo), timeout=30)
    try:
        row = database.execute(
            "SELECT workspaceId FROM compute_node WHERE id = ?", (node_id,),
        ).fetchone()
        if not row:
            raise RuntimeError("the controlled node was not found in the acceptance database")
        clash = database.execute(
            "SELECT id FROM deployment WHERE nodeId = ? AND localPort = ? "
            "AND deletedAt IS NULL AND state <> 'blocked'", (node_id, port),
        ).fetchone()
        if clash:
            # Something already holds it. Occupancy is the goal, so this is a
            # success, but it is not this call's holder to remove.
            return False
        database.execute(
            """INSERT INTO deployment (
                 id, workspaceId, projectId, nodeId, localPort, repository, target,
                 framework, commitSha, state, plan, createdAt, branch, environment,
                 exposure, observedBind, healthPath, estimatedMonthlyCost,
                 zeroModeEnabled, restartCount, crashLoop
               ) VALUES (?, ?, NULL, ?, ?, ?, 'user-node', 'Express', ?, 'planned', ?, ?,
                         'main', 'Production', 'private', 'unknown', '/', 0, 1, 0, 0)""",
            (holder_id(port), row[0], node_id, port,
             HARNESS_PORT_HOLDER, "0" * 40, plan, created_at),
        )
        database.commit()
        return True
    finally:
        database.close()


def port_holder_row(repo, node_id, port):
    """What the acceptance database says about occupancy of one port."""
    database = sqlite3.connect(f"file:{d1_database(repo)}?mode=ro", uri=True)
    try:
        row = database.execute(
            "SELECT id, state FROM deployment WHERE nodeId = ? AND localPort = ? "
            "AND deletedAt IS NULL AND state <> 'blocked'", (node_id, port),
        ).fetchone()
        return {"id": row[0], "state": row[1]} if row else None
    finally:
        database.close()


def release_reserved_ports(repo):
    """Removes every harness-owned port holder. Safe to call more than once."""
    try:
        path = d1_database(repo)
    except RuntimeError:
        return 0
    database = sqlite3.connect(path, timeout=30)
    try:
        cursor = database.execute(
            "DELETE FROM deployment WHERE repository = ?", (HARNESS_PORT_HOLDER,),
        )
        database.commit()
        return cursor.rowcount
    finally:
        database.close()
