"""Environment prerequisites for the acceptance harnesses.

Test-environment code only. It reads, it never writes: no database, no task,
no Agent, no Windows configuration. Its single job is to tell a genuinely
impossible environment apart from a product regression, before an expensive
run produces a misleading FAIL.

The case it exists for is specific. Phase 20 deploys its fixture while the node
is still running the exact frozen Agent 0.6.0, which predates private-port
negotiation: it takes the port the control plane assigns and gives up if it
cannot bind it. Agent 0.8.0 can renegotiate; 0.6.0 cannot, and its bytes are
frozen on purpose. On a host where Windows has reserved that port for Hyper-V
or WSL, the acceptance cannot run at all -- and calling that a product failure
would be untrue.
"""
import errno
import re
import socket
from pathlib import Path

LEGACY_PORT_BLOCKED = "legacy_agent_private_port_unavailable"

#: Bind failures that mean "pick another port", not "something is broken".
#: EACCES is the Windows excluded-range answer; it is not "in use".
UNAVAILABLE = {errno.EADDRINUSE, errno.EACCES}


def app_runtime_port_minimum(repo):
    """The bottom of the private App Runtime range, read from the product.

    Taken from the source rather than written down here, so the harness and the
    allocator cannot drift apart.
    """
    source = (Path(repo) / "lib" / "app-runtime.ts").read_text(encoding="utf8")
    match = re.search(r"portMinimum:\s*([0-9_]+)", source)
    if not match:
        raise RuntimeError("the App Runtime private port range could not be read")
    return int(match.group(1).replace("_", ""))


def probe_port(port, host="127.0.0.1", opener=None):
    """Whether this host will actually hand over a port, by binding it.

    The same exclusive bind on the same address the App Runtime uses. Nothing
    weaker is proof: a port with no listener can still be unbindable, because
    Windows reserves blocks for Hyper-V and WSL and refuses them with EACCES.
    `Get-NetTCPConnection`, `netstat` and the netsh exclusion list all report
    such a port as free -- which is exactly how this cost several full runs
    before anyone tried binding it.

    Returns `(bindable, code)`. `code` is a symbolic errno name, never an
    operating-system message, so nothing user-specific is ever printed.
    """
    probe = (opener or socket.socket)(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except (AttributeError, OSError):
            pass  # POSIX has no exclusive flag; the plain bind asks the same question.
        try:
            probe.bind((host, port))
            return True, ""
        except OSError as error:
            return False, errno.errorcode.get(error.errno, "EUNKNOWN")
    finally:
        try:
            probe.close()
        except OSError:
            pass


def legacy_private_port_status(repo, agent_version, probe=probe_port):
    """The verdict for a harness that must run a frozen, non-negotiating Agent.

    `None` means the environment is usable. Anything else is a bounded record
    the caller prints before stopping -- never a product result.
    """
    port = app_runtime_port_minimum(repo)
    bindable, code = probe(port)
    if bindable:
        return None
    return {
        "reason": LEGACY_PORT_BLOCKED,
        "expectedPort": port,
        "bindable": False,
        "osError": code,
        "agentVersion": agent_version,
        "why": "the frozen Agent cannot renegotiate a private port",
        "productGateResult": "not produced",
    }
