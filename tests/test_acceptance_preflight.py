"""Tests for the acceptance environment preflight.

Run with: python -m unittest discover -s tests -p "test_*.py"

The preflight decides one thing: can this host satisfy a prerequisite that the
frozen Agent 0.6.0 cannot renegotiate? Getting that wrong in either direction
is expensive -- a false "usable" costs a ten-minute run and a misleading FAIL,
a false "blocked" hides a real regression.
"""
import errno
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from acceptance_preflight import (  # noqa: E402
    LEGACY_PORT_BLOCKED,
    app_runtime_port_minimum,
    legacy_private_port_status,
    probe_port,
)

REPO = Path(__file__).resolve().parent.parent


class FakeSocket:
    """A socket that fails to bind exactly how a caller asks it to."""

    opened = 0
    closed = 0

    def __init__(self, code=None):
        self.code = code
        self.bound = None
        FakeSocket.opened += 1

    def setsockopt(self, *_args):
        return None

    def bind(self, address):
        if self.code is not None:
            raise OSError(self.code, "bind refused")
        self.bound = address

    def close(self):
        FakeSocket.closed += 1


def opener_for(code):
    def opener(*_args):
        return FakeSocket(code)
    return opener


class PreflightTests(unittest.TestCase):
    def test_expected_port_bindable_lets_acceptance_proceed(self):
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (True, ""),
        )
        self.assertIsNone(status, "a usable environment must not be reported blocked")

    def test_port_in_use_blocks(self):
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (False, "EADDRINUSE"),
        )
        self.assertIsNotNone(status)
        self.assertEqual(status["reason"], LEGACY_PORT_BLOCKED)
        self.assertEqual(status["osError"], "EADDRINUSE")

    def test_windows_excluded_range_blocks(self):
        # The real case on the acceptance host: nothing is listening, and the
        # port is still refused because Windows reserved the range.
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (False, "EACCES"),
        )
        self.assertIsNotNone(status)
        self.assertEqual(status["osError"], "EACCES")
        self.assertEqual(status["agentVersion"], "0.6.0")

    def test_unexpected_socket_error_blocks_truthfully(self):
        # An error nobody anticipated must not be silently treated as a normal
        # collision, and must not be reported as a product failure either.
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (False, "EUNKNOWN"),
        )
        self.assertIsNotNone(status)
        self.assertEqual(status["osError"], "EUNKNOWN")
        self.assertEqual(status["productGateResult"], "not produced")

    def test_probe_classifies_real_socket_errors_by_code(self):
        # The symbolic name is whatever this platform calls it -- Windows
        # spells the socket errors WSAE*. What matters is that the code comes
        # from errno rather than from a parsed operating-system message.
        for number in (errno.EACCES, errno.EADDRINUSE):
            bindable, code = probe_port(41000, opener=opener_for(number))
            self.assertFalse(bindable)
            self.assertEqual(code, errno.errorcode[number])
            self.assertNotIn(" ", code, "the code must be symbolic, not a message")

        bindable, code = probe_port(41000, opener=opener_for(None))
        self.assertTrue(bindable)
        self.assertEqual(code, "")

    def test_probe_always_closes_its_socket(self):
        FakeSocket.opened = FakeSocket.closed = 0
        probe_port(41000, opener=opener_for(errno.EACCES))
        probe_port(41000, opener=opener_for(None))
        self.assertEqual(FakeSocket.opened, 2)
        self.assertEqual(FakeSocket.closed, 2, "the preflight must not leak sockets")

    def test_preflight_writes_nothing(self):
        # It reads one product constant and binds one socket. Anything that
        # mutated database, task or Agent state would make the preflight itself
        # a source of test flakiness.
        #
        # Code only: the module deliberately *mentions* netsh in prose, to
        # record why bind() is used instead of the exclusion list.
        import ast

        module = ast.parse((REPO / "acceptance_preflight.py").read_text(encoding="utf8"))
        for node in ast.walk(module):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                node.value = ""
        code = ast.unparse(module)
        for forbidden in (
            "sqlite3", "urllib", "requests", "subprocess", "schtasks",
            "netsh", "open(", "write_text", "mkdir", "remove", "rmtree",
        ):
            self.assertNotIn(forbidden, code, f"the preflight must not use {forbidden}")

    def test_blocked_result_can_never_read_as_a_pass(self):
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (False, "EACCES"),
        )
        rendered = json.dumps(status)
        self.assertNotIn("PASS", rendered.upper().replace("NOT PRODUCED", ""))
        self.assertEqual(status["bindable"], False)
        self.assertIn("productGateResult", status)

    def test_diagnostic_carries_no_secrets_or_user_paths(self):
        status = legacy_private_port_status(
            REPO, "0.6.0", probe=lambda _port: (False, "EACCES"),
        )
        rendered = json.dumps(status).lower()
        for forbidden in ("token", "authorization", "cookie", "password", "secret",
                          "c:\\\\users", "credential", "bearer"):
            self.assertNotIn(forbidden, rendered)

    def test_expected_port_comes_from_the_product_constant(self):
        # Written down in the harness, this would drift the first time the
        # allocator range moved.
        self.assertEqual(app_runtime_port_minimum(REPO), 41000)
        source = (REPO / "lib" / "app-runtime.ts").read_text(encoding="utf8")
        self.assertIn("portMinimum", source)


if __name__ == "__main__":
    unittest.main()
