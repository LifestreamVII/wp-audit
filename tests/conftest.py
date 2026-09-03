"""Shared test fixtures for the wp-audit test-suite.

Provides a fake SSH client that the *detection* helpers call instead of a real
paramiko connection, plus a small HTTP response stub so the vulnerable-API
client can be tested offline.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Fake SSH plumbing (matches paramiko's exec_command/run_ssh_command contract)
# ---------------------------------------------------------------------------
class _Stdin:
    def write(self, *a, **k):
        return None

    def flush(self):
        return None


class _Stream:
    """Mimics paramiko stdout/stderr: a .read() returning bytes."""

    def __init__(self, data: bytes = b""):
        self._data = data

    def read(self, *a, **k):
        return self._data


class FakeClient:
    """A paramiko-SSHClient stand-in driven by substring -> output rules.

    `rules` maps a substring of the command to its stdout text. The first
    matching rule wins; unmatched commands produce empty stdout (so
    run_ssh_command returns None).
    """

    def __init__(self, rules: dict[str, str] | None = None, default: str = ""):
        self.rules = rules or {}
        self.default = default
        self.calls: list[str] = []

    def exec_command(self, command: str):
        self.calls.append(command)
        out = self.default
        for needle, repl in self.rules.items():
            if needle in command:
                out = repl
                break
        return _Stdin(), _Stream(out.encode()), _Stream(b"")

    def close(self):
        return None


@pytest.fixture
def fake_client():
    """A FakeClient factory as a function you can pass rules into."""
    return lambda rules=None, default="": FakeClient(rules=rules, default=default)


# ---------------------------------------------------------------------------
# HTTP response stub
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data

    def json(self):
        if callable(self._json):
            return self._json()
        return self._json