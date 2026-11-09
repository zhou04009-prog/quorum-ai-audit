"""Trusted pytest plugin for the Quorum Gateway v3 supervisor.

This plugin runs INSIDE the pytest process, but it is trusted code: it is
loaded from the pinned verifier tree (never from the PR subject), and it
reports test lifecycle events to an out-of-band supervisor over a Unix
socket, authenticated with a per-run token.

Trust model (v3 — replaces the v2 junitxml evidence file, which the
tested code could forge by writing to its predictable path and exiting 0):
- The executor (trusted) creates a Unix socket at a random path and a
  per-run random token. It passes the socket path and token to the
  pytest process through a PIPE FILE DESCRIPTOR (pass_fds), NOT through
  an environment variable, argv, or a file the test code can find.
- This plugin reads the socket path + token from that FD at
  pytest_configure time, then CLOSES the FD immediately and deletes the
  env var naming it, so by the time any test/subject code runs, the FD
  is gone and the token exists only in this plugin's memory.
- The plugin sends one event per test phase (setup/call/teardown) plus
  session_start / session_finish, each carrying the token. The
  supervisor validates the token and records the events; the gateway's
  decision rests ONLY on those supervisor events plus pytest's exit
  code. There is NO evidence file for the tested code to forge.
- If the plugin cannot reach the supervisor, it fails loudly at
  configure time (pytest errors out) — fail-closed, never a silent
  pass without supervision.

Residual risk (documented, not hidden): the token lives in this
plugin's memory inside the pytest process, so test code that
specifically hunts for it (importing this module and reading its
internals, then impersonating the supervisor protocol) could in
principle forge events. That is a targeted attack on the supervisor
itself — qualitatively different from, and far more visible than,
writing a predictable evidence file — and it is the reason the
supervisor also requires a sane event sequence (session_start first,
setup before call, call before teardown) and the gateway cross-checks
the events against pytest's own exit code. Closing that last step
airtight would need the tests to run in a separate trust domain from
the reporter, which is a follow-up architecture item.
"""

import json
import os
import socket
import sys

# Connection state. The token is read from the supervisor FD at configure
# time and kept only here (module scope of THIS trusted plugin). The FD is
# closed and the env var deleted immediately after reading, before any
# test/subject code runs.
_SOCK = None
_TOKEN = None
_SESSION_STARTED = False


def _send(event):
    """Send one authenticated event to the supervisor (best effort)."""
    if _SOCK is None or _TOKEN is None:
        return
    try:
        event = dict(event)
        event["token"] = _TOKEN
        _SOCK.sendall((json.dumps(event) + "\n").encode("utf-8"))
    except (OSError, ValueError):
        # A failed send means the supervisor will be missing this event,
        # which fails the check closed (EVIDENCE_MISSING). Never crash
        # pytest over a reporting failure: the missing evidence is itself
        # the verdict.
        pass


def pytest_configure(config):
    """Connect to the supervisor. Fail loudly if unreachable."""
    global _SOCK, _TOKEN
    fd_s = os.environ.get("QUORUM_SUPERVISOR_FD")
    if not fd_s:
        raise RuntimeError("quorum supervisor: QUORUM_SUPERVISOR_FD is not set")
    try:
        fd = int(fd_s)
    except ValueError:
        raise RuntimeError("quorum supervisor: QUORUM_SUPERVISOR_FD is not an fd")
    try:
        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as f:
            sock_path = f.readline().strip()
            token = f.readline().strip()
    except OSError as exc:
        raise RuntimeError(f"quorum supervisor: cannot read supervisor fd: {exc}")
    finally:
        # The FD is closed (closefd=True above, or on error). Remove the
        # env var so test code cannot even learn the FD number.
        os.environ.pop("QUORUM_SUPERVISOR_FD", None)
    if not sock_path or not token:
        raise RuntimeError("quorum supervisor: empty socket path or token")
    _TOKEN = token
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sock_path)
    except OSError as exc:
        raise RuntimeError(f"quorum supervisor: cannot connect: {exc}")
    _SOCK = sock


def pytest_sessionstart(session):
    global _SESSION_STARTED
    _send({"type": "session_start"})
    _SESSION_STARTED = True


def pytest_runtest_logreport(report):
    _send({"type": "test", "node": report.nodeid,
           "phase": report.when, "outcome": report.outcome})


def pytest_sessionfinish(session, exitstatus):
    _send({"type": "session_finish", "exitstatus": exitstatus})
    global _SOCK
    try:
        if _SOCK is not None:
            _SOCK.close()
    except OSError:
        pass
    _SOCK = None


# The plugin must be importable without pytest (unit tests import it to
# check it does not execute subject code on import). Importing alone must
# not connect anywhere or read any fd.
if __name__ == "__main__":
    sys.exit("quorum_supervisor_plugin is a pytest plugin, not a script")
