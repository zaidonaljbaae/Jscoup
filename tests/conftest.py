# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
import pytest


@pytest.fixture(autouse=True)
def _isolated_working_dir(tmp_path, monkeypatch):
    """JSCoup's side stores (call log, gateway, sessions) default to
    repo-relative ``.jscoup/*.db`` paths; running every test from its own
    temp directory keeps one test's rows from leaking into the next."""
    monkeypatch.chdir(tmp_path)


import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _EchoHandler(BaseHTTPRequestHandler):
    """A stand-in for a real API: /ping -> 200, /boom -> 500, anything else -> 200
    echoing the method and path. JSCoup only ever replays APIs over HTTP, so
    tests that need something to call point ``base_url`` here."""

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        path, _, query = self.path.partition("?")
        if path.startswith("/echo"):
            from urllib.parse import parse_qs

            status, payload = 200, {
                "method": self.command, "path": path, "query": parse_qs(query),
                "content_type": self.headers.get("Content-Type"), "body": raw,
                "credential_header": self.headers.get("Authorization"),
            }
        elif path.startswith("/issue-token"):
            status, payload = 200, {"access_token": "abc.def.ghi", "token_type": "bearer", "user": "alice"}
        elif path.startswith("/boom"):
            status, payload = 500, {"error": "boom"}
        elif path.startswith("/ping"):
            status, payload = 200, {"pong": True}
        else:
            status, payload = 200, {"ok": True, "method": self.command, "path": path}
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _reply

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture(scope="session")
def echo_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def pytest_sessionfinish(session, exitstatus):
    """The dedicated CI backend job must never go green by skipping servers."""
    import os
    if os.environ.get("JSCOUP_REQUIRE_REAL_SERVERS") == "1":
        reporter = session.config.pluginmanager.getplugin("terminalreporter")
        if reporter and reporter.stats.get("skipped"):
            session.exitstatus = 1
