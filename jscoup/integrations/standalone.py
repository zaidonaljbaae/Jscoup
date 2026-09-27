# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Standalone dashboard server.

Serves the dashboard as its own listener on its own host/port instead of a
route mounted inside the monitored app's router, while sharing the same
:class:`~jscoup.core.JSCoup` instance (registry, storage, simulator) so it
always reflects exactly what that app is doing. Uses only :mod:`http.server`
from the standard library, matching the project's zero-dependency design.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_logger = logging.getLogger("jscoup.dashboard")


class _DashboardRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "JSCoup/1.0"

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        jscoup = self.server.jscoup  # type: ignore[attr-defined]
        parts = urlsplit(self.path)
        query = dict(parse_qsl(parts.query))
        self.connection.settimeout(10)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            self.close_connection = True
            return
        if self.headers.get("Transfer-Encoding") or length < 0 or length > jscoup.config.dashboard_max_body_bytes:
            self.send_error(413, "Unsupported transfer encoding or body too large")
            self.close_connection = True
            return
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items()}
        try:
            result = jscoup.dashboard.handle(
                path=parts.path,
                method=method,
                query=query,
                body=body,
                headers=headers,
                base_url="http://" + self.headers.get("Host", ""),
                mount="",
                client_ip=self.client_address[0] if self.client_address else None,
            )
        except Exception:  # the dashboard must never take the whole server down
            _logger.exception("jscoup dashboard request failed: %s %s", method, self.path)
            payload = b'{"error": "internal dashboard error"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(result.status)
        response_headers = result.all_headers()
        response_headers.setdefault("Content-Length", str(len(result.body)))
        for key, value in response_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(result.body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        _logger.info("%s - %s", self.address_string(), format % args)


def run_standalone_dashboard(
    jscoup: Any, host: str = "127.0.0.1", port: int = 9000, background: bool = True
) -> ThreadingHTTPServer:
    """Start the dashboard on its own ``host:port``.

    Returns the running server. With ``background=True`` (the default) it runs
    on a daemon thread so the caller can go on to start its own app right
    after this returns; with ``background=False`` it blocks the calling thread.
    """
    try:
        httpd = ThreadingHTTPServer((host, port), _DashboardRequestHandler)
    except OSError as exc:
        raise OSError(f"Could not start the JSCoup dashboard on {host}:{port} - {exc}") from exc
    httpd.jscoup = jscoup  # type: ignore[attr-defined]

    if background:
        thread = threading.Thread(target=httpd.serve_forever, name="jscoup-dashboard", daemon=True)
        thread.start()
    else:
        httpd.serve_forever()
    return httpd
