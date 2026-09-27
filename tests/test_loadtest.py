# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.loadtest — concurrent traffic across multiple services.

Spins up two tiny real HTTP servers (stdlib http.server) on the loopback
interface to stand in for "multiple independent services" — this exercises
the real urllib/threading path, not a mock.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jscoup.loadtest import format_report, run_load_test


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass  # quiet


class _FlakyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/fail":
            self.send_response(500)
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def two_services():
    server_a = HTTPServer(("127.0.0.1", 0), _OkHandler)
    server_b = HTTPServer(("127.0.0.1", 0), _FlakyHandler)
    thread_a = threading.Thread(target=server_a.serve_forever, daemon=True)
    thread_b = threading.Thread(target=server_b.serve_forever, daemon=True)
    thread_a.start()
    thread_b.start()
    yield server_a, server_b
    server_a.shutdown()
    server_b.shutdown()


def test_run_load_test_hits_multiple_independent_services(two_services):
    server_a, server_b = two_services
    targets = [
        {"base_url": f"http://127.0.0.1:{server_a.server_port}", "path": "/ping", "label": "service-a"},
        {"base_url": f"http://127.0.0.1:{server_b.server_port}", "path": "/ok", "label": "service-b"},
    ]

    result = run_load_test(targets, concurrency=4, duration_seconds=0.5)

    labels = {t["label"] for t in result["targets"]}
    assert labels == {"service-a", "service-b"}
    assert result["total_requests"] > 0
    assert all(t["requests"] > 0 for t in result["targets"])


def test_errors_are_counted_separately_per_target(two_services):
    server_a, server_b = two_services
    targets = [
        {"base_url": f"http://127.0.0.1:{server_a.server_port}", "path": "/ping", "label": "healthy"},
        {"base_url": f"http://127.0.0.1:{server_b.server_port}", "path": "/fail", "label": "flaky"},
    ]

    result = run_load_test(targets, concurrency=2, duration_seconds=0.4)

    by_label = {t["label"]: t for t in result["targets"]}
    assert by_label["healthy"]["errors"] == 0
    assert by_label["flaky"]["errors"] == by_label["flaky"]["requests"]  # every call there 500s


def test_a_dead_target_does_not_stop_traffic_to_the_others(two_services):
    server_a, _ = two_services
    targets = [
        {"base_url": f"http://127.0.0.1:{server_a.server_port}", "path": "/ping", "label": "alive"},
        {"base_url": "http://127.0.0.1:1", "path": "/x", "label": "unreachable"},  # port 1 refuses
    ]

    result = run_load_test(targets, concurrency=4, duration_seconds=0.5)

    by_label = {t["label"]: t for t in result["targets"]}
    assert by_label["alive"]["requests"] > 0
    assert by_label["alive"]["errors"] == 0
    assert by_label["unreachable"]["requests"] > 0
    assert by_label["unreachable"]["errors"] == by_label["unreachable"]["requests"]


def test_run_load_test_requires_at_least_one_target():
    with pytest.raises(ValueError):
        run_load_test([])


def test_format_report_renders_a_readable_table(two_services):
    server_a, _ = two_services
    targets = [{"base_url": f"http://127.0.0.1:{server_a.server_port}", "path": "/ping", "label": "svc"}]

    result = run_load_test(targets, concurrency=2, duration_seconds=0.2)
    report = format_report(result)

    assert "svc" in report
    assert "requests" in report or "reqs" in report
