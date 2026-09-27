# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for the "check every API at once" sweep (jscoup.healthcheck)."""

from __future__ import annotations

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.healthcheck import ApiCheckResult
from jscoup.registry import ParamSpec, Target


@pytest.fixture
def _bl(echo_server):
    """A JSCoup whose ``base_url`` is the tests' local echo API."""
    return lambda: JSCoup("t", storage=MemoryStorage(), capture_success=False, base_url=echo_server)


def _api(bl, path, method="GET", allowed=False, params=()):
    return bl.registry.add(Target(
        id=f"http:{method}:{path}", kind="http", name=path.strip("/"), method=method, path=path,
        params=list(params), healthcheck_allowed=allowed,
    ))


def test_api_check_result_to_dict():
    result = ApiCheckResult(
        target_id="service:x", kind="service", method="CALL", path="x", ok=True, status_code=200
    )
    data = result.to_dict()
    assert data["ok"] is True
    assert data["status_code"] == 200
    assert data["skipped_reason"] is None


def test_check_apis_skips_an_api_by_default(_bl):
    """'No required parameters' is not the same claim as 'safe to run
    unattended' — a parameterless endpoint can still delete something.
    Nothing gets swept unless explicitly opted in."""
    bl = _bl()
    _api(bl, "/ping")

    hit = next(r for r in bl.check_apis() if r.target_id == "http:GET:/ping")
    assert hit.ok is None
    assert hit.skipped_reason == "not marked healthcheck_allowed"


def test_check_apis_calls_a_parameterless_api_marked_healthcheck_allowed(_bl):
    bl = _bl()
    _api(bl, "/ping", allowed=True)

    hit = next(r for r in bl.check_apis() if r.target_id == "http:GET:/ping")
    assert hit.ok is True
    assert hit.skipped_reason is None
    assert "pong" in (hit.response_preview or "")


def test_check_apis_skips_apis_that_need_parameters(_bl):
    bl = _bl()
    _api(bl, "/items/{item_id}", allowed=True, params=[ParamSpec(name="item_id", location="path", required=True)])

    hit = next(r for r in bl.check_apis() if r.target_id == "http:GET:/items/{item_id}")
    assert hit.ok is None
    assert "item_id" in (hit.skipped_reason or "")


def test_check_apis_reports_a_failing_api(_bl):
    """Middleware sees only the HTTP response, so a 500 is reported with its
    status and body; a server-side diagnosis exists only when the app itself
    runs JSCoup and records its own exception."""
    bl = _bl()
    _api(bl, "/boom", allowed=True)

    hit = next(r for r in bl.check_apis() if r.target_id == "http:GET:/boom")
    assert hit.ok is False
    assert hit.status_code == 500
    assert "boom" in (hit.response_preview or "")


def test_check_apis_one_broken_target_does_not_abort_the_sweep(_bl):
    bl = _bl()
    _api(bl, "/boom", allowed=True)
    _api(bl, "/ping", allowed=True)

    ids = {r.target_id: r for r in bl.check_apis()}
    assert ids["http:GET:/boom"].ok is False
    assert ids["http:GET:/ping"].ok is True


def test_check_apis_returns_empty_list_with_no_targets(_bl):
    assert _bl().check_apis() == []


def test_describe_can_mark_an_http_target_healthcheck_allowed(_bl):
    bl = _bl()
    _api(bl, "/ping")

    bl.describe(method="GET", path="/ping", healthcheck_allowed=True)

    hit = next(r for r in bl.check_apis() if r.target_id == "http:GET:/ping")
    assert hit.ok is True


def test_check_apis_never_runs_a_python_function(_bl):
    """JSCoup only calls APIs over HTTP: a registered function is listed as
    skipped, never executed."""
    bl = _bl()
    ran = []
    bl.registry.register_callable(lambda: ran.append(1), name="job", healthcheck_allowed=True)

    hit = next(r for r in bl.check_apis() if r.target_id == "service:job")
    assert hit.ok is None
    assert hit.skipped_reason == "not an HTTP API"
    assert ran == []
