# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for the dashboard's login: password hashing, sessions, rate limiting,
and the DashboardAPI login/logout/session-gated routing built on top of them.
"""

from __future__ import annotations

import json
import re

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.dashboard import auth


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """dashboard_session_db_path defaults to a relative path
    (".jscoup/dashboard_sessions.db"), shared by every JSCoup(...) call in
    this file that doesn't override it — including, now that login-attempt
    tracking lives in that same SQLite file (see sessions.py), the failed-
    login counter. Without this, test_dashboard_login_locks_out_after_max_
    attempts's deliberate lockout leaked into later tests using the same
    default username/password, since they hash to the same realm. Running
    each test from its own throwaway directory isolates every relative
    default path this module's tests rely on, not just this one."""
    monkeypatch.chdir(tmp_path)


# --------------------------------------------------------------------------- #
# password hashing
# --------------------------------------------------------------------------- #


def test_hash_password_roundtrip():
    encoded = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", encoded)
    assert not auth.verify_password("wrong password", encoded)


def test_hash_password_uses_a_random_salt():
    a = auth.hash_password("same-password")
    b = auth.hash_password("same-password")
    assert a != b  # different salts -> different encodings even for the same input


def test_verify_password_rejects_garbage_hash():
    assert not auth.verify_password("anything", "not-a-valid-hash")
    assert not auth.verify_password("anything", None)


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #


def test_sign_and_verify_session():
    token = auth.sign_session("admin", "secret-key", ttl_seconds=3600)
    assert auth.verify_session(token, "secret-key") == "admin"


def test_verify_session_rejects_wrong_secret():
    token = auth.sign_session("admin", "secret-key", ttl_seconds=3600)
    assert auth.verify_session(token, "a-different-key") is None


def test_verify_session_rejects_tampered_payload():
    token = auth.sign_session("admin", "secret-key", ttl_seconds=3600)
    payload, _, signature = token.partition(".")
    tampered = payload + "x." + signature
    assert auth.verify_session(tampered, "secret-key") is None


def test_verify_session_rejects_expired_token():
    token = auth.sign_session("admin", "secret-key", ttl_seconds=-1)
    assert auth.verify_session(token, "secret-key") is None


def test_verify_session_rejects_malformed_input():
    assert auth.verify_session(None, "secret-key") is None
    assert auth.verify_session("", "secret-key") is None
    assert auth.verify_session("no-dot-in-here", "secret-key") is None


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #


def test_login_lockout_after_repeated_failures():
    store: auth.AttemptStore = {}
    assert not auth.is_locked(store, "admin")
    auth.record_failure(store, "admin", max_attempts=3, lockout_seconds=60)
    auth.record_failure(store, "admin", max_attempts=3, lockout_seconds=60)
    assert not auth.is_locked(store, "admin")
    auth.record_failure(store, "admin", max_attempts=3, lockout_seconds=60)
    assert auth.is_locked(store, "admin")
    auth.clear_failures(store, "admin")
    assert not auth.is_locked(store, "admin")


def test_build_set_cookie_header():
    set_cookie = auth.build_set_cookie_header("jscoup_session", "abc", max_age=3600)
    assert "jscoup_session=abc" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Max-Age=3600" in set_cookie
    assert "Secure" not in set_cookie

    cleared = auth.build_set_cookie_header("jscoup_session", "", max_age=None, secure=True)
    assert "Max-Age=0" in cleared
    assert "Secure" in cleared


# --------------------------------------------------------------------------- #
# DashboardAPI wiring
# --------------------------------------------------------------------------- #


def _login_dashboard(bl, username="admin", password="s3cret-pass"):
    response = bl.dashboard.handle(
        "/api/login", method="POST",
        body=json.dumps({"username": username, "password": password}).encode("utf-8"),
    )
    return response


def _cookie_header(response):
    set_cookie = (response.headers or {}).get("Set-Cookie", "")
    return {"Cookie": set_cookie.split(";", 1)[0]}


def test_dashboard_login_success_sets_cookie_and_grants_access():
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass"
    )
    response = _login_dashboard(bl)
    assert response.status == 200
    body = json.loads(response.body)
    assert body["ok"] is True
    assert "Set-Cookie" in (response.headers or {})

    session = _cookie_header(response)
    assert bl.dashboard.handle("/api/health", headers=session).status == 200


def test_dashboard_rejects_wrong_password():
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass"
    )
    response = _login_dashboard(bl, password="wrong")
    assert response.status == 401
    assert "Set-Cookie" not in (response.headers or {})


def test_dashboard_rejects_wrong_username():
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass"
    )
    response = _login_dashboard(bl, username="not-admin")
    assert response.status == 401


def test_dashboard_page_stays_open_but_api_requires_login():
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass"
    )
    page = bl.dashboard.handle("/")
    assert page.status == 200
    assert b"JSCoup" in page.body

    blocked = bl.dashboard.handle("/api/health")
    assert blocked.status == 401
    assert json.loads(blocked.body)["login_required"] is True


def test_dashboard_logout_returns_a_clearing_cookie():
    bl = JSCoup(
        "t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="s3cret-pass"
    )
    session = _cookie_header(_login_dashboard(bl))
    response = bl.dashboard.handle("/api/logout", method="POST", headers=session)
    assert response.status == 200
    assert "Max-Age=0" in response.headers["Set-Cookie"]


def test_dashboard_login_locks_out_after_max_attempts():
    bl = JSCoup(
        "t", storage=MemoryStorage(),
        dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_login_max_attempts=2, dashboard_login_lockout_seconds=60,
    )
    assert _login_dashboard(bl, password="wrong").status == 401
    assert _login_dashboard(bl, password="wrong").status == 401
    # third attempt is locked out even with the CORRECT password
    locked = _login_dashboard(bl, password="s3cret-pass")
    assert locked.status == 429


def test_dashboard_password_hash_can_be_set_directly():
    """Covers the documented alternative to JSCoup(dashboard_password=...): setting
    an already-hashed value, e.g. sourced from a secrets manager."""
    bl = JSCoup(
        "t", storage=MemoryStorage(),
        dashboard_username="admin", dashboard_password_hash=auth.hash_password("from-a-vault"),
    )
    assert _login_dashboard(bl, password="from-a-vault").status == 200


def test_legacy_dashboard_token_is_unaffected_by_login_support():
    """When no dashboard_username is configured, the original shared-token gate
    must behave exactly as it always has."""
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_token="s3cret")
    assert bl.dashboard.handle("/api/health").status == 401
    assert bl.dashboard.handle("/api/health", query={"token": "s3cret"}).status == 401
    assert bl.dashboard.handle("/api/health", headers={"X-JSCoup-Token": "s3cret"}).status == 200
    assert bl.dashboard.handle("/api/health", headers={"X-JSCoup-Token": "s3cret"}).status == 200


def test_dashboard_requires_login_by_default_when_no_auth_configured(capsys):
    """A bare JSCoup(...) with nothing else set must never be a wide-open
    admin panel: no username/token/local-dev opt-out configured means an
    "admin" login is generated automatically instead of leaving it open."""
    bl = JSCoup("t", storage=MemoryStorage())
    assert bl.config.dashboard_username == "admin"
    assert bl.dashboard.handle("/api/health").status == 401
    assert bl.dashboard.handle("/api/targets").status == 401

    printed = capsys.readouterr().out
    match = re.search(r"generated one: (\S+)", printed)
    assert match, printed
    assert _login_dashboard(bl, password=match.group(1)).status == 200


def test_dashboard_local_dev_keeps_the_old_fully_open_behavior():
    """The explicit opt-out for a throwaway local run with no credentials."""
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    assert bl.config.dashboard_username is None
    assert bl.dashboard.handle("/api/health").status == 200
    assert bl.dashboard.handle("/api/targets").status == 200


def test_dashboard_username_alone_generates_a_working_password(capsys):
    """JSCoup(dashboard_username=...) with no password must still produce a
    working login — not a dashboard that's configured but unreachable."""
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_username="admin")
    assert bl.config.dashboard_password_hash is not None

    printed = capsys.readouterr().out
    assert "generated" in printed.lower()
    match = re.search(r"generated one: (\S+)", printed)
    assert match, printed
    generated_password = match.group(1)

    response = _login_dashboard(bl, password=generated_password)
    assert response.status == 200


def test_dashboard_explicit_password_suppresses_generation(capsys):
    JSCoup("t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="mypassword")
    printed = capsys.readouterr().out
    assert "generated" not in printed.lower()


# --------------------------------------------------------------------------- #
# IP allowlist
# --------------------------------------------------------------------------- #


def test_ip_allowed_open_when_unrestricted():
    assert auth.ip_allowed("203.0.113.4", None) is True
    assert auth.ip_allowed("203.0.113.4", []) is True


def test_ip_allowed_exact_match():
    assert auth.ip_allowed("203.0.113.4", ["203.0.113.4"]) is True
    assert auth.ip_allowed("203.0.113.5", ["203.0.113.4"]) is False


def test_ip_allowed_cidr_match():
    assert auth.ip_allowed("10.0.5.9", ["10.0.0.0/8"]) is True
    assert auth.ip_allowed("192.168.1.1", ["10.0.0.0/8"]) is False


def test_ip_allowed_handles_forwarded_for_multi_hop():
    assert auth.ip_allowed("203.0.113.4, 10.0.0.1", ["203.0.113.4"]) is True


def test_ip_allowed_rejects_missing_or_garbage_ip():
    assert auth.ip_allowed(None, ["203.0.113.4"]) is False
    assert auth.ip_allowed("not-an-ip", ["203.0.113.4"]) is False


def test_ip_allowed_ignores_unparseable_allowlist_entries():
    # A typo'd entry must not crash the check for everyone else.
    assert auth.ip_allowed("203.0.113.4", ["not-an-ip-or-cidr", "203.0.113.4"]) is True


def test_dashboard_denies_disallowed_ip_before_login():
    bl = JSCoup(
        "t", storage=MemoryStorage(),
        dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_allowed_ips=["10.0.0.0/8"],
    )
    denied = bl.dashboard.handle("/api/login", method="POST", client_ip="203.0.113.4")
    assert denied.status == 403

    # even the page shell (normally always open) is denied for a bad IP
    denied_page = bl.dashboard.handle("/", client_ip="203.0.113.4")
    assert denied_page.status == 403


def test_dashboard_allows_matching_ip():
    bl = JSCoup(
        "t", storage=MemoryStorage(),
        dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_allowed_ips=["10.0.0.0/8"],
    )
    response = _login_dashboard(bl, password="s3cret-pass")
    # no client_ip passed at all should also be treated as not allowed —
    # this call is the "outside the allowed range" case since default is None
    assert response.status == 403

    allowed = bl.dashboard.handle(
        "/api/login", method="POST", client_ip="10.1.2.3",
        body=json.dumps({"username": "admin", "password": "s3cret-pass"}).encode("utf-8"),
    )
    assert allowed.status == 200


def test_dashboard_ip_allowlist_does_not_affect_unrestricted_instance():
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_local_dev=True)
    assert bl.dashboard.handle("/api/health", client_ip="203.0.113.4").status == 200
    assert bl.dashboard.handle("/api/health").status == 200
