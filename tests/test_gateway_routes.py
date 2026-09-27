# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Integration tests for the gateway's HTTP surface, through DashboardAPI.handle()
exactly as a real framework integration would call it — admin management routes
(session-gated), the public POST /gw/login, and the independently-authenticated
/gw/... proxy routes."""

from __future__ import annotations

import json

import pytest

from jscoup import JSCoup, MemoryStorage


@pytest.fixture
def _bl(tmp_path, echo_server):
    # Each test gets its own gateway.db and dashboard_sessions.db — both
    # default to a repo-relative path, and every test in this file uses the
    # same username/password (so the same realm), so sharing either default
    # file across tests would leak one test's users/permissions/login-lockout
    # state into the next.
    def make(**overrides):
        return JSCoup(
            "gateway-test", storage=MemoryStorage(), capture_success=False,
            gateway_enabled=True, dashboard_username="admin", dashboard_password="s3cret-pass",
            gateway_db_path=str(tmp_path / "gateway.db"),
            dashboard_session_db_path=str(tmp_path / "dashboard_sessions.db"),
            **{"base_url": echo_server, **overrides},
        )

    return make


def _login_admin(bl):
    response = bl.dashboard.handle(
        "/api/login", method="POST",
        body=json.dumps({"username": "admin", "password": "s3cret-pass"}).encode("utf-8"),
    )
    set_cookie = (response.headers or {}).get("Set-Cookie", "")
    return {"Cookie": set_cookie.split(";", 1)[0]}


PING_ID = "http:POST:/ping"


def _register_ping(bl):
    """An HTTP API the gateway can proxy to (the tests' local echo server)."""
    bl.registry.add_manual("POST", "/ping", name="ping")
    return PING_ID


def _create_gateway_user(bl, admin_session, target_id, username="alice", password="pw", allowed_ips=None):
    payload = {"label": username, "username": username, "password": password, "allowed_target_ids": [target_id]}
    if allowed_ips is not None:
        payload["allowed_ips"] = allowed_ips
    response = bl.dashboard.handle(
        "/api/gateway/users", method="POST", headers=admin_session, body=json.dumps(payload).encode(),
    )
    return json.loads(response.body)


def _gateway_login(bl, username="alice", password="pw", client_ip=None):
    response = bl.dashboard.handle(
        "/gw/login", method="POST",
        body=json.dumps({"username": username, "password": password}).encode(),
        client_ip=client_ip,
    )
    return response


def test_admin_can_create_a_gateway_user(_bl):
    bl = _bl()
    session = _login_admin(bl)

    created = _create_gateway_user(bl, session, PING_ID)

    assert created["user"]["username"] == "alice"
    assert "password" not in created["user"]


def test_creating_a_gateway_user_requires_the_admin_session(_bl):
    bl = _bl()

    response = bl.dashboard.handle(
        "/api/gateway/users", method="POST",
        body=json.dumps({"label": "alice", "username": "alice", "password": "pw",
                          "allowed_target_ids": "*"}).encode(),
    )

    assert response.status == 401


def test_gateway_user_can_log_in_and_receive_a_token_valid_for_one_hour(_bl):
    bl = _bl()
    session = _login_admin(bl)
    _create_gateway_user(bl, session, PING_ID)

    response = _gateway_login(bl)

    assert response.status == 200
    data = json.loads(response.body)
    assert len(data["token"]) > 20
    import time
    assert 0.99 < (data["expires_at"] - time.time()) / 3600 <= 1.0


def test_gateway_login_rejects_wrong_password(_bl):
    bl = _bl()
    session = _login_admin(bl)
    _create_gateway_user(bl, session, PING_ID)

    response = _gateway_login(bl, password="wrong")

    assert response.status == 401


def test_gateway_login_rate_limited_after_repeated_failures(_bl):
    bl = _bl()
    session = _login_admin(bl)
    _create_gateway_user(bl, session, PING_ID)

    for _ in range(5):
        _gateway_login(bl, password="wrong")

    response = _gateway_login(bl, password="wrong")
    assert response.status == 429


def test_gateway_call_succeeds_for_an_allowed_target(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"})

    assert response.status == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["response"]["pong"] is True


def test_gateway_call_rejected_for_a_target_outside_the_allowed_list(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, "service:something-else")
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"})

    assert response.status == 403


def test_gateway_call_without_a_token_is_rejected(_bl):
    bl = _bl()
    target_id = _register_ping(bl)

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST")

    assert response.status == 401


def test_gateway_call_with_a_bad_token_is_rejected(_bl):
    bl = _bl()
    target_id = _register_ping(bl)

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status == 401


def test_gateway_call_denied_from_an_ip_outside_the_users_whitelist(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id, allowed_ips=["10.0.0.0/8"])
    token = json.loads(_gateway_login(bl, client_ip="10.1.2.3").body)["token"]

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"}, client_ip="203.0.113.4",
    )

    assert response.status == 403


def test_gateway_login_denied_from_an_ip_outside_the_whitelist(_bl):
    bl = _bl()
    session = _login_admin(bl)
    _create_gateway_user(bl, session, PING_ID, allowed_ips=["10.0.0.0/8"])

    response = _gateway_login(bl, client_ip="203.0.113.4")

    assert response.status == 401


def test_public_target_needs_no_token_at_all(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        f"/api/gateway/targets/{target_id}/public", method="POST", headers=session,
        body=json.dumps({"public": True}).encode(),
    )

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST")

    assert response.status == 200
    assert json.loads(response.body)["ok"] is True


def test_revoked_user_can_no_longer_call_through_the_gateway(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]
    user_id = created["user"]["id"]

    revoke_response = bl.dashboard.handle(
        f"/api/gateway/users/{user_id}/revoke", method="POST", headers=session,
    )
    assert json.loads(revoke_response.body)["ok"] is True

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"})
    assert response.status == 401


def test_my_logs_only_shows_that_users_own_calls(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id, username="alice")
    _create_gateway_user(bl, session, target_id, username="bob")
    alice_token = json.loads(_gateway_login(bl, username="alice").body)["token"]
    bob_token = json.loads(_gateway_login(bl, username="bob").body)["token"]

    bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {alice_token}"})
    bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {alice_token}"})
    bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {bob_token}"})

    alice_logs = bl.dashboard.handle("/gw/my-logs", headers={"Authorization": f"Bearer {alice_token}"})
    bob_logs = bl.dashboard.handle("/gw/my-logs", headers={"Authorization": f"Bearer {bob_token}"})

    assert len(json.loads(alice_logs.body)["calls"]) == 2
    assert len(json.loads(bob_logs.body)["calls"]) == 1


def test_targets_list_reports_public_flag(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        f"/api/gateway/targets/{target_id}/public", method="POST", headers=session,
        body=json.dumps({"public": True}).encode(),
    )

    targets = json.loads(bl.dashboard.handle("/api/targets", headers=session).body)["targets"]

    hit = next(t for t in targets if t["id"] == target_id)
    assert hit["is_public"] is True


def test_gateway_proxy_ignores_caller_supplied_base_url(_bl):
    """Regression test: when the dashboard is mounted in-app, the per-request
    base_url passed to handle() reflects the *external* Host header (e.g.
    behind Docker port mapping, what the caller outside the container sees)
    — but the gateway's proxied call executes from inside the same process,
    which is not always reachable at that same address. It must always use
    JSCoupConfig.base_url instead, never the caller-supplied one."""
    bl = _bl(base_url="http://127.0.0.1:8000")
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    seen = {}
    real_invoke = bl.simulator.invoke

    def spy(*args, **kwargs):
        seen["base_url"] = kwargs.get("base_url")
        return real_invoke(*args, **kwargs)

    bl.simulator.invoke = spy

    bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"},
        base_url="http://127.0.0.1:8001",  # what an external caller sees — must be ignored
    )

    assert seen["base_url"] == "http://127.0.0.1:8000"


def test_gateway_disabled_by_default_falls_through_to_the_admin_session_gate(tmp_path):
    """With gateway_enabled off (the default), /gw/... isn't special-cased at
    all — it's just another unauthenticated request against a login-
    protected dashboard, so it gets the same 401 anything else would."""
    bl = JSCoup("t", storage=MemoryStorage(), dashboard_username="admin", dashboard_password="x")
    target_id = _register_ping(bl)

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST")

    assert response.status == 401


def test_gateway_rejects_the_wrong_method_before_checking_auth_at_all(_bl):
    """A GET must not be able to trigger a service target the way POST does
    — 'public' or 'no required parameters' never meant 'any HTTP verb is
    fine'. The method check applies even with no token at all, and even to
    a public target: it isn't a credential check being bypassed."""
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle(f"/gw/{target_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status == 405

    bl.dashboard.handle(
        f"/api/gateway/targets/{target_id}/public", method="POST", headers=session,
        body=json.dumps({"public": True}).encode(),
    )
    public_get = bl.dashboard.handle(f"/gw/{target_id}")
    assert public_get.status == 405


def test_gateway_never_echoes_a_raw_exception_message_to_the_caller(_bl):
    """A call that fails inside JSCoup (here: the upstream is unreachable) must
    fail the gateway call safely — the exception's own text is internal
    diagnostic detail, not application response content, and must never reach
    an external caller."""
    bl = _bl(base_url="http://secret-internal-host.invalid:9")
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status == 502
    body_text = response.body.decode()
    assert "secret-internal-host" not in body_text
    assert json.loads(response.body)["ok"] is False


def test_my_logs_is_denied_from_an_ip_outside_the_users_whitelist(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id, allowed_ips=["10.0.0.0/8"])
    token = json.loads(_gateway_login(bl, client_ip="10.1.2.3").body)["token"]

    response = bl.dashboard.handle(
        "/gw/my-logs", headers={"Authorization": f"Bearer {token}"}, client_ip="203.0.113.4",
    )
    assert response.status == 403


def test_admin_can_reset_a_gateway_users_password(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    user_id = created["user"]["id"]
    old_token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle(
        f"/api/gateway/users/{user_id}/reset-password", method="POST", headers=session,
        body=json.dumps({"password": "brand-new-pw"}).encode(),
    )

    assert response.status == 200
    assert json.loads(response.body)["ok"] is True
    # old session and old password both stop working
    stale = bl.dashboard.handle(f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {old_token}"})
    assert stale.status == 401
    assert _gateway_login(bl).status == 401
    assert _gateway_login(bl, password="brand-new-pw").status == 200


def test_reset_password_rejects_a_short_password(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    user_id = created["user"]["id"]

    response = bl.dashboard.handle(
        f"/api/gateway/users/{user_id}/reset-password", method="POST", headers=session,
        body=json.dumps({"password": "short"}).encode(),
    )

    assert response.status == 400


def test_reset_password_requires_the_admin_session(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    user_id = created["user"]["id"]

    response = bl.dashboard.handle(
        f"/api/gateway/users/{user_id}/reset-password", method="POST",
        body=json.dumps({"password": "brand-new-pw"}).encode(),
    )

    assert response.status == 401


def test_admin_can_edit_a_gateway_users_allowed_apis_and_ips(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, "service:something-else")
    user_id = created["user"]["id"]

    response = bl.dashboard.handle(
        f"/api/gateway/users/{user_id}", method="PUT", headers=session,
        body=json.dumps({"allowed_target_ids": [target_id], "allowed_ips": ["203.0.113.4"]}).encode(),
    )
    assert response.status == 200
    assert json.loads(response.body)["ok"] is True

    token = json.loads(_gateway_login(bl, client_ip="203.0.113.4").body)["token"]
    call = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"}, client_ip="203.0.113.4",
    )
    assert call.status == 200
    denied_ip = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"}, client_ip="198.51.100.1",
    )
    assert denied_ip.status == 403


def test_admin_can_revoke_then_restore_a_gateway_user(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    user_id = created["user"]["id"]

    bl.dashboard.handle(f"/api/gateway/users/{user_id}/revoke", method="POST", headers=session)
    assert _gateway_login(bl).status == 401

    restore_response = bl.dashboard.handle(f"/api/gateway/users/{user_id}/restore", method="POST", headers=session)
    assert json.loads(restore_response.body)["ok"] is True
    assert _gateway_login(bl).status == 200


def test_admin_can_permanently_delete_a_gateway_user(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    created = _create_gateway_user(bl, session, target_id)
    user_id = created["user"]["id"]

    response = bl.dashboard.handle(f"/api/gateway/users/{user_id}", method="DELETE", headers=session)

    assert response.status == 200
    assert json.loads(response.body)["ok"] is True
    users = json.loads(bl.dashboard.handle("/api/gateway/users", headers=session).body)["users"]
    assert users == []


def test_admin_can_add_and_disable_a_manual_target(_bl):
    bl = _bl()
    session = _login_admin(bl)

    add_response = bl.dashboard.handle(
        "/api/targets", method="POST", headers=session,
        body=json.dumps({"method": "GET", "path": "/partner/orders", "description": "Partner feed"}).encode(),
    )
    assert add_response.status == 200
    target = json.loads(add_response.body)["target"]
    assert target["id"] == "http:GET:/partner/orders"

    listed = json.loads(bl.dashboard.handle("/api/targets", headers=session).body)["targets"]
    assert any(t["id"] == target["id"] for t in listed)

    disable_response = bl.dashboard.handle(f"/api/targets/{target['id']}", method="DELETE", headers=session)
    assert json.loads(disable_response.body)["ok"] is True
    listed_after = json.loads(bl.dashboard.handle("/api/targets", headers=session).body)["targets"]
    assert not any(t["id"] == target["id"] for t in listed_after)
    # still visible to the admin's own catalogue view, so it can be restored
    catalogue = json.loads(
        bl.dashboard.handle("/api/targets", headers=session, query={"include_disabled": "1"}).body
    )["targets"]
    hidden = next(t for t in catalogue if t["id"] == target["id"])
    assert hidden["disabled"] is True

    enable_response = bl.dashboard.handle(f"/api/targets/{target['id']}/enable", method="POST", headers=session)
    assert json.loads(enable_response.body)["ok"] is True
    listed_again = json.loads(bl.dashboard.handle("/api/targets", headers=session).body)["targets"]
    assert any(t["id"] == target["id"] for t in listed_again)


def test_disabled_target_is_unreachable_through_the_gateway(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    bl.dashboard.handle(f"/api/targets/{target_id}", method="DELETE", headers=session)

    response = bl.dashboard.handle(
        f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"})
    assert response.status == 404


def test_managing_targets_requires_the_admin_session(_bl):
    bl = _bl()

    response = bl.dashboard.handle(
        "/api/targets", method="POST",
        body=json.dumps({"method": "GET", "path": "/x"}).encode(),
    )

    assert response.status == 401


def test_manual_targets_and_disabled_state_are_shared_across_worker_processes(tmp_path):
    """Regression test for a real bug found running this against gunicorn
    -w 2: Registry's manual-target and disabled-target state is plain
    in-memory, so a naive implementation only affects whichever worker
    process handled that one admin request — the next request, landing on
    a different worker, would not see it. Two separate JSCoup instances
    sharing one gateway_db_path stand in for two worker processes."""
    gateway_db = str(tmp_path / "gateway.db")
    session_db = str(tmp_path / "dashboard_sessions.db")

    def make():
        return JSCoup(
            "t", storage=MemoryStorage(), capture_success=False, gateway_enabled=True,
            dashboard_username="admin", dashboard_password="s3cret-pass", gateway_db_path=gateway_db,
            dashboard_session_db_path=session_db,
        )

    worker_a = make()
    worker_b = make()
    session_a = _login_admin(worker_a)
    session_b = _login_admin(worker_b)

    add_response = worker_a.dashboard.handle(
        "/api/targets", method="POST", headers=session_a,
        body=json.dumps({"method": "GET", "path": "/partner/orders"}).encode(),
    )
    target_id = json.loads(add_response.body)["target"]["id"]

    # worker_b never saw that POST — its own refresh_targets() (run inside
    # handle()) must still pick it up from the shared gateway database.
    listed_b = json.loads(worker_b.dashboard.handle("/api/targets", headers=session_b).body)["targets"]
    assert any(t["id"] == target_id for t in listed_b)

    disable_response = worker_b.dashboard.handle(f"/api/targets/{target_id}", method="DELETE", headers=session_b)
    assert json.loads(disable_response.body)["ok"] is True

    # worker_a never saw that DELETE either.
    listed_a = json.loads(worker_a.dashboard.handle("/api/targets", headers=session_a).body)["targets"]
    assert not any(t["id"] == target_id for t in listed_a)


def test_caller_supplied_downstream_token_overrides_the_users_configured_one(_bl):
    from jscoup.crypto import generate_key
    bl = _bl(encryption_key=generate_key())
    seen = {}

    target_id = bl.registry.add_manual("POST", "/needs-token", name="needs-token").id
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/gateway/users", method="POST", headers=session,
        body=json.dumps({
            "label": "alice", "username": "alice", "password": "pw",
            "allowed_target_ids": [target_id], "downstream_token": "admin-configured-token",
        }).encode(),
    )
    token = json.loads(_gateway_login(bl).body)["token"]

    real_invoke = bl.simulator.invoke

    def spy(*args, **kwargs):
        seen["token"] = kwargs.get("token")
        return real_invoke(*args, **kwargs)

    bl.simulator.invoke = spy

    bl.dashboard.handle(
        f"/gw/{target_id}", method="POST",
        headers={"Authorization": f"Bearer {token}", "X-Downstream-Token": "caller-supplied-token"},
    )

    assert seen["token"] == "caller-supplied-token"


def test_downstream_token_falls_back_to_the_users_configured_one_when_not_supplied(_bl):
    from jscoup.crypto import generate_key
    bl = _bl(encryption_key=generate_key())
    seen = {}

    target_id = bl.registry.add_manual("POST", "/needs-token", name="needs-token").id
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/gateway/users", method="POST", headers=session,
        body=json.dumps({
            "label": "alice", "username": "alice", "password": "pw",
            "allowed_target_ids": [target_id], "downstream_token": "admin-configured-token",
        }).encode(),
    )
    token = json.loads(_gateway_login(bl).body)["token"]

    real_invoke = bl.simulator.invoke

    def spy(*args, **kwargs):
        seen["token"] = kwargs.get("token")
        return real_invoke(*args, **kwargs)

    bl.simulator.invoke = spy

    bl.dashboard.handle(f"/gw/{target_id}", method="POST", headers={"Authorization": f"Bearer {token}"})

    assert seen["token"] == "admin-configured-token"


def test_my_targets_returns_only_the_users_allowed_apis(_bl):
    bl = _bl()
    allowed_id = _register_ping(bl)

    @bl.watch(kind="service", name="secret")
    def secret():
        return {"nope": True}

    session = _login_admin(bl)
    _create_gateway_user(bl, session, allowed_id)
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle("/gw/my-targets", headers={"Authorization": f"Bearer {token}"})

    assert response.status == 200
    data = json.loads(response.body)
    ids = {t["id"] for t in data["targets"]}
    assert ids == {allowed_id}
    assert data["user"]["username"] == "alice"


def test_my_targets_wildcard_user_sees_every_api(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/gateway/users", method="POST", headers=session,
        body=json.dumps({
            "label": "alice", "username": "alice", "password": "pw", "allowed_target_ids": "*",
        }).encode(),
    )
    token = json.loads(_gateway_login(bl).body)["token"]

    response = bl.dashboard.handle("/gw/my-targets", headers={"Authorization": f"Bearer {token}"})

    ids = {t["id"] for t in json.loads(response.body)["targets"]}
    assert target_id in ids


def test_my_targets_requires_a_valid_gateway_token(_bl):
    bl = _bl()
    _register_ping(bl)

    response = bl.dashboard.handle("/gw/my-targets", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status == 401


def test_my_targets_denied_from_an_ip_outside_the_users_whitelist(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    _create_gateway_user(bl, session, target_id, allowed_ips=["10.0.0.0/8"])
    token = json.loads(_gateway_login(bl, client_ip="10.1.2.3").body)["token"]

    response = bl.dashboard.handle(
        "/gw/my-targets", headers={"Authorization": f"Bearer {token}"}, client_ip="203.0.113.4",
    )
    assert response.status == 403


def test_whoami_reports_the_callers_client_ip(_bl):
    bl = _bl()
    session = _login_admin(bl)

    response = bl.dashboard.handle("/api/whoami", headers=session, client_ip="203.0.113.9")

    assert response.status == 200
    assert json.loads(response.body)["ip"] == "203.0.113.9"


def test_admin_can_set_a_targets_description(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)

    response = bl.dashboard.handle(
        f"/api/targets/{target_id}/description", method="PUT", headers=session,
        body=json.dumps({"description": "Health-checks the service"}).encode(),
    )
    assert json.loads(response.body)["ok"] is True

    targets = json.loads(bl.dashboard.handle("/api/targets", headers=session).body)["targets"]
    updated = next(t for t in targets if t["id"] == target_id)
    assert updated["description"] == "Health-checks the service"


def test_setting_a_targets_description_requires_the_admin_session(_bl):
    bl = _bl()
    target_id = _register_ping(bl)

    response = bl.dashboard.handle(
        f"/api/targets/{target_id}/description", method="PUT",
        body=json.dumps({"description": "sneaky"}).encode(),
    )

    assert response.status == 401


def test_target_descriptions_are_shared_across_worker_processes(tmp_path):
    gateway_db = str(tmp_path / "gateway.db")
    session_db = str(tmp_path / "dashboard_sessions.db")

    def make():
        return JSCoup(
            "t", storage=MemoryStorage(), capture_success=False, gateway_enabled=True,
            dashboard_username="admin", dashboard_password="s3cret-pass", gateway_db_path=gateway_db,
            dashboard_session_db_path=session_db,
        )

    worker_a = make()
    worker_b = make()
    session_a = _login_admin(worker_a)
    target_id = _register_ping(worker_a)
    worker_b.registry.add_manual("POST", "/ping", name="ping")

    worker_a.dashboard.handle(f"/api/gateway/targets/{target_id}/public", method="POST", headers=session_a,
                               body=json.dumps({"public": True}).encode())
    worker_a.dashboard.handle(f"/api/targets/{target_id}/description", method="PUT", headers=session_a,
                               body=json.dumps({"description": "Set by worker A"}).encode())

    data = json.loads(worker_b.dashboard.handle("/api/targets", method="GET", headers=session_a).body)
    listed = next(t for t in data["targets"] if t["id"] == target_id)
    assert listed["description"] == "Set by worker A"


# --------------------------------------------------------------------------- #
# public API-doc groups
# --------------------------------------------------------------------------- #

def test_admin_can_publish_a_doc_group(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)

    response = bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "partners", "title": "Partner APIs", "target_ids": [target_id]}).encode(),
    )
    assert response.status == 200
    group = json.loads(response.body)["group"]
    assert group["slug"] == "partners"
    assert group["allowed_ips"] is None

    listed = json.loads(bl.dashboard.handle("/api/doc-groups", headers=session).body)["groups"]
    assert any(g["slug"] == "partners" for g in listed)


def test_publishing_a_doc_group_requires_the_admin_session(_bl):
    bl = _bl()
    target_id = _register_ping(bl)

    response = bl.dashboard.handle(
        "/api/doc-groups", method="POST",
        body=json.dumps({"slug": "partners", "title": "x", "target_ids": [target_id]}).encode(),
    )

    assert response.status == 401


def test_publishing_a_doc_group_rejects_a_reserved_slug(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)

    response = bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "gw", "title": "x", "target_ids": [target_id]}).encode(),
    )

    assert response.status == 400


def test_doc_group_page_and_data_are_reachable_with_no_login_at_all(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "partners", "title": "Partner APIs", "target_ids": [target_id]}).encode(),
    )

    page = bl.dashboard.handle("/partners", method="GET")
    data = json.loads(bl.dashboard.handle("/partners/data", method="GET").body)

    assert page.status == 200
    assert "text/html" in page.content_type
    assert [t["id"] for t in data["targets"]] == [target_id]
    assert data["title"] == "Partner APIs"


def test_doc_group_lists_exactly_its_chosen_targets_not_every_public_one(_bl):
    """A group is a fixed, admin-curated menu — unrelated to
    which targets are separately marked public/global-docs-visible."""
    bl = _bl()
    ping_id = _register_ping(bl)

    other_id = bl.registry.add_manual("GET", "/other", name="other").id

    session = _login_admin(bl)
    bl.dashboard.handle(f"/api/gateway/targets/{ping_id}/public", method="POST", headers=session,
                         body=json.dumps({"public": True}).encode())
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "just-other", "title": "Just other", "target_ids": [other_id]}).encode(),
    )

    data = json.loads(bl.dashboard.handle("/just-other/data", method="GET").body)

    assert [t["id"] for t in data["targets"]] == [other_id]


def test_doc_group_denied_from_an_ip_outside_its_own_allow_list(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({
            "slug": "partners", "title": "Partner APIs", "target_ids": [target_id],
            "allowed_ips": ["10.0.0.0/8"],
        }).encode(),
    )

    denied = bl.dashboard.handle("/partners", method="GET", client_ip="203.0.113.4")
    allowed = bl.dashboard.handle("/partners", method="GET", client_ip="10.1.2.3")

    assert denied.status == 403
    assert allowed.status == 200


def test_doc_group_open_to_everyone_ignores_the_admin_dashboards_own_ip_allowlist(tmp_path):
    """The whole point of a public group is to be reachable without regard
    to dashboard_allowed_ips — an admin might lock the dashboard itself to
    an office network while still wanting this page open to the internet."""
    bl = JSCoup(
        "t", storage=MemoryStorage(), capture_success=False, gateway_enabled=True,
        dashboard_username="admin", dashboard_password="s3cret-pass",
        dashboard_allowed_ips=["10.0.0.0/8"],
        gateway_db_path=str(tmp_path / "gateway.db"),
        dashboard_session_db_path=str(tmp_path / "dashboard_sessions.db"),
    )
    target_id = _register_ping(bl)
    session = bl.dashboard.handle(
        "/api/login", method="POST", client_ip="10.1.2.3",
        body=json.dumps({"username": "admin", "password": "s3cret-pass"}).encode(),
    )
    cookie = {"Cookie": session.headers.get("Set-Cookie", "").split(";", 1)[0]}
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=cookie, client_ip="10.1.2.3",
        body=json.dumps({"slug": "partners", "title": "Partner APIs", "target_ids": [target_id]}).encode(),
    )

    response = bl.dashboard.handle("/partners", method="GET", client_ip="203.0.113.4")

    assert response.status == 200


def test_admin_can_update_a_doc_groups_title_and_targets(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "partners", "title": "Old title", "target_ids": [target_id]}).encode(),
    )

    response = bl.dashboard.handle(
        "/api/doc-groups/partners", method="PUT", headers=session,
        body=json.dumps({"title": "New title"}).encode(),
    )

    assert json.loads(response.body)["group"]["title"] == "New title"


def test_admin_can_delete_a_doc_group(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({"slug": "partners", "title": "Partner APIs", "target_ids": [target_id]}).encode(),
    )

    delete_response = bl.dashboard.handle("/api/doc-groups/partners", method="DELETE", headers=session)
    assert json.loads(delete_response.body)["ok"] is True

    # No longer a recognized public group, so it falls through to the normal
    # admin-gated dashboard flow, which requires a session for any path.
    after = bl.dashboard.handle("/partners", method="GET")
    assert after.status == 401


def test_doc_group_with_a_category_override_is_reflected_in_its_public_data(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({
            "slug": "partners", "title": "Partner APIs", "target_ids": [target_id],
            "categories": {target_id: "billing"},
        }).encode(),
    )

    data = json.loads(bl.dashboard.handle("/partners/data", method="GET").body)

    assert data["targets"][0]["category"] == "billing"


def test_admin_can_change_a_doc_groups_category_override(_bl):
    bl = _bl()
    target_id = _register_ping(bl)
    session = _login_admin(bl)
    bl.dashboard.handle(
        "/api/doc-groups", method="POST", headers=session,
        body=json.dumps({
            "slug": "partners", "title": "Partner APIs", "target_ids": [target_id],
            "categories": {target_id: "billing"},
        }).encode(),
    )

    bl.dashboard.handle(
        "/api/doc-groups/partners", method="PUT", headers=session,
        body=json.dumps({"categories": {target_id: "internal"}}).encode(),
    )

    data = json.loads(bl.dashboard.handle("/partners/data", method="GET").body)
    assert data["targets"][0]["category"] == "internal"



def test_private_user_categories_are_stored_edited_and_shown_to_that_user(_bl):
    bl = _bl()
    session = _login_admin(bl)
    target_id = _register_ping(bl)
    payload = {"label": "bob", "username": "bob", "password": "pw", "allowed_target_ids": [target_id],
               "categories": {target_id: "Partner tools", "x": "  "}}
    created = json.loads(bl.dashboard.handle(
        "/api/gateway/users", method="POST", headers=session, body=json.dumps(payload).encode()).body)
    assert created["user"]["categories"] == {target_id: "Partner tools"}

    token = json.loads(_gateway_login(bl, "bob", "pw").body)["token"]
    mine = json.loads(bl.dashboard.handle(
        "/gw/my-targets", headers={"Authorization": f"Bearer {token}"}).body)
    assert mine["targets"][0]["category"] == "Partner tools"

    uid = created["user"]["id"]
    bl.dashboard.handle(f"/api/gateway/users/{uid}", method="PUT", headers=session,
                        body=json.dumps({"categories": {target_id: "Renamed"}}).encode())
    listed = json.loads(bl.dashboard.handle("/api/gateway/users", headers=session).body)["users"]
    assert listed[0]["categories"] == {target_id: "Renamed"}
