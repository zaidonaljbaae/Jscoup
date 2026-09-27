# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Which APIs a gateway caller may reach without a gateway token, and what happens
to a bearer token on those calls.

* An admin can mark an API public (always supported).
* ``gateway_open_tokenless_apis`` (opt-in) additionally opens every API that
  needs no token of its own -- and never one that does.
* On an open API nobody is authenticated by the gateway, so a bearer token on the
  call is the API's own token and is forwarded downstream; on a gated API the
  bearer is the gateway token and must never be forwarded.
"""

from __future__ import annotations

import json

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.registry import Target


@pytest.fixture
def make(tmp_path, echo_server):
    def build(**overrides):
        return JSCoup(
            "open-apis", storage=MemoryStorage(), capture_success=False,
            gateway_enabled=True, dashboard_username="admin", dashboard_password="s3cret-pass",
            gateway_db_path=str(tmp_path / "gateway.db"),
            dashboard_session_db_path=str(tmp_path / "dashboard_sessions.db"),
            **{"base_url": echo_server, **overrides},
        )

    return build


def _add(bl, path, *, requires_auth):
    target = Target(id=f"http:POST:{path}", kind="http", name=path, method="POST", path=path,
                    requires_auth=requires_auth, framework="manual")
    bl.registry.add(target)
    return target.id


def _call(bl, target_id, bearer=None):
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    response = bl.dashboard.handle(f"/gw/{target_id}", method="POST", headers=headers)
    return response.status, json.loads(response.body)


def test_tokenless_api_needs_a_gateway_token_by_default(make):
    bl = make()
    target_id = _add(bl, "/echo/login", requires_auth=False)

    status, body = _call(bl, target_id)

    assert status == 401
    assert "gateway token" in body["error"]


def test_tokenless_api_is_open_when_the_setting_is_on(make):
    bl = make(gateway_open_tokenless_apis=True)
    target_id = _add(bl, "/echo/login", requires_auth=False)

    status, body = _call(bl, target_id)

    assert status == 200
    assert body["ok"] is True
    assert body["response"]["path"] == "/echo/login"


def test_the_setting_never_opens_an_api_that_needs_a_token(make):
    bl = make(gateway_open_tokenless_apis=True)
    target_id = _add(bl, "/echo/secret", requires_auth=True)

    status, _ = _call(bl, target_id)

    assert status == 401


def test_an_admin_marked_public_api_is_open_even_with_the_setting_off(make):
    bl = make()
    target_id = _add(bl, "/echo/secret", requires_auth=True)
    bl.gateway.set_public(target_id, True)

    status, _ = _call(bl, target_id)

    assert status == 200


def test_bearer_token_on_an_open_api_is_forwarded_as_the_apis_own_token(make):
    bl = make()
    target_id = _add(bl, "/echo/secret", requires_auth=True)
    bl.gateway.set_public(target_id, True)

    status, body = _call(bl, target_id, bearer="my-own-api-token")

    assert status == 200
    assert body["response"]["credential_header"] == "Bearer my-own-api-token"


def test_open_api_without_any_token_forwards_no_credentials(make):
    bl = make(gateway_open_tokenless_apis=True)
    target_id = _add(bl, "/echo/login", requires_auth=False)

    _, body = _call(bl, target_id)

    assert body["response"]["credential_header"] is None


def test_docs_data_reports_the_effective_open_state(make):
    bl = make(gateway_open_tokenless_apis=True)
    open_id = _add(bl, "/echo/login", requires_auth=False)
    gated_id = _add(bl, "/echo/secret", requires_auth=True)

    items = {i["id"]: i for i in bl.dashboard._enrich_targets(bl.registry.to_list())}

    assert items[open_id]["public"] is True
    assert items[gated_id]["public"] is False


# --- the response a caller gets back is the API's real answer ----------------------


def test_replay_returns_the_real_token_a_login_api_issues(make):
    bl = make()
    target_id = _add(bl, "/issue-token", requires_auth=False)

    result = bl.invoke(target_id)

    assert result["response"] == {"access_token": "abc.def.ghi", "token_type": "bearer", "user": "alice"}


def test_gateway_caller_receives_the_real_token(make):
    bl = make(gateway_open_tokenless_apis=True)
    target_id = _add(bl, "/issue-token", requires_auth=False)

    status, body = _call(bl, target_id)

    assert status == 200
    assert body["response"]["access_token"] == "abc.def.ghi"
    assert body["response"]["token_type"] == "bearer"


def test_masking_the_replay_response_is_available_as_an_option(make):
    bl = make(redact_replay_response=True)
    target_id = _add(bl, "/issue-token", requires_auth=False)

    response = bl.invoke(target_id)["response"]

    assert response["access_token"] == "[redacted]"
    assert response["user"] == "alice"


# --- gateway_forward_own_tokens: a token-requiring API accepts its own token ---------


def test_own_token_is_rejected_by_the_gateway_by_default(make):
    bl = make()
    target_id = _add(bl, "/echo/secret", requires_auth=True)

    status, body = _call(bl, target_id, bearer="my-own-api-token")

    assert status == 401
    assert "gateway token" in body["error"]


def test_own_token_is_forwarded_when_the_setting_is_on(make):
    bl = make(gateway_forward_own_tokens=True)
    target_id = _add(bl, "/echo/secret", requires_auth=True)

    status, body = _call(bl, target_id, bearer="my-own-api-token")

    assert status == 200
    assert body["response"]["credential_header"] == "Bearer my-own-api-token"


def test_no_token_at_all_is_still_refused_on_a_token_requiring_api(make):
    bl = make(gateway_forward_own_tokens=True)
    target_id = _add(bl, "/echo/secret", requires_auth=True)

    status, body = _call(bl, target_id)

    assert status == 401
    assert "its own token" in body["error"]  # says what to send, not "gateway token"


def test_the_setting_does_not_forward_tokens_to_an_api_that_needs_none(make):
    bl = make(gateway_forward_own_tokens=True)
    target_id = _add(bl, "/echo/login", requires_auth=False)

    status, _ = _call(bl, target_id, bearer="anything")

    assert status == 401  # not open (its own setting is off) and no own-token path applies


def test_a_real_gateway_token_is_still_treated_as_one_and_never_forwarded(make):
    from jscoup import generate_encryption_key

    bl = make(gateway_forward_own_tokens=True, encryption_key=generate_encryption_key())
    target_id = _add(bl, "/echo/secret", requires_auth=True)
    bl.gateway.create_user("alice", "alice", "pw", [target_id], downstream_token="configured-downstream")
    gateway_token = bl.gateway.login("alice", "pw")["token"]

    status, body = _call(bl, target_id, bearer=gateway_token)

    assert status == 200
    assert body["response"]["credential_header"] == "Bearer configured-downstream"


def test_a_gateway_user_is_still_limited_to_their_allowed_apis(make):
    from jscoup import generate_encryption_key

    bl = make(gateway_forward_own_tokens=True, encryption_key=generate_encryption_key())
    allowed = _add(bl, "/echo/allowed", requires_auth=True)
    other = _add(bl, "/echo/other", requires_auth=True)
    bl.gateway.create_user("alice", "alice", "pw", [allowed])
    gateway_token = bl.gateway.login("alice", "pw")["token"]

    status, _ = _call(bl, other, bearer=gateway_token)

    assert status == 403


def test_docs_data_flags_apis_that_accept_their_own_token(make):
    bl = make(gateway_forward_own_tokens=True)
    secret = _add(bl, "/echo/secret", requires_auth=True)
    plain = _add(bl, "/echo/login", requires_auth=False)

    items = {i["id"]: i for i in bl.dashboard._enrich_targets(bl.registry.to_list())}

    assert items[secret]["accepts_own_token"] is True
    assert items[plain]["accepts_own_token"] is False
