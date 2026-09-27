# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.gateway — the API Gateway's user/session/permission store."""

import time

import pytest

from jscoup.gateway import ALL_TARGETS, GatewayStore, RateLimiter


def make_store(tmp_path, **kwargs):
    return GatewayStore(str(tmp_path / "gateway.db"), **kwargs)


def test_create_user_stores_credentials_without_returning_a_token(tmp_path):
    store = make_store(tmp_path)

    user = store.create_user("alice", "alice", "s3cret-pw", ["http:GET:/api/v1/team"])

    assert user.label == "alice"
    assert user.username == "alice"
    assert not hasattr(user, "token")


def test_login_succeeds_with_correct_credentials_and_issues_a_token(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "s3cret-pw", ["http:GET:/x"])

    session = store.login("alice", "s3cret-pw")

    assert session is not None
    assert isinstance(session["token"], str) and len(session["token"]) > 20
    assert session["user"].username == "alice"


def test_login_fails_with_wrong_password(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "s3cret-pw", ["http:GET:/x"])

    assert store.login("alice", "wrong-password") is None


def test_login_fails_for_unknown_username(tmp_path):
    store = make_store(tmp_path)

    assert store.login("nobody", "whatever") is None


def test_token_ttl_defaults_to_exactly_one_hour(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])

    session = store.login("alice", "pw")

    delta_hours = (session["expires_at"] - time.time()) / 3600
    assert 0.99 < delta_hours <= 1.0


def test_custom_token_ttl_is_honored(tmp_path):
    store = make_store(tmp_path, token_ttl_hours=0.01)  # ~36 seconds
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])

    session = store.login("alice", "pw")

    delta_seconds = session["expires_at"] - time.time()
    assert 30 < delta_seconds <= 36


def test_authenticate_succeeds_for_a_freshly_issued_token(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    session = store.login("alice", "pw")

    found = store.authenticate(session["token"])

    assert found is not None
    assert found.username == "alice"


def test_authenticate_rejects_a_bad_or_missing_token(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    session = store.login("alice", "pw")

    assert store.authenticate(session["token"] + "x") is None
    assert store.authenticate(None) is None
    assert store.authenticate("") is None


def test_authenticate_rejects_an_expired_token(tmp_path):
    store = make_store(tmp_path, token_ttl_hours=-1.0)  # already expired the instant it's issued
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    session = store.login("alice", "pw")

    assert store.authenticate(session["token"]) is None


def test_allows_checks_the_users_own_target_list(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/api/v1/team"])
    user = store.authenticate(store.login("alice", "pw")["token"])

    assert user.allows("http:GET:/api/v1/team") is True
    assert user.allows("http:DELETE:/api/v1/team/1") is False


def test_all_targets_wildcard_allows_everything(tmp_path):
    store = make_store(tmp_path)
    store.create_user("admin-bot", "admin-bot", "pw", ALL_TARGETS)
    user = store.authenticate(store.login("admin-bot", "pw")["token"])

    assert user.allows("http:GET:/anything") is True
    assert user.allows("service:whatever") is True


def test_ip_whitelist_blocks_login_from_a_disallowed_address(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    assert store.login("alice", "pw", client_ip="203.0.113.4") is None
    assert store.login("alice", "pw", client_ip="10.1.2.3") is not None


def test_no_ip_whitelist_means_unrestricted(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw", ["http:GET:/x"])

    assert store.login("alice", "pw", client_ip="203.0.113.4") is not None


def test_allows_ip_matches_exact_and_cidr(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"], allowed_ips=["203.0.113.4", "10.0.0.0/8"])

    assert user.allows_ip("203.0.113.4") is True
    assert user.allows_ip("10.5.5.5") is True
    assert user.allows_ip("198.51.100.1") is False


def test_revoked_user_can_no_longer_authenticate(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    token = store.login("alice", "pw")["token"]

    revoked = store.revoke(user.id)

    assert revoked is True
    assert store.authenticate(token) is None


def test_revoked_user_can_no_longer_log_in_again(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    store.revoke(user.id)

    assert store.login("alice", "pw") is None


def test_revoke_unknown_user_returns_false(tmp_path):
    store = make_store(tmp_path)

    assert store.revoke("does-not-exist") is False


def test_public_targets_toggle_on_and_off(tmp_path):
    store = make_store(tmp_path)
    target_id = "http:GET:/api/v1/pages/public"

    assert store.is_public(target_id) is False
    store.set_public(target_id, True)
    assert store.is_public(target_id) is True
    store.set_public(target_id, False)
    assert store.is_public(target_id) is False


def test_list_public_targets_returns_only_ids_marked_public(tmp_path):
    store = make_store(tmp_path)
    store.set_public("http:GET:/open", True)
    store.set_public("http:GET:/also-open", True)
    store.set_public("http:GET:/private", False)

    assert sorted(store.list_public_targets()) == ["http:GET:/also-open", "http:GET:/open"]


def test_set_target_description_then_get_all_descriptions(tmp_path):
    store = make_store(tmp_path)

    store.set_target_description("http:GET:/x", "Lists widgets")
    store.set_target_description("http:GET:/y", "Creates a widget")

    assert store.get_target_descriptions() == {
        "http:GET:/x": "Lists widgets",
        "http:GET:/y": "Creates a widget",
    }


def test_set_target_description_overwrites_the_previous_value(tmp_path):
    store = make_store(tmp_path)
    store.set_target_description("http:GET:/x", "First draft")

    store.set_target_description("http:GET:/x", "Final wording")

    assert store.get_target_descriptions()["http:GET:/x"] == "Final wording"


def test_target_descriptions_persist_across_store_instances(tmp_path):
    path = str(tmp_path / "gateway.db")
    store1 = GatewayStore(path)
    store1.set_target_description("http:GET:/x", "Cross-worker description")
    store1.close()

    store2 = GatewayStore(path)

    assert store2.get_target_descriptions()["http:GET:/x"] == "Cross-worker description"


def test_downstream_token_is_stored_and_returned(tmp_path):
    from jscoup.crypto import generate_key
    store = GatewayStore(str(tmp_path / "encrypted.db"), encryption_key=generate_key())
    store.create_user("alice", "alice", "pw", ["http:GET:/x"], downstream_token="real-app-secret")

    found = store.authenticate(store.login("alice", "pw")["token"])

    assert found.downstream_token == "real-app-secret"


def test_users_and_public_targets_persist_across_store_instances(tmp_path):
    path = str(tmp_path / "gateway.db")
    store1 = GatewayStore(path)
    store1.create_user("alice", "alice", "pw", ["http:GET:/x"])
    token = store1.login("alice", "pw")["token"]
    store1.set_public("http:GET:/open", True)
    store1.close()

    store2 = GatewayStore(path)

    assert store2.authenticate(token) is not None
    assert store2.is_public("http:GET:/open") is True


def test_usernames_must_be_unique(tmp_path):
    import sqlite3

    store = make_store(tmp_path)
    store.create_user("alice", "alice", "pw1", ["http:GET:/x"])

    try:
        store.create_user("alice again", "alice", "pw2", ["http:GET:/y"])
        assert False, "expected a uniqueness violation"
    except sqlite3.IntegrityError:
        pass


def test_restore_reverses_a_revoke(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    store.revoke(user.id)

    restored = store.restore(user.id)

    assert restored is True
    assert store.login("alice", "pw") is not None


def test_reset_password_changes_credentials_and_invalidates_sessions(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "old-pw", ["http:GET:/x"])
    old_token = store.login("alice", "old-pw")["token"]

    ok = store.reset_password(user.id, "new-pw")

    assert ok is True
    assert store.authenticate(old_token) is None
    assert store.login("alice", "old-pw") is None
    assert store.login("alice", "new-pw") is not None


def test_reset_password_unknown_user_returns_false(tmp_path):
    store = make_store(tmp_path)

    assert store.reset_password("does-not-exist", "whatever-pw") is False


def test_update_permissions_replaces_allowed_targets_and_ips(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    ok = store.update_permissions(user.id, allowed_target_ids=["http:GET:/y"], allowed_ips=["203.0.113.4"])

    assert ok is True
    found = store.authenticate(store.login("alice", "pw", client_ip="203.0.113.4")["token"])
    assert found.allows("http:GET:/y") is True
    assert found.allows("http:GET:/x") is False
    assert found.allows_ip("203.0.113.4") is True
    assert found.allows_ip("10.1.1.1") is False


def test_update_permissions_leaves_omitted_fields_unchanged(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    store.update_permissions(user.id, allowed_target_ids=["http:GET:/y"])

    found = store.authenticate(store.login("alice", "pw", client_ip="10.1.1.1")["token"])
    assert found.allows("http:GET:/y") is True
    assert found.allows_ip("10.1.1.1") is True  # unchanged


def test_update_permissions_empty_ip_list_lifts_the_restriction(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    store.update_permissions(user.id, allowed_ips=[])

    assert store.login("alice", "pw", client_ip="203.0.113.4") is not None


def test_delete_user_removes_the_user_and_its_sessions(tmp_path):
    store = make_store(tmp_path)
    user = store.create_user("alice", "alice", "pw", ["http:GET:/x"])
    token = store.login("alice", "pw")["token"]

    deleted = store.delete_user(user.id)

    assert deleted is True
    assert store.authenticate(token) is None
    assert store.list_users() == []


def test_delete_user_unknown_user_returns_false(tmp_path):
    store = make_store(tmp_path)

    assert store.delete_user("does-not-exist") is False


def test_rate_limiter_blocks_after_the_configured_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60.0)

    results = [limiter.allow("tok-1") for _ in range(4)]

    assert results == [True, True, True, False]


def test_rate_limiter_tracks_keys_independently():
    limiter = RateLimiter(max_requests=1, window_seconds=60.0)

    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("a") is False


def test_rate_limiter_allows_again_after_the_window_expires():
    limiter = RateLimiter(max_requests=1, window_seconds=0.05)

    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    time.sleep(0.06)
    assert limiter.allow("a") is True


# --------------------------------------------------------------------------- #
# public doc groups
# --------------------------------------------------------------------------- #

def test_create_doc_group_and_get_it_back(tmp_path):
    store = make_store(tmp_path)

    group = store.create_doc_group("partners", "Partner APIs", ["http:GET:/api/orders"], allowed_ips=["10.0.0.0/8"])

    assert group["slug"] == "partners"
    assert group["title"] == "Partner APIs"
    assert group["target_ids"] == ["http:GET:/api/orders"]
    assert group["allowed_ips"] == ["10.0.0.0/8"]

    fetched = store.get_doc_group("partners")
    assert fetched == group


def test_create_doc_group_with_no_allowed_ips_means_open_to_everyone(tmp_path):
    store = make_store(tmp_path)

    group = store.create_doc_group("public-menu", "Public menu", ["service:ping"])

    assert group["allowed_ips"] is None


def test_create_doc_group_rejects_a_duplicate_slug(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"])

    with pytest.raises(ValueError):
        store.create_doc_group("partners", "Another title", ["http:GET:/y"])


def test_create_doc_group_rejects_reserved_slugs(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(ValueError):
        store.create_doc_group("api", "Shadowing the admin API", ["http:GET:/x"])
    with pytest.raises(ValueError):
        store.create_doc_group("gw", "Shadowing the gateway proxy", ["http:GET:/x"])


def test_create_doc_group_rejects_an_invalid_slug(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(ValueError):
        store.create_doc_group("Not Valid!", "title", ["http:GET:/x"])


def test_get_doc_group_unknown_slug_returns_none(tmp_path):
    store = make_store(tmp_path)

    assert store.get_doc_group("nope") is None


def test_list_doc_groups_returns_every_group(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("a", "A", ["http:GET:/a"])
    store.create_doc_group("b", "B", ["http:GET:/b"])

    slugs = {g["slug"] for g in store.list_doc_groups()}

    assert slugs == {"a", "b"}


def test_update_doc_group_replaces_only_given_fields(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    ok = store.update_doc_group("partners", title="Renamed")

    assert ok is True
    group = store.get_doc_group("partners")
    assert group["title"] == "Renamed"
    assert group["target_ids"] == ["http:GET:/x"]
    assert group["allowed_ips"] == ["10.0.0.0/8"]


def test_update_doc_group_with_empty_allowed_ips_opens_it_to_everyone(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])

    store.update_doc_group("partners", allowed_ips=[])

    assert store.get_doc_group("partners")["allowed_ips"] is None


def test_update_doc_group_unknown_slug_returns_false(tmp_path):
    store = make_store(tmp_path)

    assert store.update_doc_group("nope", title="x") is False


def test_delete_doc_group(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"])

    assert store.delete_doc_group("partners") is True
    assert store.get_doc_group("partners") is None
    assert store.delete_doc_group("partners") is False


def test_doc_groups_persist_across_store_instances(tmp_path):
    path = str(tmp_path / "gateway.db")
    store1 = GatewayStore(path)
    store1.create_doc_group("partners", "Partner APIs", ["http:GET:/x"], allowed_ips=["10.0.0.0/8"])
    store1.close()

    store2 = GatewayStore(path)

    assert store2.get_doc_group("partners") == {
        "slug": "partners", "title": "Partner APIs",
        "target_ids": ["http:GET:/x"], "allowed_ips": ["10.0.0.0/8"], "categories": {},
        "created_at": store2.get_doc_group("partners")["created_at"],
    }


def test_create_doc_group_with_a_per_target_category_override(tmp_path):
    store = make_store(tmp_path)

    group = store.create_doc_group(
        "partners", "Partner APIs", ["http:GET:/x", "http:GET:/y"],
        categories={"http:GET:/x": "billing"},
    )

    assert group["categories"] == {"http:GET:/x": "billing"}


def test_update_doc_group_categories_replaces_the_whole_mapping(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"], categories={"http:GET:/x": "billing"})

    store.update_doc_group("partners", categories={"http:GET:/x": "internal"})

    assert store.get_doc_group("partners")["categories"] == {"http:GET:/x": "internal"}


def test_update_doc_group_categories_empty_dict_clears_overrides(tmp_path):
    store = make_store(tmp_path)
    store.create_doc_group("partners", "Partner APIs", ["http:GET:/x"], categories={"http:GET:/x": "billing"})

    store.update_doc_group("partners", categories={})

    assert store.get_doc_group("partners")["categories"] == {}

