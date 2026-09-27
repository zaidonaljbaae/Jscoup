# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Every parameter the library detects must be sent where it was declared: the Live
Tester replays it over HTTP, so the API sees a path segment, a query string, a JSON
body or a form body exactly as its own code expects."""

from __future__ import annotations

import json

from jscoup import JSCoup, MemoryStorage
from jscoup.registry import ParamSpec, Target


def _bl(echo_server):
    return JSCoup("t", storage=MemoryStorage(), capture_success=False, base_url=echo_server)


def _post(bl, params):
    bl.registry.add(Target(id="http:POST:/echo/{item_id}", kind="http", name="echo", method="POST",
                           path="/echo/{item_id}", params=params))
    return bl.invoke("http:POST:/echo/{item_id}", params={"item_id": "7", "page": "2", "name": "widget", "kind": "a"},
                     token="tok")["response"]


def test_path_query_and_json_body_parameters_arrive_where_declared(echo_server):
    seen = _post(_bl(echo_server), [
        ParamSpec(name="item_id", location="path"),
        ParamSpec(name="page", location="query", type="int"),
        ParamSpec(name="name", location="body"),
    ])

    assert seen["path"] == "/echo/7"
    assert seen["query"] == {"page": ["2"]}
    assert seen["content_type"] == "application/json"
    assert json.loads(seen["body"]) == {"name": "widget", "kind": "a"}
    assert seen["credential_header"] == "Bearer tok"


def test_form_parameters_are_sent_form_encoded_not_as_json(echo_server):
    seen = _post(_bl(echo_server), [
        ParamSpec(name="item_id", location="path"),
        ParamSpec(name="page", location="query", type="int"),
        ParamSpec(name="name", location="form"),
        ParamSpec(name="kind", location="form"),
    ])

    assert seen["query"] == {"page": ["2"]}
    assert seen["content_type"] == "application/x-www-form-urlencoded"
    assert seen["body"] in ("name=widget&kind=a", "kind=a&name=widget")


def test_get_sends_all_non_path_parameters_in_the_query_string(echo_server):
    bl = _bl(echo_server)
    bl.registry.add(Target(id="http:GET:/echo", kind="http", name="echo", method="GET", path="/echo",
                           params=[ParamSpec(name="id_categoria", location="query"), ParamSpec(name="page", location="query")]))

    seen = bl.invoke("http:GET:/echo", params={"id_categoria": "abc", "page": "1"})["response"]

    assert seen["query"] == {"id_categoria": ["abc"], "page": ["1"]}
    assert seen["body"] == ""
