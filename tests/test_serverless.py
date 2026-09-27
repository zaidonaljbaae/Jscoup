# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for watch_azure_function/watch_oci_function.

No azure-functions or fdk package is installed (or required) for these —
the wrappers are duck-typed, so these tests use hand-built fakes shaped
exactly like the real SDK objects (per each platform's public docs) to prove
the wrapper reads the right attributes without ever importing either SDK.
"""

from __future__ import annotations

import io
import json

import pytest

from jscoup import JSCoup, MemoryStorage


# --------------------------------------------------------------------------- #
# fakes shaped like the real SDKs
# --------------------------------------------------------------------------- #


class FakeAzureHttpRequest:
    """Mirrors azure.functions.HttpRequest's public surface."""

    def __init__(self, method="GET", url="https://x.azurewebsites.net/api/hello",
                 headers=None, params=None, body=b""):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.params = params or {}
        self._body = body

    def get_body(self):
        return self._body


class FakeAzureHttpResponse:
    """Mirrors azure.functions.HttpResponse's public surface."""

    def __init__(self, body=b"", status_code=200):
        self._body = body
        self.status_code = status_code


class FakeOciInvokeContext:
    """Mirrors fdk.context.InvokeContext's public surface."""

    def __init__(self, headers=None, call_id="call-123"):
        self._headers = headers or {}
        self._call_id = call_id

    def Headers(self):
        return self._headers

    def CallID(self):
        return self._call_id


class FakeOciResponse:
    """Mirrors fdk.response.Response's public surface."""

    def __init__(self, response_data="", status_code=200, headers=None):
        self.response_data = response_data
        self.status_code = status_code
        self.headers = headers or {}


# --------------------------------------------------------------------------- #
# Azure Functions
# --------------------------------------------------------------------------- #


def test_watch_azure_function_captures_a_successful_call():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    @bl.watch_azure_function()
    def main(req):
        return FakeAzureHttpResponse(body=b'{"ok": true}', status_code=200)

    req = FakeAzureHttpRequest(
        method="POST", url="https://x.azurewebsites.net/api/orders",
        headers={"X-Client": "test"}, params={"page": "2"},
        body=json.dumps({"order_id": 42}).encode(),
    )
    result = main(req)
    assert result.status_code == 200

    event = bl.storage.list()[0]
    assert event.kind == "azure_function"
    assert event.method == "POST"
    assert event.path == "https://x.azurewebsites.net/api/orders"
    assert event.status_code == 200
    assert event.params.get("page") == "2"
    assert event.params.get("order_id") == 42


def test_watch_azure_function_captures_an_exception():
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch_azure_function()
    def main(req):
        raise RuntimeError("boom")

    req = FakeAzureHttpRequest()
    with pytest.raises(RuntimeError):
        main(req)

    event = bl.storage.list()[0]
    assert event.status == "error"
    assert event.error_type == "RuntimeError"


def test_watch_azure_function_registers_a_target():
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch_azure_function(name="orders-handler")
    def main(req):
        return FakeAzureHttpResponse()

    target = bl.registry.get("service:orders-handler")
    assert target is not None
    assert target.framework == "azure_function"


# --------------------------------------------------------------------------- #
# OCI Functions
# --------------------------------------------------------------------------- #


def test_watch_oci_function_captures_a_successful_call():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    @bl.watch_oci_function()
    def handler(ctx, data=None):
        return FakeOciResponse(response_data='{"ok": true}', status_code=200)

    ctx = FakeOciInvokeContext(headers={"fn-http-h-x-test": "1"}, call_id="abc-123")
    data = io.BytesIO(json.dumps({"user_id": 7}).encode())
    result = handler(ctx, data)
    assert result.status_code == 200

    event = bl.storage.list()[0]
    assert event.kind == "oci_function"
    assert event.trace_id == "abc-123"
    assert event.params.get("user_id") == 7

    # the real handler must still be able to read the body itself — the
    # instrumentation must not have consumed the BytesIO stream.
    assert data.getvalue() == json.dumps({"user_id": 7}).encode()


def test_watch_oci_function_does_not_consume_the_data_stream_before_the_real_handler_runs():
    bl = JSCoup("t", storage=MemoryStorage())
    seen = {}

    @bl.watch_oci_function()
    def handler(ctx, data=None):
        seen["body"] = data.getvalue()
        return FakeOciResponse(status_code=200)

    ctx = FakeOciInvokeContext()
    data = io.BytesIO(b'{"still": "here"}')
    handler(ctx, data)
    assert seen["body"] == b'{"still": "here"}'


def test_watch_oci_function_captures_an_exception():
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch_oci_function()
    def handler(ctx, data=None):
        raise ValueError("bad input")

    with pytest.raises(ValueError):
        handler(FakeOciInvokeContext(), io.BytesIO(b"{}"))

    event = bl.storage.list()[0]
    assert event.status == "error"
    assert event.error_type == "ValueError"


def test_watch_oci_function_registers_a_target():
    bl = JSCoup("t", storage=MemoryStorage())

    @bl.watch_oci_function(name="resize-image")
    def handler(ctx, data=None):
        return FakeOciResponse()

    target = bl.registry.get("service:resize-image")
    assert target is not None
    assert target.framework == "oci_function"
