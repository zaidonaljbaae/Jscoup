# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Duck-typed field extraction for serverless platforms whose SDKs JSCoup
never imports:

* Azure Functions — ``azure.functions.HttpRequest``/``HttpResponse``
* OCI (Oracle Cloud) Functions — the Fn Project Python FDK,
  ``def handler(ctx, data: io.BytesIO = None)``

Every accessor here is defensive (``getattr``/``try``) so a missing field
degrades to "unknown" instead of breaking capture.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional


def _safe_call(obj: Any, method: str) -> Any:
    fn = getattr(obj, method, None)
    if not callable(fn):
        return None
    try:
        return fn()
    except Exception:
        return None


def _safe_json(text: Optional[str]) -> Optional[Any]:
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Azure Functions
# --------------------------------------------------------------------------- #


def azure_request_fields(req: Any) -> Dict[str, Any]:
    """Extract method/url/headers/query/body from an
    ``azure.functions.HttpRequest`` (or anything shaped like one) without
    importing ``azure.functions``."""
    headers = dict(getattr(req, "headers", None) or {})
    query_params = dict(getattr(req, "params", None) or {})

    body_text: Optional[str] = None
    # get_body() returns the already-buffered bytes, so calling it here
    # doesn't consume a stream the real handler will also read.
    raw_body = _safe_call(req, "get_body")
    if isinstance(raw_body, (bytes, bytearray)) and raw_body:
        body_text = raw_body.decode("utf-8", "replace")

    return {
        "method": getattr(req, "method", None),
        "url": getattr(req, "url", None),
        "headers": headers,
        "query_params": query_params,
        "body_text": body_text,
        "body_json": _safe_json(body_text),
    }


def azure_response_status(result: Any) -> Optional[int]:
    """``azure.functions.HttpResponse.status_code`` when the handler returned
    one; ``None`` for a non-HTTP-trigger handler (queue/timer/blob) that
    returns something else entirely."""
    value = getattr(result, "status_code", None)
    return value if isinstance(value, int) else None


# --------------------------------------------------------------------------- #
# OCI Functions (Fn Project Python FDK)
# --------------------------------------------------------------------------- #


def oci_request_fields(ctx: Any, data: Any) -> Dict[str, Any]:
    """Extract call id/headers/body from an ``fdk`` ``(ctx, data)`` pair
    without importing ``fdk``."""
    headers: Dict[str, Any] = {}
    raw_headers = _safe_call(ctx, "Headers")
    if isinstance(raw_headers, dict):
        headers = dict(raw_headers)

    call_id = _safe_call(ctx, "CallID")

    body_text: Optional[str] = None
    if data is not None:
        # getvalue() returns the whole buffer without consuming it, unlike
        # .read(), so the real handler still sees the full stream afterwards.
        raw = getattr(data, "getvalue", None)
        raw_bytes = raw() if callable(raw) else data
        if isinstance(raw_bytes, (bytes, bytearray)) and raw_bytes:
            body_text = raw_bytes.decode("utf-8", "replace")

    return {
        "call_id": call_id if isinstance(call_id, str) else None,
        "headers": headers,
        "body_text": body_text,
        "body_json": _safe_json(body_text),
    }


def oci_response_status(result: Any) -> Optional[int]:
    """``fdk.response.Response.status_code`` when the handler returned one."""
    value = getattr(result, "status_code", None)
    return value if isinstance(value, int) else None
