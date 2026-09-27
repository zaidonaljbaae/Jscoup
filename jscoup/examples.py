# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Smart, automatic examples for the docs page, OpenAPI and Postman exports.

Nothing here needs a developer to write anything by hand: an example value is
derived from a parameter's name and type, a request body example is assembled
from its body parameters, and the response examples for each status code are
either a real, previously seen response (from the call log) or a fixed,
sensible default per status. A developer can still override any of it in code
via ``JSCoup.describe(..., example=..., params_example=...)``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

STATUS_TEXT: Dict[int, str] = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

_DEFAULT_ERROR_BODIES: Dict[int, Dict[str, Any]] = {
    400: {"error": "Bad Request", "detail": "One or more parameters are missing or invalid."},
    401: {"error": "Unauthorized", "detail": "Missing or invalid credentials."},
    403: {"error": "Forbidden", "detail": "You are not allowed to do this."},
    404: {"error": "Not Found", "detail": "The requested resource does not exist."},
    405: {"error": "Method Not Allowed", "detail": "This endpoint does not accept that HTTP method."},
    409: {"error": "Conflict", "detail": "The request conflicts with the current state of the resource."},
    422: {"error": "Unprocessable Entity", "detail": "The input is well-formed but semantically invalid."},
    429: {"error": "Too Many Requests", "detail": "Rate limit exceeded. Try again later."},
    500: {"error": "Internal Server Error", "detail": "Something went wrong on the server."},
    502: {"error": "Bad Gateway", "detail": "The upstream service returned an invalid response."},
    503: {"error": "Service Unavailable", "detail": "The service is temporarily unavailable."},
}


# The well-known documentation UUID: valid in shape, and unlikely to exist.
EXAMPLE_UUID = "123e4567-e89b-12d3-a456-426614174000"


def sample_value(name: str, type_name: str = "", default: Any = None) -> Any:
    """A plausible example for one parameter — its declared default when it
    has one, otherwise a fixed value guessed from its name, then its type."""
    if default is not None:
        return default
    lowered = (name or "").lower()
    kind = (type_name or "").lower()
    if kind == "file":
        return "(file upload)"
    if "email" in lowered:
        return "user@example.com"
    if (lowered == "id" or lowered.startswith("id_") or lowered.endswith("_id") or lowered.endswith("id"))             and "bool" not in kind:
        # A string (or uuid) id is most likely a UUID; an integer id is a number.
        # A made-up word would be rejected by a UUID column outright.
        if "uuid" in kind or kind in ("str", "string", "text"):
            return EXAMPLE_UUID
        return 1
    if "name" in lowered:
        return f"Example {name}"
    if "date" in lowered or "time" in lowered:
        return "2026-01-15"
    if "url" in lowered or "link" in lowered:
        return "https://example.com"
    if "phone" in lowered:
        return "+1-555-0100"
    if "password" in lowered:
        return "change-me"
    if "int" in kind:
        return 1
    if "float" in kind or "number" in kind or "decimal" in kind:
        return 1.5
    if "bool" in kind:
        return True
    if "list" in kind or "array" in kind:
        return ["a", "b"]
    if "dict" in kind or "object" in kind or "json" in kind:
        return {"key": "value"}
    return f"example-{name or 'value'}"


def request_body_example(params: Iterable[Any]) -> Optional[Dict[str, Any]]:
    """A JSON example assembled from every parameter that belongs in the
    request body — ``None`` when there isn't one."""
    body_params = [p for p in params if getattr(p, "location", "") == "body"]
    if len(body_params) == 1 and (getattr(body_params[0], "type", "") or "").lower() in ("dict", "object", "json"):
        # A lone dict/object body parameter *is* the whole JSON body, not a
        # field named after the parameter.
        return _example_of(body_params[0])
    body = {p.name: _example_of(p) for p in body_params}
    return body or None


def _example_of(param: Any) -> Any:
    explicit = getattr(param, "example", None)
    if explicit is not None:
        return explicit
    return sample_value(param.name, getattr(param, "type", ""), getattr(param, "default", None))


def default_error_example(status_code: int) -> Dict[str, Any]:
    return dict(_DEFAULT_ERROR_BODIES.get(status_code) or {"error": STATUS_TEXT.get(status_code, "Error")})


def expected_status_codes(method: str, params: List[Any], requires_auth: bool) -> List[int]:
    """Which statuses an operation can plausibly return, from what's known
    about it — a best-effort expectation, not a guarantee."""
    codes = {204 if (method or "GET").upper() == "DELETE" else 200}
    if (method or "").upper() == "POST":
        codes.add(201)
    if params:
        codes.add(400)
    if any(getattr(p, "location", "") == "path" for p in params):
        codes.add(404)
    if requires_auth:
        codes.update((401, 403))
    codes.add(500)
    return sorted(codes)


def parse_preview(preview: Optional[str]) -> Any:
    """A stored response preview back into a JSON value when it is one."""
    if not preview:
        return None
    try:
        return json.loads(preview)
    except (ValueError, TypeError):
        return preview


def build_expected_responses(
    method: str,
    params: List[Any],
    requires_auth: bool,
    seen: Optional[Dict[int, Any]] = None,
    overrides: Optional[Dict[int, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """``{status: {"description": ..., "example": ...}}`` for every plausible
    status. For each: a developer override wins, then a real response
    previously seen for that exact status, then a fixed default."""
    seen = seen or {}
    overrides = overrides or {}
    out: Dict[str, Dict[str, Any]] = {}
    for code in expected_status_codes(method, params, requires_auth):
        if code in overrides:
            example = overrides[code]
        elif code in seen:
            example = seen[code]
        elif code >= 400:
            example = default_error_example(code)
        elif code == 204:
            example = None
        else:
            example = {"ok": True}
        out[str(code)] = {"description": STATUS_TEXT.get(code, ""), "example": example}
    return out
