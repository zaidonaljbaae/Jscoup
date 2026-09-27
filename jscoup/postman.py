# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Postman Collection (v2.1) export of every catalogued HTTP API.

Mirrors :mod:`jscoup.openapi`: one item per target, grouped into a folder per
category, with each parameter's type and example carried over so the imported
collection is runnable as-is. Path parameters become Postman ``:variables``,
query parameters go on the URL, and body parameters become a JSON example.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
_PATH_PARAM = re.compile(r"<(?:[^<>:]+:)?([^<>]+)>|\{([^{}:]+)(?::[^{}]+)?\}")


def _category(target: Dict[str, Any]) -> str:
    if target.get("tags"):
        return str(target["tags"][0])
    segments = [s for s in (target.get("path") or "").split("/") if s and not s.startswith(("{", "<"))]
    first = segments[1] if segments[:1] == ["api"] and len(segments) > 1 else (segments[0] if segments else "")
    return first or target.get("framework") or "general"


def _postman_path(path: str) -> List[str]:
    converted = _PATH_PARAM.sub(lambda m: ":" + (m.group(1) or m.group(2)), path)
    return [segment for segment in converted.split("/") if segment]


def build_postman_collection(service_name: str, targets: List[Dict[str, Any]], base_url: str) -> Dict[str, Any]:
    folders: Dict[str, List[Dict[str, Any]]] = {}
    for target in targets:
        if target.get("kind") != "http":
            continue
        method = (target.get("method") or "GET").upper()
        if method == "ANY":
            method = "GET"
        params = target.get("params") or []
        query = [
            {"key": p["name"], "value": str(p.get("example", "")), "description": _param_note(p),
             "disabled": not p.get("required")}
            for p in params if p.get("location") == "query"
        ]
        variables = [
            {"key": p["name"], "value": str(p.get("example", "")), "description": _param_note(p)}
            for p in params if p.get("location") == "path"
        ]
        request: Dict[str, Any] = {
            "method": method,
            "header": [{"key": "Accept", "value": "application/json"}],
            "url": {
                "raw": "{{baseUrl}}" + (target.get("path") or ""),
                "host": ["{{baseUrl}}"],
                "path": _postman_path(target.get("path") or ""),
                "query": query,
                "variable": variables,
            },
            "description": target.get("full_description") or target.get("description") or "",
        }
        if target.get("requires_auth"):
            request["header"].append({"key": "Authorization", "value": "Bearer {{token}}"})
        body = target.get("request_example")
        if body and method in ("POST", "PUT", "PATCH", "DELETE"):
            import json

            request["header"].append({"key": "Content-Type", "value": "application/json"})
            request["body"] = {
                "mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}},
            }
        item: Dict[str, Any] = {"name": f"{method} {target.get('path')}", "request": request}
        responses = target.get("expected_responses") or {}
        if responses:
            import json

            item["response"] = [
                {
                    "name": f"{code} {info.get('description', '')}".strip(),
                    "originalRequest": request,
                    "status": info.get("description", ""),
                    "code": int(code),
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": json.dumps(info.get("example"), indent=2) if info.get("example") is not None else "",
                }
                for code, info in responses.items()
            ]
        folders.setdefault(_category(target), []).append(item)
    return {
        "info": {"name": service_name, "schema": _SCHEMA},
        "item": [{"name": name, "item": items} for name, items in sorted(folders.items())],
        "variable": [
            {"key": "baseUrl", "value": base_url.rstrip("/")},
            {"key": "token", "value": ""},
        ],
    }


def _param_note(param: Dict[str, Any]) -> str:
    note = f"{param.get('type', 'string')}"
    if param.get("required"):
        note += ", required"
    if param.get("description"):
        note += f" — {param['description']}"
    return note
