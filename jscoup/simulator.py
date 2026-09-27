# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Live invocation ("simulation") of endpoints and services.

The dashboard posts a target id, a parameter map and an optional token; the
simulator runs it and returns the result together with the id of the event that
the run produced, so the UI can jump straight to the analysis.

HTTP targets are replayed through a real request against the running server so
the whole stack participates. Service targets are called in-process, which is
what makes it possible to exercise a Lambda handler or a background job without
deploying anything.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Optional

from .models import new_id


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect instead of following it, so a redirect to an
    unapproved origin can never carry a live bearer token there."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class SimulationResult(dict):
    """Plain dict so it serialises straight to JSON."""


def _not_http(target: Any) -> "SimulationResult":
    """JSCoup is middleware: it replays HTTP APIs (with the caller's own token)
    and records what happens, but does not execute application code itself."""
    return SimulationResult(
        ok=False,
        error=(
            f"'{target.name}' is not an HTTP API. JSCoup only calls APIs over HTTP; "
            "it does not run Python functions itself."
        ),
    )


class Simulator:
    def __init__(self, jscoup: Any):
        self.jscoup = jscoup
        import threading
        self._slots = threading.BoundedSemaphore(jscoup.config.invoke_max_concurrency)

    # -- entry point -------------------------------------------------------- #

    def invoke(
        self,
        target_id: str,
        params: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> SimulationResult:
        """Synchronous entry point. Replays an HTTP API over the network;
        JSCoup never runs application code itself, so any other kind of target
        is refused."""
        target = self.jscoup.registry.get(target_id)
        if target is None:
            return SimulationResult(ok=False, error=f"Unknown target: {target_id}")

        if target.kind != "http":
            return _not_http(target)

        simulation_id = f"sim_{uuid.uuid4().hex[:12]}"
        params = params or {}
        started = time.perf_counter()

        result = self._invoke_http(target, params, token, base_url, method, headers, simulation_id)

        result["simulation_id"] = simulation_id
        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result["target"] = target.to_dict()
        if "event_id" not in result:
            result["event_id"] = None
        return result

    async def ainvoke(
        self,
        target_id: str,
        params: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> SimulationResult:
        """Async entry point — the one to use from inside an async caller.

        HTTP replay is dispatched to a worker thread via
        ``loop.run_in_executor`` since ``_invoke_http`` is a blocking,
        ``urllib``-based call that doesn't open its own capture context.
        """
        target = self.jscoup.registry.get(target_id)
        if target is None:
            return SimulationResult(ok=False, error=f"Unknown target: {target_id}")

        if target.kind != "http":
            return _not_http(target)

        simulation_id = f"sim_{uuid.uuid4().hex[:12]}"
        params = params or {}
        started = time.perf_counter()

        loop = asyncio.get_running_loop()
        if not self._slots.acquire(blocking=False):
            return SimulationResult(ok=False, error="Invocation concurrency limit reached")
        try:
            future = loop.run_in_executor(
                None, self._invoke_admitted, target, params, token, base_url, method, headers, simulation_id
            )
        except BaseException:
            self._slots.release()
            raise
        # Cancellation must not free a slot while the network thread still runs.
        result = await asyncio.shield(future)

        result["simulation_id"] = simulation_id
        result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result["target"] = target.to_dict()
        if "event_id" not in result:
            result["event_id"] = None
        return result

    # -- http --------------------------------------------------------------- #

    def _invoke_http(self, *args):
        if not self._slots.acquire(blocking=False):
            return SimulationResult(ok=False, error="Invocation concurrency limit reached")
        return self._invoke_admitted(*args)

    def _invoke_admitted(self, *args):
        try:
            return self._invoke_http_inner(*args)
        finally:
            self._slots.release()

    def _invoke_http_inner(
        self,
        target: Any,
        params: Dict[str, Any],
        token: Optional[str],
        base_url: Optional[str],
        method: Optional[str],
        headers: Optional[Dict[str, str]],
        simulation_id: str,
    ) -> SimulationResult:
        base = (base_url or self.jscoup.config.base_url or "").rstrip("/")
        if not base:
            return SimulationResult(
                ok=False,
                error="No base URL available. Set JSCoupConfig.base_url or call from the dashboard.",
            )
        parsed_base = urllib.parse.urlsplit(base)
        if parsed_base.scheme not in ("http", "https"):
            return SimulationResult(ok=False, error=f"Unsupported base_url scheme: {parsed_base.scheme!r}")
        if parsed_base.username or parsed_base.password:
            # Userinfo in a URL is a classic SSRF/credential-smuggling vector.
            return SimulationResult(ok=False, error="base_url must not contain embedded credentials")

        path = target.path
        remaining = dict(params)
        # Path parameter names come from target.params (already extracted per
        # framework by registry.py), rather than re-parsing the path template
        # here, since Flask (<converter:name>) and FastAPI/Starlette
        # ({name:converter}) disagree on the order.
        path_param_names = [p.name for p in target.params if p.location == "path"]
        for name in path_param_names:
            value = remaining.pop(name, "")
            path = re.sub(r"(?:<(?:[^<>:]+:)?" + re.escape(name) + r">|\{" + re.escape(name) + r"(?::[^{}]+)?\})",
                          lambda _: urllib.parse.quote(str(value), safe=""), path, count=1)

        location_by_name = {p.name: p.location for p in target.params}
        http_method = (method or target.method or "GET").upper()
        query = {}
        body: Optional[bytes] = None
        request_headers = {
            "Accept": "application/json",
            "X-JSCoup-Simulation": simulation_id,
            "User-Agent": "JSCoup-Simulator/1.0",
        }
        request_headers.update(headers or {})
        if token:
            request_headers["Authorization"] = (
                token if token.lower().startswith(("bearer ", "basic ", "token ")) else f"Bearer {token}"
            )

        if http_method in {"GET", "DELETE", "HEAD"}:
            # No body on these methods regardless of declared location.
            query = {k: v for k, v in remaining.items() if v not in (None, "")}
        elif any(_is_file_value(v) for v in remaining.values()):
            # A file parameter (FastAPI UploadFile...) — send multipart/form-data;
            # the other body fields travel as plain form fields.
            fields = {}
            files = {}
            for key, value in remaining.items():
                if _is_file_value(value):
                    files[key] = value
                elif value not in (None, ""):
                    if location_by_name.get(key) == "query":
                        query[key] = value
                    else:
                        fields[key] = value if isinstance(value, str) else json.dumps(value, default=str)
            try:
                body, content_type = _encode_multipart(fields, files)
            except ValueError as exc:
                return SimulationResult(ok=False, error=str(exc))
            request_headers["Content-Type"] = content_type
        elif "__body__" in remaining:
            # Explicit escape hatch: the caller supplied the entire body as
            # one value under this key; anything else remaining is query-only.
            payload = remaining.pop("__body__")
            query = {
                k: v for k, v in remaining.items()
                if location_by_name.get(k) == "query" and v not in (None, "")
            }
            body = json.dumps(payload, default=str).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        else:
            # Split by each parameter's own declared location (query vs.
            # body) rather than dumping everything not consumed by the path
            # into the body. Anything with no matching ParamSpec falls back
            # to the body.
            payload = {}
            form = {}
            for key, value in remaining.items():
                if value in (None, ""):
                    continue
                location = location_by_name.get(key)
                if location == "query":
                    query[key] = value
                elif location == "form":
                    form[key] = value
                else:
                    payload[key] = value
            if form and not payload:
                # Form(...) parameters are read from an urlencoded body, not JSON.
                body = urllib.parse.urlencode(
                    {k: v if isinstance(v, str) else json.dumps(v, default=str) for k, v in form.items()}
                ).encode("utf-8")
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                payload.update(form)
                body = json.dumps(payload, default=str).encode("utf-8")
                request_headers["Content-Type"] = "application/json"

        url = base + path
        if query:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                {k: _flat(v) for k, v in query.items()}
            )

        if body and len(body) > self.jscoup.config.dashboard_max_body_bytes:
            return SimulationResult(ok=False, error="Outbound request body too large")
        request = urllib.request.Request(url, data=body, method=http_method, headers=request_headers)
        deadline = time.monotonic() + self.jscoup.config.invoke_timeout
        try:
            with _opener.open(request, timeout=self.jscoup.config.invoke_timeout) as resp:
                raw = _read_response(resp, self.jscoup.config.invoke_max_response_bytes, deadline).decode("utf-8", "replace")
                status = resp.status
                response_type = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            try:
                raw = _read_response(exc, self.jscoup.config.invoke_max_response_bytes, deadline).decode("utf-8", "replace")
            except ValueError as limit_error:
                return SimulationResult(ok=False, error=str(limit_error), url=url)
            status = exc.code
            response_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        except Exception as exc:  # connection refused, timeout, ...
            return SimulationResult(ok=False, error=f"{type(exc).__name__}: {exc}", url=url)

        # give the server a moment to persist the event it just produced
        event_id = self._find_event(simulation_id, attempts=12)
        return SimulationResult(
            ok=200 <= status < 400,
            status_code=status,
            url=url,
            method=http_method,
            request_body=_loggable_body(body, request_headers),
            content_type=response_type.split(";")[0].strip().lower(),
            response=(
                self.jscoup.redactor.scrub(_maybe_json(raw))
                if self.jscoup.config.redact_replay_response
                else _maybe_json(raw)
            ),
            event_id=event_id,
        )

    # -- linking ------------------------------------------------------------ #

    def _find_event(self, simulation_id: str, attempts: int = 3) -> Optional[str]:
        for _ in range(1):
            events = self.jscoup.storage.list(limit=1, simulation_id=simulation_id)
            if events:
                return events[0].id
            # No polling on a request thread: async persistence may complete later.
            pass
        return None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _run_async(coro: Any) -> Any:
    """Only ever reached when no event loop is running in this thread;
    ``Simulator.invoke()`` already refuses the running-loop case and directs
    the caller to ``ainvoke()`` instead."""
    return asyncio.run(coro)


def _flat(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)


def _maybe_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw[:200000]


MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _is_file_value(value: Any) -> bool:
    """A file param as the dashboard sends it: {"filename", "content_type", "data" (base64)}."""
    return isinstance(value, dict) and "data" in value and "filename" in value and set(value) <= {
        "filename", "content_type", "data", "__file__"}


def _encode_multipart(fields: Dict[str, Any], files: Dict[str, Any]) -> "tuple[bytes, str]":
    import base64
    import uuid

    boundary = "----jscoup" + uuid.uuid4().hex
    crlf = b"\r\n"
    out = bytearray()
    for name, value in fields.items():
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{_q(name)}"\r\n\r\n'.encode()
        out += str(value).encode("utf-8") + crlf
    if len(out) > MAX_UPLOAD_BYTES:
        raise ValueError("Aggregate upload exceeds limit")
    for name, f in files.items():
        encoded = f.get("data") or ""
        if len(encoded) > ((MAX_UPLOAD_BYTES + 2) // 3) * 4:
            raise ValueError("Encoded file exceeds upload limit")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError(f"File '{f.get('filename')}' is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
        ctype = _q(f.get("content_type") or "application/octet-stream")
        out += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{_q(name)}"; '
            f'filename="{_q(f.get("filename") or "upload")}"\r\nContent-Type: {ctype}\r\n\r\n'
        ).encode()
        if len(out) + len(raw) + len(crlf) > MAX_UPLOAD_BYTES:
            raise ValueError("Aggregate upload exceeds limit")
        out += raw + crlf
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def _q(text: Any) -> str:
    return str(text).replace('"', "").replace("\r", "").replace("\n", "")


def _loggable_body(body: Optional[bytes], headers: Dict[str, str]) -> Any:
    if not body:
        return None
    if headers.get("Content-Type", "").startswith("multipart/"):
        return {"__multipart__": f"{len(body)} bytes"}
    try:
        return json.loads(body)
    except ValueError:
        return None


def _read_response(response, limit, deadline=None):
    out = bytearray()
    reader = getattr(response, "read1", response.read)
    while len(out) <= limit:
        if deadline is not None and time.monotonic() >= deadline:
            raise ValueError("Outbound response deadline exceeded")
        chunk = reader(min(65536, limit + 1 - len(out)))
        if not chunk:
            return bytes(out)
        out.extend(chunk)
    raise ValueError("Outbound response exceeds configured byte limit")
