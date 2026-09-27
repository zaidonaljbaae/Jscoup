# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Framework agnostic dashboard.

The integrations only have to translate their own request object into
``handle(...)`` arguments and turn the returned :class:`Response` into a native
response. Everything else — routing, JSON, the HTML page — lives here.

Endpoints (all relative to the mount path, ``/__jscoup`` by default, or to
``/`` when served by the standalone dashboard server):

====================================  ======================================
``GET  /``                            the single page UI (always reachable)
``POST /api/login``                   admin login, sets a session cookie
``POST /api/logout``                  clear the session cookie
``GET  /api/summary``                 counters, top endpoints, top actors
``GET  /api/timeline``                bucketed activity for the trace strip
``GET  /api/events``                  filtered list
``GET  /api/events/<id>``             full detail incl. SQL and breadcrumbs
``POST /api/events/<id>/resolve``     mark an event handled
``GET  /api/issues``                  events grouped by fingerprint
``GET  /api/targets``                 endpoints and services that can be run
``GET  /api/postman.json``            Postman Collection v2.1 of every HTTP target
``GET  /api/call-log``                every call (success too), newest first
``GET  /api/call-log/summary``        per-API call/success/failure totals
``POST /api/invoke``                  run one of them live
``POST /api/audit``                   static naming/style + route audit
``POST /api/purge``                   clear stored events
``GET  /api/health``                  liveness + config snapshot
``GET/POST /api/gateway/users``        list / create gateway users (admin-only)
``PUT   /api/gateway/users/<id>``      edit a user's allowed APIs / allowed IPs
``DELETE /api/gateway/users/<id>``     permanently delete a gateway user
``POST /api/gateway/users/<id>/revoke`` disable a gateway user without deleting it
``POST /api/gateway/users/<id>/restore`` re-enable a revoked gateway user
``POST /api/gateway/users/<id>/reset-password`` set a new password, invalidate its sessions
``POST /api/gateway/targets/<id>/public`` toggle whether a target needs no token
``POST /api/targets``                 manually catalogue an API not auto-discovered
``DELETE /api/targets/<id>``          hide an API from the catalogue and the gateway
``POST /api/targets/<id>/enable``     restore a hidden API
``PUT   /api/targets/<id>/description`` set the description shown on the docs page
``GET  /api/whoami``                  the caller's own client IP
``GET/POST /api/doc-groups``           list / create public API-doc groups (admin-only)
``PUT    /api/doc-groups/<slug>``      edit a group's title, APIs, categories, or allowed IPs
``DELETE /api/doc-groups/<slug>``      unpublish a group
====================================  ======================================

A doc group is a separate, admin-curated public page: ``GET /<slug>`` and
``GET /<slug>/data`` list exactly the APIs chosen when the group was created
via ``POST /api/doc-groups`` — a fixed menu, independent of any token — gated only by that group's own ``allowed_ips`` (empty/None
opens it to everyone). ``slug`` may be anything except ``api`` or ``gw``. Each
group may also assign its own ``categories`` override (target id -> a display
category specific to that group), for grouping the same API differently
across two published pages.

Everything except ``GET /`` and ``POST /api/login`` requires authentication:
either a signed session from ``dashboard_username``/``dashboard_password``, or
— when no login is configured — the legacy shared ``dashboard_token``.

When ``gateway_enabled`` is on, ``/gw/<target_id>`` and any published ``/<slug>``/``/<slug>/data`` doc group
are a **separate, independently-authenticated** surface (a gateway token, a
target explicitly marked public, or a group's own IP allow-list) — see
:mod:`jscoup.gateway`. These are the one part of JSCoup meant to be reachable
by non-admins, and are checked before, and instead of, the admin dashboard's
network gate and session gate.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..gateway import RateLimiter
from . import auth

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    headers: Optional[Dict[str, str]] = None

    def all_headers(self) -> Dict[str, str]:
        base = {
            "Content-Type": self.content_type,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
        }
        base.update(self.headers or {})
        return base


def json_response(data: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
    return Response(
        status=status,
        body=json.dumps(data, default=str, ensure_ascii=False).encode("utf-8"),
        headers=headers,
    )


class DashboardAPI:
    def __init__(self, jscoup: Any):
        self.jscoup = jscoup
        self._login_lock = threading.Lock()
        self._gateway_auth_lock = threading.Lock()
        self._gateway_limiter = RateLimiter(
            jscoup.config.gateway_rate_limit, jscoup.config.gateway_rate_window
        )

    def _allow_gateway_rate(self, key):
        c = self.jscoup.config
        return self.jscoup.gateway.allow_rate("invoke:" + key, c.gateway_rate_limit, c.gateway_rate_window)

    @property
    def _sessions(self):
        """Lazily-built :class:`~jscoup.dashboard.sessions.SessionStore`."""
        from .sessions import SessionStore
        import hashlib
        c = self.jscoup.config
        credential_id = self.jscoup._auth_credential_id if c.dashboard_password_hash == self.jscoup._initial_password_hash else hashlib.sha256((c.dashboard_password_hash or "").encode()).hexdigest()
        realm = json.dumps([c.auth_realm_id or [c.service_name, c.environment], c.dashboard_username, c.credential_epoch, credential_id])
        if not hasattr(self, "_session_store") or self._session_store.realm != realm:
            if hasattr(self, "_session_store"):
                self._session_store.revoke_all()
                self._session_store.close()
            self._session_store = SessionStore(c.dashboard_session_db_path, realm=realm)
        return self._session_store

    # -- routing ------------------------------------------------------------ #

    def handle(
        self,
        path: str,
        method: str = "GET",
        query: Optional[Dict[str, Any]] = None,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
        mount: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Response:
        query = query or {}
        headers = headers or {}
        method = method.upper()
        if body and len(body) > self.jscoup.config.dashboard_max_body_bytes:
            return json_response({"error": "Request body too large"}, 413)
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
        if method not in {"GET", "HEAD", "OPTIONS"}:
            from urllib.parse import urlsplit
            origin = lowered.get("origin")
            if lowered.get("sec-fetch-site") == "cross-site":
                return json_response({"error": "Cross-site request rejected"}, 403)
            if origin:
                expected = base_url
                try:
                    incoming = urlsplit(origin)
                    destination = urlsplit(expected or "")
                    valid_origin = incoming.scheme in ("http", "https") and incoming.netloc and (incoming.scheme, incoming.netloc) == (destination.scheme, destination.netloc)
                except ValueError:
                    valid_origin = False
                if not valid_origin:
                    return json_response({"error": "Origin rejected"}, 403)
        path = "/" + (path or "").strip("/")
        mount = self.jscoup.config.mount_path if mount is None else mount

        if not self.jscoup.config.dashboard_enabled:
            return json_response({"error": "Dashboard disabled"}, 404)

        try:
            # Picks up any route registered after install(app) was called
            # (e.g. a root route defined below it) — see refresh_targets().
            self.jscoup.refresh_targets()
        except Exception:
            pass

        # The gateway proxy surface, the docs page, and public doc groups all
        # have their own, independent auth (a gateway token, a public-target
        # flag, or a group's own allowed_ips) — checked before, and instead
        # of, the admin dashboard's network gate and session gate below. This
        # is the one part of JSCoup meant to be reachable by non-admins, so it
        # must never be blocked by dashboard_allowed_ips.
        if self.jscoup.config.gateway_enabled:
            if path.startswith("/gw/"):
                raw = path[len("/gw/"):]
                if raw == "login" and method == "POST":
                    return self._gateway_login(body, client_ip)
                return self._gateway_dispatch(raw, method, query, body, headers, base_url, client_ip)

            first_segment = path[1:].split("/", 1)[0] if len(path) > 1 else ""
            if first_segment and first_segment not in ("api", "gw") and method == "GET":
                group = self.jscoup.gateway.get_doc_group(first_segment)
                if group is not None:
                    if not auth.ip_allowed(client_ip, group.get("allowed_ips")):
                        return json_response({"error": "Access denied from this network location"}, 403)
                    remainder = path[1:].split("/", 1)
                    sub = remainder[1] if len(remainder) > 1 else ""
                    if sub == "":
                        return self._doc_group_page(mount, group)
                    if sub == "data":
                        return self._doc_group_data(group)
                    return json_response({"error": f"Unknown route: {path}"}, 404)

        # Network-level gate for the admin dashboard itself, ahead of
        # everything else including login.
        if not auth.ip_allowed(client_ip, self.jscoup.config.dashboard_allowed_ips):
            return json_response({"error": "Access denied from this network location"}, 403)

        if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}:
            return json_response({"error": "Method not allowed"}, 405)

        if path == "/api/login" and method == "POST":
            return self._login(body, client_ip)

        auth_error = self._authenticate(path, method, query, headers)
        if auth_error is not None:
            return auth_error

        if "window" in query and path in ("/api/events", "/api/issues", "/api/summary"):
            _, error = _int_query(query, "window", default=3600, minimum=1, maximum=2592000)
            if error is not None:
                return error
        if path in ("/", "") and method == "GET":
            return self._page(mount)
        if path == "/api/logout" and method == "POST":
            return self._logout(headers)
        if path == "/api/health":
            return json_response(self._health())
        if path == "/api/summary":
            return json_response(self.jscoup.storage.summary(since=_since(query)))
        if path == "/api/timeline":
            buckets, error = _int_query(query, "buckets", default=60, minimum=1, maximum=1000)
            if error is not None:
                return error
            window_seconds, error = _int_query(query, "window", default=3600, minimum=1, maximum=86400 * 30)
            if error is not None:
                return error
            return json_response(
                {"buckets": self.jscoup.storage.timeline(buckets=buckets, window_seconds=window_seconds)}
            )
        if path == "/api/events" and method == "GET":
            events, error = self._events(query)
            if error is not None:
                return error
            return json_response(events)
        if path == "/api/issues":
            limit, error = _int_query(query, "limit", default=50, minimum=1, maximum=500)
            if error is not None:
                return error
            return json_response({"issues": self.jscoup.storage.issues(limit=limit, since=_since(query))})
        if path == "/api/targets" and method == "GET":
            include_disabled = str(query.get("include_disabled") or "").lower() in ("1", "true")
            targets = self._enrich_targets(self.jscoup.registry.to_list(include_disabled=include_disabled))
            if self.jscoup.config.gateway_enabled:
                gw = self.jscoup.gateway
                for item in targets:
                    item["is_public"] = gw.is_public(item["id"])
            return json_response({"targets": targets})
        if path == "/api/targets" and method == "POST":
            return self._add_manual_target(body)
        if path.startswith("/api/targets/") and path.endswith("/enable") and method == "POST":
            target_id = path[len("/api/targets/"):-len("/enable")]
            self.jscoup.gateway.set_target_disabled(target_id, False)
            self.jscoup.registry.enable(target_id)
            return json_response({"ok": True})
        if path.startswith("/api/targets/") and path.endswith("/description") and method == "PUT":
            target_id = path[len("/api/targets/"):-len("/description")]
            payload = _json_body(body)
            description = str(payload.get("description") or "")
            self.jscoup.gateway.set_target_description(target_id, description)
            self.jscoup.registry.set_description(target_id, description)
            return json_response({"ok": True})
        if path.startswith("/api/targets/") and method == "DELETE":
            target_id = path[len("/api/targets/"):]
            self.jscoup.gateway.set_target_disabled(target_id, True)
            self.jscoup.registry.disable(target_id)
            return json_response({"ok": True})
        if path == "/api/whoami":
            return json_response({"ip": client_ip})
        if path == "/api/postman.json" and method == "GET":
            return self._postman_export(base_url)
        if path == "/api/call-log" and method == "GET":
            return self._call_log(query)
        if path == "/api/call-log/summary" and method == "GET":
            return self._call_log_summary(query)
        if path == "/api/gateway/users" and method == "GET":
            return json_response({"users": [u.to_dict() for u in self.jscoup.gateway.list_users()]})
        if path == "/api/gateway/users" and method == "POST":
            return self._gateway_create_user(body)
        if path.startswith("/api/gateway/users/") and path.endswith("/revoke") and method == "POST":
            user_id = path[len("/api/gateway/users/"):-len("/revoke")]
            ok = self.jscoup.gateway.revoke(user_id)
            return json_response({"ok": ok})
        if path.startswith("/api/gateway/users/") and path.endswith("/restore") and method == "POST":
            user_id = path[len("/api/gateway/users/"):-len("/restore")]
            ok = self.jscoup.gateway.restore(user_id)
            return json_response({"ok": ok})
        if path.startswith("/api/gateway/users/") and path.endswith("/reset-password") and method == "POST":
            user_id = path[len("/api/gateway/users/"):-len("/reset-password")]
            return self._gateway_reset_password(user_id, body)
        if path.startswith("/api/gateway/users/") and method == "PUT":
            user_id = path[len("/api/gateway/users/"):]
            return self._gateway_update_user(user_id, body)
        if path.startswith("/api/gateway/users/") and method == "DELETE":
            user_id = path[len("/api/gateway/users/"):]
            ok = self.jscoup.gateway.delete_user(user_id)
            return json_response({"ok": ok})
        if path.startswith("/api/gateway/targets/") and path.endswith("/public") and method == "POST":
            target_id = path[len("/api/gateway/targets/"):-len("/public")]
            payload = _json_body(body)
            self.jscoup.gateway.set_public(target_id, bool(payload.get("public")))
            return json_response({"ok": True})
        if path == "/api/doc-groups" and method == "GET":
            return json_response({"groups": self.jscoup.gateway.list_doc_groups(), "mount_path": mount})
        if path == "/api/doc-groups" and method == "POST":
            return self._create_doc_group(body)
        if path.startswith("/api/doc-groups/") and method == "PUT":
            slug = path[len("/api/doc-groups/"):]
            return self._update_doc_group(slug, body)
        if path.startswith("/api/doc-groups/") and method == "DELETE":
            slug = path[len("/api/doc-groups/"):]
            ok = self.jscoup.gateway.delete_doc_group(slug)
            return json_response({"ok": ok})
        if path == "/api/invoke" and method == "POST":
            return self._invoke(body)
        if path == "/api/audit" and method == "POST":
            return self._audit(body)
        if path == "/api/check-apis" and method == "POST":
            return self._check_apis(body)
        if path == "/api/purge" and method == "POST":
            deleted = self.jscoup.storage.purge()
            return json_response({"deleted": deleted})
        if path.startswith("/api/events/"):
            parts = path[len("/api/events/"):].split("/")
            event_id = parts[0]
            if len(parts) > 1 and parts[1] == "resolve" and method == "POST":
                payload = _json_body(body)
                ok = self.jscoup.storage.mark_resolved(event_id, bool(payload.get("resolved", True)))
                return json_response({"ok": ok})
            event = self.jscoup.storage.get(event_id)
            if event is None:
                return json_response({"error": "Event not found"}, 404)
            data = event.to_dict()
            data["related"] = [
                e.to_dict()
                for e in self.jscoup.storage.list(limit=8, fingerprint=event.fingerprint)
                if e.id != event.id
            ]
            return json_response(data)

        return json_response({"error": f"Unknown route: {path}"}, 404)

    # -- handlers ----------------------------------------------------------- #

    def _page(self, mount: str) -> Response:
        index = os.path.join(_STATIC_DIR, "index.html")
        with open(index, "rb") as handle:
            html = handle.read()
        html = html.replace(b"__JSCOUP_MOUNT__", mount.encode())
        html = html.replace(b"__JSCOUP_SERVICE__", str(self.jscoup.config.service_name).encode())
        html = html.replace(b"__JSCOUP_ENV__", str(self.jscoup.config.environment).encode())
        return Response(body=html, content_type="text/html; charset=utf-8")

    def _events(self, query: Dict[str, Any]) -> "tuple[Optional[Dict[str, Any]], Optional[Response]]":
        limit, error = _int_query(query, "limit", default=50, minimum=1, maximum=200)
        if error is not None:
            return None, error
        offset, error = _int_query(query, "offset", default=0, minimum=0, maximum=10_000_000)
        if error is not None:
            return None, error
        filters = {
            "status": query.get("status"),
            "category": query.get("category"),
            "kind": query.get("kind"),
            "severity": query.get("severity"),
            "search": query.get("search"),
            "actor": query.get("actor"),
            "fingerprint": query.get("fingerprint"),
            "simulation_id": query.get("simulation_id"),
            "since": _since(query),
        }
        filters = {k: v for k, v in filters.items() if v}
        events = self.jscoup.storage.list(limit=limit, offset=offset, **filters)
        return {
            "events": [_summary_row(e) for e in events],
            "total": self.jscoup.storage.count(**filters),
            "limit": limit,
            "offset": offset,
        }, None

    def _safe_base_url(self, requested: Optional[str]) -> "tuple[Optional[str], Optional[Response]]":
        """Returns ``(base_url, None)`` on success or ``(None, error_response)``.
        A destination is only honored when it matches the configured
        ``base_url`` or ``allowed_base_urls``; otherwise this would be a live
        server making a request to anywhere named (SSRF).

        Deliberately takes no per-request "fallback" parameter: a caller
        controls the incoming request's Host header just as directly as a
        JSON field, so falling back to it would let a spoofed Host header
        bypass this check entirely.
        """
        config = self.jscoup.config
        allowed = [u for u in ([config.base_url] + list(config.allowed_base_urls)) if u]
        candidate = requested or config.base_url
        if not candidate:
            return None, json_response(
                {"error": "No destination available: set JSCoupConfig.base_url, or supply "
                          "a base_url that matches allowed_base_urls"},
                400,
            )
        if any(candidate == u or candidate.startswith(u.rstrip("/") + "/") or candidate.rstrip("/") == u.rstrip("/") for u in allowed):
            return candidate, None
        return None, json_response(
            {"error": "base_url is not in allowed_base_urls (or the configured base_url)"}, 400
        )

    def _invoke(self, body: Optional[bytes]) -> Response:
        if not self.jscoup.config.allow_live_invoke:
            return json_response({"error": "Live invocation is disabled by configuration"}, 403)
        payload = _json_body(body)
        target_id = payload.get("target_id")
        if not target_id:
            return json_response({"error": "target_id is required"}, 400)
        resolved_base_url, error = self._safe_base_url(payload.get("base_url"))
        if error is not None:
            return error
        result = self.jscoup.simulator.invoke(
            target_id,
            params=payload.get("params") or {},
            token=payload.get("token") or None,
            base_url=resolved_base_url,
            method=payload.get("method"),
            headers=payload.get("headers"),
        )
        return json_response(result)

    def _audit(self, body: Optional[bytes]) -> Response:
        if not self.jscoup.config.audit_enabled:
            return json_response({"error": "Code audit disabled"}, 403)
        payload = _json_body(body)
        paths = payload.get("paths") or None
        if paths is not None and not isinstance(paths, list):
            return json_response({"error": "paths must be a list of strings"}, 400)
        findings = self.jscoup.audit_code(paths=[str(p) for p in paths] if paths else None)
        return json_response({"findings": [f.to_dict() for f in findings]})

    def _gateway_create_user(self, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        label = str(payload.get("label") or "").strip()
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if len(username) > 256 or len(password) > 1024:
            return json_response({"error": "Credentials exceed length limit"}, 400)
        if not label or not username or not password:
            return json_response({"error": "label, username, and password are required"}, 400)
        allowed = payload.get("allowed_target_ids")
        if allowed != "*" and not isinstance(allowed, list):
            return json_response({"error": "allowed_target_ids must be a list of target ids, or \"*\""}, 400)
        allowed_ips = payload.get("allowed_ips") or None
        if allowed_ips is not None and not isinstance(allowed_ips, list):
            return json_response({"error": "allowed_ips must be a list of IPs/CIDR ranges, or omitted"}, 400)
        downstream_token = payload.get("downstream_token") or None
        categories = _clean_categories(payload.get("categories"))
        try:
            user = self.jscoup.gateway.create_user(
                label, username, password,
                allowed if allowed == "*" else [str(t) for t in allowed],
                allowed_ips=[str(ip) for ip in allowed_ips] if allowed_ips else None,
                downstream_token=downstream_token,
                categories=categories,
            )
        except Exception as exc:  # e.g. UNIQUE constraint on a duplicate username
            return json_response({"error": f"Could not create user: {exc}"}, 400)
        return json_response({"user": user.to_dict()})

    def _gateway_update_user(self, user_id: str, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        allowed = payload.get("allowed_target_ids")
        if allowed is not None and allowed != "*" and not isinstance(allowed, list):
            return json_response({"error": "allowed_target_ids must be a list of target ids, or \"*\""}, 400)
        allowed_ips = payload.get("allowed_ips")
        if allowed_ips is not None and not isinstance(allowed_ips, list):
            return json_response({"error": "allowed_ips must be a list of IPs/CIDR ranges"}, 400)
        ok = self.jscoup.gateway.update_permissions(
            user_id,
            allowed_target_ids=(allowed if allowed == "*" else [str(t) for t in allowed]) if allowed is not None else None,
            allowed_ips=[str(ip) for ip in allowed_ips] if allowed_ips is not None else None,
            categories=_clean_categories(payload["categories"]) if "categories" in payload else None,
        )
        return json_response({"ok": ok})

    def _gateway_reset_password(self, user_id: str, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        password = str(payload.get("password") or "")
        if len(password) > 1024:
            return json_response({"error": "Credentials exceed length limit"}, 400)
        if len(password) < 8:
            return json_response({"error": "password must be at least 8 characters"}, 400)
        ok = self.jscoup.gateway.reset_password(user_id, password)
        return json_response({"ok": ok})

    def _add_manual_target(self, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        method = str(payload.get("method") or "").strip()
        path = str(payload.get("path") or "").strip()
        if not method or not path.startswith("/"):
            return json_response({"error": "method and a path starting with \"/\" are required"}, 400)
        name = str(payload.get("name") or "").strip() or None
        description = str(payload.get("description") or "")
        # Persisted in the gateway's own database so every worker process
        # picks it up on its next refresh_targets() call, then applied to
        # this process's Registry immediately so this same response — and
        # anything else this process serves before its next refresh — sees
        # it without waiting.
        self.jscoup.gateway.add_manual_target(method, path, name=name, description=description)
        target = self.jscoup.registry.add_manual(method, path, name=name, description=description)
        return json_response({"target": target.to_dict()})

    def _enrich_targets(self, targets: list) -> list:
        """Add ``expected_responses`` — an example body for every status the
        API can plausibly return: an explicitly approved developer example,
        then a synthetic default. Captured telemetry is never published (see :mod:`jscoup.examples`)."""
        from ..examples import build_expected_responses, parse_preview

        config = self.jscoup.config
        # JSCoup only calls APIs over HTTP, so only HTTP APIs are ever listed.
        targets = [item for item in targets if item.get("kind") == "http"]
        try:
            gateway = self.jscoup.gateway if config.gateway_enabled else None
        except Exception:
            gateway = None
        for item in targets:
            # Whether the gateway lets a caller in without a gateway token.
            # Unknown (None) when the gateway is off, so the page never blocks on a guess.
            try:
                item["public"] = bool(self._gateway_open(gateway, item["id"])) if gateway is not None else None
            except Exception:
                item["public"] = None
            # A token-requiring API that accepts the API's own token through the gateway.
            item["accepts_own_token"] = bool(
                item.get("requires_auth") and self.jscoup.config.gateway_forward_own_tokens
            )
            target = self.jscoup.registry.get(item["id"])
            seen: Dict[int, Any] = {}
            overrides = dict(target.response_examples) if target is not None else {}
            params = target.params if target is not None else []
            item["expected_responses"] = build_expected_responses(
                item["method"], params, bool(item.get("requires_auth")), seen=seen, overrides=overrides,
            )
        return targets

    def _postman_export(self, base_url: Optional[str]) -> Response:
        from ..postman import build_postman_collection

        targets = self._enrich_targets(self.jscoup.registry.to_list())
        collection = build_postman_collection(
            self.jscoup.config.service_name, targets, self.jscoup.config.base_url or base_url or "http://localhost",
        )
        return Response(
            body=json.dumps(collection, indent=2).encode("utf-8"),
            content_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{self.jscoup.config.service_name}.postman_collection.json"'},
        )

    def _call_log(self, query: Dict[str, Any]) -> Response:
        if not self.jscoup.config.call_log_enabled:
            return json_response({"enabled": False, "calls": [], "total": 0})
        limit, error = _int_query(query, "limit", default=100, minimum=1, maximum=500)
        if error is not None:
            return error
        offset, error = _int_query(query, "offset", default=0, minimum=0, maximum=10_000_000)
        if error is not None:
            return error
        ok_raw = str(query.get("ok") or "").lower()
        ok = True if ok_raw in ("1", "true") else False if ok_raw in ("0", "false") else None
        since = _since(query)
        log = self.jscoup.call_log
        return json_response({
            "enabled": True,
            "retention_days": self.jscoup.config.call_log_retention_days,
            "calls": log.recent(limit=limit, offset=offset, name=query.get("name") or None, ok=ok, since=since),
            "total": log.count(since=since),
        })

    def _call_log_summary(self, query: Dict[str, Any]) -> Response:
        if not self.jscoup.config.call_log_enabled:
            return json_response({"enabled": False, "total_calls": 0, "succeeded": 0, "failed": 0, "apis": []})
        data = self.jscoup.call_log.summary(since=_since(query))
        data.update(enabled=True, retention_days=self.jscoup.config.call_log_retention_days)
        return json_response(data)

    def _create_doc_group(self, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        slug = str(payload.get("slug") or "").strip()
        title = str(payload.get("title") or "").strip() or slug
        target_ids = payload.get("target_ids") or []
        allowed_ips = payload.get("allowed_ips") or None
        categories = payload.get("categories") or None
        if not slug:
            return json_response({"error": "slug is required"}, 400)
        if not isinstance(target_ids, list) or not target_ids:
            return json_response({"error": "target_ids must be a non-empty list"}, 400)
        target_ids = [str(t) for t in target_ids]
        try:
            group = self.jscoup.gateway.create_doc_group(
                slug, title, target_ids,
                allowed_ips=[str(ip) for ip in allowed_ips] if allowed_ips else None,
                categories={str(k): str(v) for k, v in categories.items()} if categories else None,
            )
        except ValueError as exc:
            return json_response({"error": str(exc)}, 400)
        return json_response({"group": group})

    def _update_doc_group(self, slug: str, body: Optional[bytes]) -> Response:
        payload = _json_body(body)
        title = payload.get("title")
        target_ids = payload.get("target_ids")
        allowed_ips = payload.get("allowed_ips")
        categories = payload.get("categories")
        ok = self.jscoup.gateway.update_doc_group(
            slug,
            title=str(title).strip() if title is not None else None,
            target_ids=[str(t) for t in target_ids] if target_ids is not None else None,
            allowed_ips=[str(ip) for ip in allowed_ips] if allowed_ips is not None else None,
            categories={str(k): str(v) for k, v in categories.items()} if categories is not None else None,
        )
        if not ok:
            return json_response({"error": f"No group with slug {slug!r}"}, 404)
        return json_response({"group": self.jscoup.gateway.get_doc_group(slug)})

    def _gateway_login(self, body: Optional[bytes], client_ip: Optional[str]) -> Response:
        payload = _json_body(body)
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if len(username) > 256 or len(password) > 1024:
            return json_response({"error": "Credentials exceed length limit"}, 400)
        gw = self.jscoup.gateway
        source = client_ip or "unknown"
        if not gw.allow_rate("login-source:" + source, 30, 60) or not gw.allow_rate("login:" + source + ":" + username.lower(), 5, 300):
            return json_response({"error": "Too many login attempts. Try again later."}, 429)
        session = gw.login(username, password, client_ip=client_ip)
        if session is None:
            return json_response({"error": "Invalid credentials, or not allowed from this network"}, 401)
        return json_response({
            "token": session["token"],
            "expires_at": session["expires_at"],
            "user": session["user"].to_dict(),
        })

    def _gateway_open(self, gw: Any, target_id: str) -> bool:
        """True when a caller needs no gateway token for this target: an admin
        marked it public, or (opt-in ``gateway_open_tokenless_apis``) the API
        needs no token of its own. An API that requires a token is never opened
        by the setting."""
        if gw.is_public(target_id):
            return True
        if not self.jscoup.config.gateway_open_tokenless_apis:
            return False
        target = self.jscoup.registry.get(target_id)
        return bool(target is not None and target.kind == "http" and not target.requires_auth)

    def _gateway_accepts_own_token(self, target_id: str) -> bool:
        """True when a caller may present the API's *own* token instead of a
        gateway token (opt-in ``gateway_forward_own_tokens``): only for an API
        that needs a token, since the API itself is what checks it."""
        if not self.jscoup.config.gateway_forward_own_tokens:
            return False
        target = self.jscoup.registry.get(target_id)
        return bool(target is not None and target.kind == "http" and target.requires_auth)

    def _gateway_dispatch(
        self, raw_target: str, method: str, query: Dict[str, Any], body: Optional[bytes],
        headers: Dict[str, str], base_url: Optional[str], client_ip: Optional[str],
    ) -> Response:
        # Ignores the caller-supplied base_url (derived from the incoming
        # request's own Host header) and uses JSCoupConfig.base_url instead,
        # since this is a loopback call and the external and internal
        # addresses aren't always the same (e.g. behind Docker port mapping).
        base_url = self.jscoup.config.base_url
        if raw_target == "my-logs":
            return self._gateway_my_logs(headers, client_ip)
        if raw_target == "my-targets":
            return self._gateway_my_targets(headers, client_ip)

        gw = self.jscoup.gateway
        target_id = raw_target
        target = self.jscoup.registry.get(target_id)
        if target is None:
            return json_response({"error": f"Unknown target: {target_id}"}, 404)
        if target.kind != "http":
            return json_response({"error": f"Unknown target: {target_id}"}, 404)
        # A method policy applies to every call, public or authenticated: a
        # GET must not be able to trigger a mutating API.
        expected_method = (target.method or "GET").upper()
        if method.upper() != expected_method:
            return json_response({"error": f"This API only accepts {expected_method}"}, 405)
        lowered = {str(k).lower(): v for k, v in headers.items()}
        header_value = (lowered.get("authorization") or "").strip()
        token = header_value[7:].strip() if header_value.lower().startswith("bearer ") else (header_value or None)

        user = None
        if not self._gateway_open(gw, target_id):
            user = gw.authenticate(token)
            if user is None and token and self._gateway_accepts_own_token(target_id):
                # Not a gateway token, so it can only be the API's own token:
                # forward it below and let the API accept or reject it. Limited
                # per credential so this path cannot be used to hammer the app.
                from ..identity import fingerprint_token

                if not self._allow_gateway_rate("own:" + fingerprint_token(token)):
                    return json_response({"error": "Rate limit exceeded"}, 429)
            elif user is None:
                if self._gateway_accepts_own_token(target_id):
                    return json_response({"error": "This API needs a token: send its own token (for example the one its login API returns) as the Bearer token"}, 401)
                return json_response({"error": "Invalid, missing, or expired gateway token"}, 401)
            elif not user.allows(target_id):
                return json_response({"error": "This token is not permitted to call this API"}, 403)
            elif not user.allows_ip(client_ip):
                # Defense in depth beyond the login-time IP check.
                return json_response({"error": "Access denied from this network location"}, 403)
            elif not self._allow_gateway_rate(user.id):
                return json_response({"error": "Rate limit exceeded"}, 429)
        elif not self._allow_gateway_rate(f"public:{target_id}"):
            return json_response({"error": "Rate limit exceeded"}, 429)

        params = dict(query)
        params.update(_json_body(body))
        # The admin-configured downstream_token (set when the user was
        # created) is the default — but some APIs need a token that's
        # specific to the caller, not the whole sub-user, so an explicit
        # X-Downstream-Token header on this call overrides it.
        # On an open API nobody was authenticated by the gateway, so a bearer
        # token on the call can only be the API's own token: forward it. (On a
        # gated API the bearer is the gateway token and is never forwarded.)
        downstream_token = lowered.get("x-downstream-token") or (
            user.downstream_token if user else token
        )
        result = self.jscoup.simulator.invoke(
            target_id, params=params, token=downstream_token, base_url=base_url,
        )
        ok = bool(result.get("ok"))
        status_code = result.get("status_code")
        gw.log_call(user.id if user else None, target_id, ok, status_code)
        # A gateway caller never sees a traceback, SQL, or diagnosis; that
        # stays admin-only via the session-gated /api/invoke above. A
        # service target that raised has only "error", a raw exception
        # message that must never reach this surface.
        if "response" in result:
            response_payload = result.get("response")
        elif "result" in result:
            response_payload = result.get("result")
        else:
            response_payload = {"error": "The call failed", "event_id": result.get("event_id")}
        stripped = {
            "ok": ok,
            "status_code": status_code,
            "content_type": result.get("content_type"),
            "response": response_payload,
        }
        status = status_code if isinstance(status_code, int) and 100 <= status_code <= 599 else (200 if ok else 502)
        return json_response(stripped, status)

    def _gateway_my_logs(self, headers: Dict[str, str], client_ip: Optional[str] = None) -> Response:
        lowered = {str(k).lower(): v for k, v in headers.items()}
        header_value = (lowered.get("authorization") or "").strip()
        token = header_value[7:].strip() if header_value.lower().startswith("bearer ") else (header_value or None)
        user = self.jscoup.gateway.authenticate(token)
        if user is None:
            return json_response({"error": "Invalid or missing gateway token"}, 401)
        if not user.allows_ip(client_ip):
            # Same per-user network restriction the proxy path already enforces.
            return json_response({"error": "Access denied from this network location"}, 403)
        if not self._allow_gateway_rate(user.id):
            return json_response({"error": "Rate limit exceeded"}, 429)
        return json_response({"calls": self.jscoup.gateway.list_calls(user.id)})

    def _gateway_my_targets(self, headers: Dict[str, str], client_ip: Optional[str] = None) -> Response:
        """The subset of the API catalogue this sub-user is actually allowed
        to call — lets a restricted login (see /gw/login) build its own
        picker without ever needing an admin session."""
        lowered = {str(k).lower(): v for k, v in headers.items()}
        header_value = (lowered.get("authorization") or "").strip()
        token = header_value[7:].strip() if header_value.lower().startswith("bearer ") else (header_value or None)
        user = self.jscoup.gateway.authenticate(token)
        if user is None:
            return json_response({"error": "Invalid or missing gateway token"}, 401)
        if not user.allows_ip(client_ip):
            return json_response({"error": "Access denied from this network location"}, 403)
        if not self._allow_gateway_rate(user.id):
            return json_response({"error": "Rate limit exceeded"}, 429)
        allowed = self._enrich_targets([t for t in self.jscoup.registry.to_list() if user.allows(t["id"])])
        for t in allowed:
            if t["id"] in user.categories:
                t["category"] = user.categories[t["id"]]
        return json_response({
            "targets": allowed,
            "user": {"label": user.label, "username": user.username},
        })

    def _render_docs_html(self, mount: str, data_url: str) -> Response:
        docs_path = os.path.join(_STATIC_DIR, "docs.html")
        with open(docs_path, "rb") as handle:
            html = handle.read()
        html = html.replace(b"__JSCOUP_SERVICE__", str(self.jscoup.config.service_name).encode())
        html = html.replace(b"__JSCOUP_DATA_URL__", data_url.encode())
        html = html.replace(b"__JSCOUP_GW_BASE__", f"{mount}/gw/".encode())
        return Response(body=html, content_type="text/html; charset=utf-8")



    def _doc_group_page(self, mount: str, group: Dict[str, Any]) -> Response:
        return self._render_docs_html(mount, f"{mount}/{group['slug']}/data")

    def _doc_group_data(self, group: Dict[str, Any]) -> Response:
        """A named, admin-curated subset of the catalogue — always the exact
        set chosen when the group was created, regardless of any token; a
        group is a fixed public menu, not another auth surface."""
        wanted = set(group["target_ids"])
        categories = group.get("categories") or {}
        visible = self._enrich_targets([t for t in self.jscoup.registry.to_list() if t["id"] in wanted])
        for t in visible:
            if t["id"] in categories:
                t["category"] = categories[t["id"]]
        return json_response({
            "service": self.jscoup.config.service_name,
            "title": group["title"],
            "targets": visible,
            "authenticated_as": None,
        })

    def _check_apis(self, body: Optional[bytes]) -> Response:
        if not self.jscoup.config.allow_live_invoke:
            return json_response({"error": "Live invocation is disabled by configuration"}, 403)
        payload = _json_body(body)
        resolved_base_url, error = self._safe_base_url(payload.get("base_url"))
        if error is not None:
            return error
        results = self.jscoup.check_apis(
            token=payload.get("token") or None,
            base_url=resolved_base_url,
            include_params=bool(payload.get("include_params")),
        )
        return json_response({"results": [r.to_dict() for r in results]})

    def _health(self) -> Dict[str, Any]:
        from .. import __version__

        config = self.jscoup.config
        return {
            "ok": True,
            "library": "JSCoup",
            "version": __version__,
            "service": config.service_name,
            "environment": config.environment,
            "mount_path": config.mount_path,
            "storage": type(self.jscoup.storage).__name__,
            "db_path": getattr(self.jscoup.storage, "db_path", None),
            "analyzers": [a.name for a in self.jscoup.analyzers.analyzers],
            "targets": len(self.jscoup.registry.all()),
            "live_invoke": config.allow_live_invoke,
            "capture_success": config.capture_success,
            "gateway_enabled": config.gateway_enabled,
            "before_store_failures": self.jscoup._before_store_failures,
            "audit_enabled": config.audit_enabled,
            "metrics": self.jscoup.metrics(),
            "time": time.time(),
        }

    def _authenticate(
        self, path: str, method: str, query: Dict[str, Any], headers: Dict[str, str]
    ) -> Optional[Response]:
        config = self.jscoup.config
        if not config.dashboard_username:
            # No admin login configured — fall back to the legacy shared token, unchanged.
            return self._check_token(query, headers)

        if path in ("/", "") and method == "GET":
            return None  # the page shell must always load so the login form can render

        username = self._sessions.verify(_read_cookie(headers, auth.SESSION_COOKIE_NAME))
        if username == config.dashboard_username:
            return None
        return json_response({"error": "Login required", "login_required": True}, 401)

    def _login(self, body: Optional[bytes], client_ip=None) -> Response:
        config = self.jscoup.config
        if not config.dashboard_username:
            return json_response({"error": "No dashboard login is configured"}, 400)
        payload = _json_body(body)
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        if len(username) > 256 or len(password) > 1024:
            return json_response({"error": "Credentials exceed length limit"}, 400)
        source = client_ip or "unknown"
        pair = "login:" + source + ":" + username.lower()
        sessions = self._sessions
        if not sessions.allow_rate("source:" + source, 30, 60) or not sessions.allow_rate(pair, config.dashboard_login_max_attempts, config.dashboard_login_lockout_seconds):
            return json_response({"error": "Too many login attempts. Try again later."}, 429)
        # Always perform the password verification, even for an unknown name.
        valid_password = auth.verify_password(password, config.dashboard_password_hash)
        if not (auth.verify_username(username, config.dashboard_username) and valid_password):
            return json_response({"error": "Invalid username or password"}, 401)

        token = self._sessions.create(username, config.dashboard_session_hours * 3600)
        cookie = auth.build_set_cookie_header(
            auth.SESSION_COOKIE_NAME, token,
            max_age=int(config.dashboard_session_hours * 3600),
            secure=config.dashboard_cookie_secure,
        )
        return json_response({"ok": True, "username": username}, headers={"Set-Cookie": cookie})

    def _logout(self, headers: Dict[str, str]) -> Response:
        # Immediately revoked server-side, not just cleared client-side.
        self._sessions.revoke(_read_cookie(headers, auth.SESSION_COOKIE_NAME))
        cookie = auth.build_set_cookie_header(
            auth.SESSION_COOKIE_NAME, "", max_age=None, secure=self.jscoup.config.dashboard_cookie_secure
        )
        return json_response({"ok": True}, headers={"Set-Cookie": cookie})

    def _check_token(self, query: Dict[str, Any], headers: Dict[str, str]) -> Optional[Response]:
        expected = self.jscoup.config.dashboard_token
        if not expected:
            return None
        lowered = {str(k).lower(): v for k, v in headers.items()}
        provided = lowered.get("x-jscoup-token") or ""
        import hmac
        if not hmac.compare_digest(str(provided).encode(), str(expected).encode()):
            return json_response({"error": "Dashboard token required"}, 401)
        return None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _summary_row(event: Any) -> Dict[str, Any]:
    diagnosis = event.diagnosis
    return {
        "id": event.id,
        "ts": event.ts,
        "kind": event.kind,
        "name": event.name,
        "status": event.status,
        "severity": event.severity,
        "category": event.category,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "duration_ms": event.duration_ms,
        "error_type": event.error_type,
        "error_message": (event.error_message or "")[:240],
        "title": diagnosis.title if diagnosis else None,
        "subtype": diagnosis.subtype if diagnosis else None,
        "actor": event.actor.label if event.actor else None,
        "token_fingerprint": event.actor.token_fingerprint if event.actor else None,
        "query_count": event.query_count,
        "db_time_ms": event.db_time_ms,
        "fingerprint": event.fingerprint,
        "resolved": event.resolved,
        "simulation_id": event.simulation_id,
    }


def _int_query(
    query: Dict[str, Any], key: str, default: int, minimum: int, maximum: int,
) -> "tuple[Optional[int], Optional[Response]]":
    """Parse ``query[key]`` as a bounded integer, or return a clear 400
    instead of letting malformed input reach application code (e.g. an
    unvalidated ``buckets=0`` reaching ``storage.timeline()``)."""
    raw = query.get(key)
    if raw is None or raw == "":
        return default, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, json_response({"error": f"{key!r} must be an integer"}, 400)
    if value < minimum or value > maximum:
        return None, json_response(
            {"error": f"{key!r} must be between {minimum} and {maximum}"}, 400
        )
    return value, None


def _clean_categories(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v).strip() for k, v in value.items() if str(v).strip()}


def _json_body(body: Optional[bytes]) -> Dict[str, Any]:
    if not body:
        return {}
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_cookie(headers: Dict[str, str], name: str) -> Optional[str]:
    lowered = {str(k).lower(): v for k, v in headers.items()}
    raw = lowered.get("cookie", "") or ""
    for part in raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None


def _since(query: Dict[str, Any]) -> Optional[float]:
    window = query.get("window")
    if not window:
        return None
    try:
        return time.time() - float(window)
    except (TypeError, ValueError):
        return None
