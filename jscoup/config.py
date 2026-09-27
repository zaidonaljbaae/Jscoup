# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Configuration for a :class:`jscoup.JSCoup` instance."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

DEFAULT_MOUNT_PATH = "/__jscoup"
DEFAULT_DB_PATH = ".jscoup/jscoup.db"

DEFAULT_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "set-cookie",
    "session",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
    "private_key",
    "client_secret",
)

DEFAULT_TOKEN_SOURCES = (
    ("header", "Authorization"),
    ("header", "X-API-Key"),
    ("header", "X-Auth-Token"),
    ("query", "access_token"),
    ("cookie", "session_token"),
)


@dataclass
class JSCoupConfig:
    """Every knob of the library lives here so nothing is hard coded.

    Attributes are intentionally plain values so a config can be built from a
    dict, an env file or a framework settings module.
    """

    # identity of the instrumented process
    service_name: str = "service"
    environment: str = field(default_factory=lambda: os.getenv("JSCOUP_ENV", "local"))
    release: Optional[str] = None

    # storage
    db_path: str = DEFAULT_DB_PATH
    max_events: int = 5_000
    retention_days: int = 14

    # dashboard
    mount_path: str = DEFAULT_MOUNT_PATH
    dashboard_enabled: bool = True  # master switch: DashboardAPI.handle() refuses everything when False
    dashboard_mount_in_app: bool = True  # install_flask/install_fastapi also mount it into the app's own router;
    # set False when serving it only via JSCoup.run_dashboard() as a standalone server
    dashboard_token: Optional[str] = None  # legacy: shared-secret gate if set and no login is configured
    allow_live_invoke: bool = False  # off by default: running a registered function on demand must be opt-in
    dashboard_local_dev: bool = False  # explicit escape hatch for a throwaway local run with no credentials

    # dashboard login (admin username/password, replaces the shared token when set)
    dashboard_username: Optional[str] = None
    dashboard_password_hash: Optional[str] = None  # set via JSCoup(dashboard_password=...); never plaintext
    # Session state lives in a small local SQLite table (see
    # jscoup.dashboard.sessions.SessionStore) so sessions can be revoked and
    # shared across worker processes without a shared signing secret.
    dashboard_session_db_path: str = ".jscoup/dashboard_sessions.db"
    dashboard_session_hours: float = 12.0
    dashboard_cookie_secure: Optional[bool] = None
    dashboard_login_max_attempts: int = 5
    dashboard_login_lockout_seconds: float = 300.0
    # Network-level gate, checked before login: None/[] means unrestricted.
    # Entries are exact IPs ("203.0.113.4") or CIDR ranges ("10.0.0.0/8").
    dashboard_allowed_ips: Optional[List[str]] = None
    # Off by default: the client-supplied X-Forwarded-For is only trusted
    # when the app genuinely sits behind a proxy that overwrites it.
    trust_proxy_headers: bool = False

    # API Gateway — off by default. When on, the admin can create users with
    # their own tokens and a curated set of APIs they may call (proxied
    # through Simulator), and mark specific targets public. See jscoup/gateway.py.
    gateway_enabled: bool = False
    gateway_db_path: str = ".jscoup/gateway.db"
    gateway_rate_limit: int = 120  # max requests per token per gateway_rate_window
    gateway_rate_window: float = 60.0
    # Treat an API that needs no token of its own as open through the gateway:
    # callable with no gateway token, as if an admin had marked it public. Off by
    # default. APIs that do need a token are never opened by this.
    gateway_open_tokenless_apis: bool = False
    # Let a caller reach an API that needs a token by presenting that API's own
    # token (for example the one its login route issued) as the Bearer token.
    # The gateway forwards it and the API itself accepts or rejects it, exactly as
    # for a direct call. A bearer that is a valid gateway login token is still
    # treated as one (permissions, IP list, downstream token). Off by default.
    gateway_forward_own_tokens: bool = False
    gateway_token_ttl_hours: float = 1.0  # how long a POST /gw/login session stays valid before it must be reissued

    # A cheap, always-on record of every call (successes too), separate from
    # the full event pipeline that capture_success gates — feeds the
    # Overview/Events "all calls" views and real response examples. On by
    # default; set call_log_enabled=False to turn it off entirely. Rows older
    # than call_log_retention_days are deleted automatically (0 = keep forever).
    call_log_enabled: bool = True
    call_log_max_rows: int = 100000
    call_log_retention_days: int = 30
    call_log_db_path: str = ".jscoup/call_log.db"

    audit_enabled: bool = True
    auth_realm_id: Optional[str] = None
    credential_epoch: str = "1"
    async_storage: bool = False
    event_queue_size: int = 4096
    sample_rate: float = 1.0
    capture_query_caller: bool = False

    # capture behaviour
    enabled: bool = True
    capture_success: bool = False  # store successful calls too
    capture_slow: bool = True
    slow_request_ms: float = 1_000.0
    slow_query_ms: float = 200.0
    n_plus_one_threshold: int = 8
    capture_4xx: bool = False
    capture_5xx: bool = True
    capture_auth_failures: bool = True  # 401/403 outcomes are always capture-worthy, independent of capture_4xx
    max_breadcrumbs: int = 100
    max_queries: int = 200
    body_preview_chars: int = 4_000
    traceback_limit: int = 40

    # print() interception — off by default; patches sys.stdout for the whole
    # process (see jscoup/printcapture.py).
    capture_print: bool = False
    max_print_chars: int = 4_000

    # Field-level encryption at rest for body/response previews, headers and
    # params — see jscoup/crypto.py. None (default) = plaintext; requires
    # `pip install jscoup[crypto]`.
    encryption_key: Optional[str] = None

    # privacy
    sensitive_keys: List[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_KEYS))
    mask: str = "[redacted]"
    store_raw_token: bool = False
    capture_headers: bool = True

    # identity resolution
    token_sources: List[Any] = field(default_factory=lambda: list(DEFAULT_TOKEN_SOURCES))
    static_tokens: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    decode_jwt: bool = True
    identity_resolver: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None

    # hooks
    before_store: Optional[Callable[[Any], Optional[Any]]] = None
    on_event: Optional[Callable[[Any], None]] = None
    ignored_paths: List[str] = field(default_factory=list)
    ignored_exceptions: List[str] = field(default_factory=list)

    # live simulation
    base_url: Optional[str] = None  # used when the dashboard replays HTTP targets
    dashboard_max_body_bytes: int = 16 * 1024 * 1024
    invoke_max_concurrency: int = 8
    invoke_max_response_bytes: int = 2 * 1024 * 1024
    # Mask sensitive-looking fields (anything named like a token/password/secret) in
    # the response a replay, the Live Tester or a gateway call hands back. Off by
    # default: that response is the API's real answer to an authorised caller, and
    # masking it makes a login route useless. Captured events, call logs and stored
    # previews are always redacted regardless of this setting.
    redact_replay_response: bool = False
    invoke_timeout: float = 30.0
    # A live-invoke call may only replay against `base_url` unless its
    # destination is also listed here; prevents /api/invoke from becoming an
    # open SSRF primitive. Entries are exact prefixes, e.g. "http://127.0.0.1:8000".
    allowed_base_urls: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.dashboard_cookie_secure is None:
            self.dashboard_cookie_secure = self.environment.lower() not in {"local", "development", "dev", "test", "testing"}
        if min(self.dashboard_max_body_bytes, self.invoke_max_response_bytes, self.call_log_max_rows, self.gateway_rate_limit, self.gateway_rate_window, self.invoke_timeout, self.invoke_max_concurrency) <= 0:
            raise ValueError("Security limits must be positive")
        if not 0 <= self.sample_rate <= 1:
            raise ValueError("sample_rate must be between 0 and 1")
        if self.event_queue_size < 1 or self.max_queries < 0:
            raise ValueError("invalid queue or query limit")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JSCoupConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def merged(self, **overrides: Any) -> "JSCoupConfig":
        data = {f: getattr(self, f) for f in self.__dataclass_fields__}  # type: ignore[attr-defined]
        if "environment" in overrides and "dashboard_cookie_secure" not in overrides:
            data["dashboard_cookie_secure"] = None
        data.update({k: v for k, v in overrides.items() if v is not None})
        return JSCoupConfig(**data)
