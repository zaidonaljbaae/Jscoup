# Changelog

All notable changes to this project are documented here, in the style of [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project follows [Semantic Versioning](https://semver.org/).

For full per-file, per-defect detail (including internal build history: 2.2.0 → 2.3.0rc1 → 2.3.0 → 2.3.1rc1), see [RELEASE_NOTES.md](RELEASE_NOTES.md) and [SECURITY_UPGRADE.md](SECURITY_UPGRADE.md).

## [Unreleased]

### Changed
- `tests/tools/concurrent_boot.py` (the multi-worker boot-race check) now reports every worker's stage (imported, barrier passed, constructed, used), reads results with a timeout instead of the unreliable `Queue.empty()`, prints a full traceback for a worker that raises, dumps every thread's stack for a worker still running after 75 s, and names a missing worker with its last stage and exit code instead of only a bare `N/8 workers reported back` count. The CI job now has a 10-minute limit. Test-tooling only; no change to the published package.

## [1.0.0] — 2026-09-26

First stable, public release. Built directly on the 2.3.1rc1 security/architecture candidate, promoted to final after a full pass of its own test suite (549 passed, 5 skipped, 0 failed) and real-world integration against two independent applications.

### Added
- Public documentation set: [Integration Guide](docs/INTEGRATION_GUIDE.md), [API Reference](docs/API_REFERENCE.md), [User Manual](docs/JSCOUP_Manual.pdf), [Technical White Paper](docs/JSCOUP_Whitepaper.pdf), architecture flowchart, [llms.txt](llms.txt) for AI-tool discoverability.
- Work paper website with eight diagrams (`docs/index.html`, published with GitHub Pages) and an animated walkthrough (`docs/assets/how-it-works.gif`); the PDF work paper is generated from the same page.
- Ownership protection: copyright + SPDX header on every source file, `__author__` / `__copyright__` / `__license__` in the package, expanded `NOTICE`, `TRADEMARK.md`, contributor licensing terms (DCO sign-off) in `CONTRIBUTING.md`.
- Release automation: `publish.yml` (PyPI trusted publishing with signed build provenance), `pages.yml`, `CODEOWNERS`; PEP 561 `py.typed`; runnable `examples/` for Flask, FastAPI and plain functions.
- `project.urls` metadata, community files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue/PR templates).
- `gateway_open_tokenless_apis` (default `False`): treats every API that needs no token of its own as open through the gateway — callable with no gateway token, as if an admin had marked it public. An API that *does* need a token is never opened by it. Docs data reports the effective state as `public`. Regression tests: `tests/test_gateway_open_apis.py`.
- `gateway_forward_own_tokens` (default `False`): a caller can reach an API that *needs* a token by presenting that API's own token (for example the one its login route issued) as the Bearer token. The gateway forwards it and the API itself accepts or rejects it, exactly as for a direct call, so a wrong or expired token gets the API's own 401. A bearer that is a valid gateway login token is still treated as one (permissions, IP list, configured downstream token, never forwarded). Limited per credential by the gateway rate limit. Docs data reports it as `accepts_own_token`.

### Changed
- Version scheme reset to a clean public `1.0.0` (previously tracked internally as `2.3.1rc1`) — the same code base, plus version metadata, packaging polish and the fixes listed under "Fixed" below.
- `pyproject.toml` classifiers extended (Python 3.9-3.12, Flask/FastAPI/Django frameworks, project URLs); development status `3 - Alpha` for the first public release.

### Removed
- The Arabic README (`README.ar.md`) and its link.

### Fixed
- **FastAPI parameter detection now reads FastAPI's own resolved dependency tree** (`route.dependant`) instead of guessing from the function signature. A route such as `login(form: OAuth2PasswordRequestForm = Depends())` used to be documented as "takes no parameters"; it now lists `username` / `password` (required) and `grant_type`, `scope`, `client_id`, `client_secret` (optional), each with its real location (`form` / `query` / `path` / `body`), required-or-optional, default, description, allowed values (`Literal` / `Enum`) and rules (`pattern`, `ge`, `le`, `min_length`...). Query parameters declared by `Depends(...)` helpers are found too, and `x: str = Form()` is no longer mistaken for a query parameter.
- **Token detection for FastAPI is exact.** A security scheme (`OAuth2PasswordBearer`, `HTTPBearer`, `HTTPBasic`, `APIKeyHeader`...) anywhere in the dependency chain — including behind `get_current_user` — marks the API as needing a token; `auto_error=False` schemes are reported as *token optional*; an API with no scheme needs none. Targets now carry `auth_scheme` and `auth_optional`. A dependency *class* (e.g. `OAuth2PasswordRequestForm`) is never treated as an auth guard.
- **Examples respect the field's rules and leave optional inputs empty.** `grant_type` (pattern `^password$`) is pre-filled with `password` instead of a made-up value the API rejects; optional inputs with no default are no longer pre-filled with fake values.
- **Docs page: the gateway 401 is explained.** Published-docs "Run" goes through the gateway, which requires a gateway token unless an admin marked the API public — even when the API needs no token of its own. Docs data now carries `public`, the page says "Gateway token required" up front instead of showing a bare 401, and marks token-optional and public APIs. The admin Live Tester shows "Token optional".
- **Overview summary failed on PostgreSQL** (`GroupingError: column "actor_label" must appear in the GROUP BY clause`): `SqlStorage.summary()` grouped by a differently-parameterised `coalesce(...)` than it selected. SQLite tolerated it, Postgres with psycopg v3 did not. Regression test added (`real_server`), and CI now installs psycopg v3.
- `python-multipart` added to the `dev` extra (needed by the FastAPI form tests).
- **Parameters carry a real description.** FastAPI's own field documentation (`Doc(...)`) is used when no `description=` is set, so `OAuth2PasswordRequestForm`'s `grant_type`, `scope`, `client_id` and `client_secret` explain themselves instead of showing "—". A developer's own description is never shortened.
- **Docs page:** required parameters are listed first and optional ones sit behind a "N optional parameters — not needed, leave empty" toggle.
- **Replay / gateway / Live Tester return the API's real response.** They used to mask any field whose name contains "token", "password" or similar, so a login route came back as `{"access_token": "[redacted]", "token_type": "[redacted]"}` and the caller could never obtain their token. The response is now passed through unchanged; set `redact_replay_response=True` to bring the masking back. Captured events, call logs and stored previews are still always redacted.
- **Public APIs with their own token.** On an API that is open through the gateway, a bearer token on the call is now forwarded to the API as its own token (on a gated API the bearer is the gateway token and is never forwarded). Previously it was silently dropped, so a public API that needed a token could not be called from the docs page.

### Behaviour notes
- `ParamSpec` gained `choices` and `constraints`; `Target` gained `auth_scheme` and `auth_optional`. All are additive.
- By default an API that needs no token of its own is still not reachable through the gateway without a gateway token until an admin marks it public (Access tab → Public); detection never opens an API to the gateway unless `gateway_open_tokenless_apis` is turned on.

### Security
Everything from the 2.3.1rc1 security/architecture revision ships in this release — see [SECURITY_UPGRADE.md](SECURITY_UPGRADE.md) for full detail:
- Realm-isolated gateway state (separate local SQLite file per application realm).
- Downstream gateway credentials require an explicit encryption key; fail closed with no plaintext fallback.
- PBKDF2-HMAC-SHA256 password hashing raised to 600,000 iterations.
- Login lockout keyed by source address *and* account (previously account alone, allowing a stranger to lock out a known admin username).
- HTTP hardening: bounded request/response sizes, security response headers (CSP, anti-sniff, frame denial), rejection of cross-site mutating requests.
- Local SQLite state files created at restrictive permissions (0600/0700 on POSIX).

## [2.3.0] — earlier internal build

Promoted from 2.3.0rc1 after closing two concrete defects and validating SQL/Mongo storage against real servers. See [RELEASE_NOTES.md](RELEASE_NOTES.md) for the full table of changes (HTTP-only replay, Flask parameter detection, auth-decorator detection, per-file API grouping, and more).

## [2.2.0] and earlier

Foundational capture/diagnosis engine, dashboard, Live Tester, API Gateway, OpenAPI export (later removed in 2.3.0 in favor of the published-docs/Postman flow), and the original storage backends. See [RELEASE_NOTES.md](RELEASE_NOTES.md) for details.

[1.0.0]: https://github.com/zaidonaljbaae/JSCOUP/releases/tag/v1.0.0
