# JSCOUP 1.0.0 architecture and security update

> Written and validated as the 2.3.1rc1 candidate; 1.0.0 is that build promoted to the first public release.

This release preserves the dashboard layout, gateway, API discovery, live tester, and Flask, FastAPI and Django adapters. It changes the trust boundaries underneath them. It has had no independent third-party security audit and is not a production security certification or a claim of millions of calls per second.

## Data flow and privacy

`capture -> event construction -> sanitizer -> before_store -> sanitizer -> metadata call log and optional full-event storage`

`before_store` now runs for successful captured calls even when `capture_success=False`. Returning `None`, raising an exception, or excluding a route suppresses both persistence paths. Sampling and `enabled=False` also apply to both paths. Hooks must be fast and safe to call concurrently. They still run on the application thread. `on_event` continues to refer to full stored events.

Call logs no longer store response bodies or actor labels. Core-generated rows also omit concrete paths; names and counts remain available to the existing dashboard. The low-level call-log method retains its signature for compatibility but discards `response_preview` and `actor`. The active call-log database has legacy bodies and actor labels cleared on opening. This is not forensic secure erasure: handle free pages, WAL files, backups, snapshots, and replicas under your retention policy. Encryption of full events is still field-level, not whole-database encryption. Event names and other metadata can contain personal data if the application puts it there; the application must apply its privacy policy through `before_store`.

Documentation, gateway target catalogues and Postman exports now use explicitly authored `response_examples` and synthetic defaults. They never consume the call log, including old rows. Do not put real customer records in an explicit example. Public doc groups remain public according to their own configured IP policy; they do not inherit the admin network gate.

## Authentication and local state

Gateway state is separated into deterministic realm-specific SQLite files. With `gateway_db_path='.jscoup/gateway.db'`, the effective filename is `gateway.<realm hash>.db`. All gateway tables, including users, sessions, public flags, docs, descriptions and quotas, live in that file. The realm is `auth_realm_id`, or the service name and environment when no explicit realm is set. Workers for the same application must use the same realm and same local volume. Applications that must be isolated must use different realms. The low-level `GatewayStore` accepts an optional `realm`; callers using it directly must supply that realm or use separate files themselves.

Existing unscoped gateway users and sessions are deliberately not imported. Back up the old file with restricted permissions, create the intended users and groups in the new realm, and have users log in again. Do not rename an old gateway file to the new name: it can contain unencrypted downstream credentials and permissions from other applications. This release does not silently make an ownership decision about legacy gateway records.

Stored downstream credentials now require `encryption_key` and the `crypto` extra. Their database column contains authenticated Fernet ciphertext. Missing keys and legacy plaintext credentials fail closed. Caller-supplied transient bearer tokens still work without storing them. Keep the key in your deployment secret manager, separate from the database and its backups. Key rotation requires securely recreating or re-encrypting stored credentials; changing the key alone will make them unreadable.

Local SQLite files are created with mode 0600 on POSIX, new state directories with 0700. Existing file modes and SQLite WAL/SHM companions are tightened; existing parent-directory permissions are not silently changed. Use a dedicated private parent directory and an OS identity dedicated to the app. Windows ACLs must be configured by the operator; this implementation does not enforce Windows ACLs. Event, call-log, session and gateway SQLite files are covered. Remote database permissions remain deployment responsibilities.

New password hashes use PBKDF2-HMAC-SHA256 with 600000 iterations. Existing hashes remain readable. Reset older gateway passwords and regenerate configured dashboard password hashes to adopt the higher work factor; there is no automatic rehash migration. Unknown usernames still incur password-verification work. Admin and gateway login admission uses shared source and source-plus-account quotas, checked before expensive hashing. Counters expire and their table has a hard capacity of 10000 entries; a full table rejects new keys until entries expire. The policy counts successful attempts as well as failures. Shared-NAT users may need an appropriate upstream policy. Multi-source credential stuffing still needs edge controls or centralized authentication/MFA.

Runtime changes to the dashboard password hash or `credential_epoch` invalidate cached local session bindings and revoke the previous realm's sessions. Prefer `bl.rotate_dashboard_credentials(new_password, credential_epoch='2026-09-22-1')`, then deploy the same password and epoch to every worker. All workers must receive the new configuration; a worker retaining old credentials must not remain active and issuing sessions. Never put the new password in source control.

Legacy dashboard secrets are accepted only in `X-JSCoup-Token`, using a constant-time comparison. Query-string tokens no longer authorize access. For an interactive browser, use the existing username/password login. Browser gateway and downstream tokens are retained only in sessionStorage; old localStorage copies are deleted, so users log in or paste transient tokens again. sessionStorage is still accessible to same-origin JavaScript and is not an XSS defense.

## HTTP boundaries and browser protections

Dashboard request bodies are capped at 16 MiB by default through `dashboard_max_body_bytes`. Flask, Django and FastAPI adapters use bounded reads. ASGI observation copies only bounded slices of incoming chunks and never alters the body delivered to the host application. The standalone server rejects unsupported transfer encoding, invalid/oversized Content-Length, and applies a socket timeout. It remains a development-only server.

Replay responses are capped at 2 MiB with `invoke_max_response_bytes`; exceeding the cap returns an error rather than a misleading truncated successful JSON result. The response loop also checks elapsed time. Network timeout is still not a complete wall-clock budget covering every DNS, TLS and slow-header scenario. Enforce a hard request deadline at the production reverse proxy/server. Replay concurrency is capped at eight per instance with `invoke_max_concurrency`. Async cancellation does not release an occupied slot while its network thread is still active.

Multipart uploads check encoded size before decoding and enforce a 10 MiB aggregate construction limit. Framework or reverse-proxy request-body limits should be configured as well, including before Django's ASGI body buffering. These library limits do not bound arbitrary application request handling or a malicious object's Python serialization methods.

Mutating requests reject foreign Origin and cross-site Fetch Metadata. Same-origin clients continue using the existing UI. Reverse proxies must preserve a correct external scheme/host and strip client-supplied forwarding headers before any trusted-proxy configuration is enabled. Cookie Secure defaults to true outside local/dev/test environments and remains explicitly configurable. Set HTTPS, trusted host validation, HSTS and TLS at the edge.

Responses add nosniff, DENY framing, no-referrer, and a CSP blocking foreign resources, frames, objects and base URL changes. The existing dashboard uses inline scripts, handlers and styles, so this candidate retains `unsafe-inline` to preserve its interface. A nonce/hash-based CSP needs a subsequent frontend code refactor and browser validation; this candidate does not claim full XSS prevention.

The dashboard's configured outbound destination policy remains in force and redirects remain disabled. Direct Python `invoke`/`ainvoke` is a trusted developer API and can still receive a caller-specified destination. Do not expose that argument to untrusted users outside the dashboard's validated route. A future centralized transport policy can unify both entry points if the application needs that guarantee.

## Delivery and capacity

In `async_storage=True` or `JSCoup.high_volume`, call-log and full-event writes use separate bounded background publishers. Call-log state initializes at application startup. Each publisher allows 4096 queued items by default and limits accounted Python object size to 16 MiB. The byte accounting is an estimate, not a guarantee about total process RSS. Accepted work is best-effort, not crash-durable. Saturation drops telemetry and increments counters; it never blocks a request waiting for storage capacity.

`bl.metrics()` exposes each writer's accepted/saved/dropped/failed/pending counts and accounted bytes. `bl.flush(timeout)` and `bl.close(timeout)` cover both writers. Initialize JSCoup after worker fork, stop request admission before shutdown, check the return value of close, and allow a sufficient drain period. Keep privacy hooks inexpensive and use explicit sampling for high traffic.

Call logs have `call_log_max_rows=100000` in addition to time retention. Metadata lengths are bounded. Row limits do not impose a hard disk-space quota or shrink previously allocated SQLite files. Background call-log writes batch up to 100 records per transaction. This reduces commit overhead but does not guarantee lossless delivery when producers outrun the writer. A 10000-call burst in this environment still dropped 5704 records with the default 4096-item queue; see the validation evidence. Gateway quotas use atomic SQLite transactions shared by local workers. They are fixed-window quotas, so boundary bursts remain possible. This is not cross-host distributed coordination. For a cluster, use an edge/API-gateway quota service and a suitable shared telemetry backend rather than placing SQLite on a network filesystem.

## CI and verification

The supplied CI now explicitly installs psycopg2-binary for PostgreSQL tests. Its real-backend job sets `JSCOUP_REQUIRE_REAL_SERVERS=1`, which makes skipped tests fail that job. Run the real PostgreSQL and MongoDB jobs in your infrastructure before approval. This candidate was not tested against those live servers here.

The full verification results, commands, limitations and architecture mapping are in the accompanying Word report and `VALIDATION_231.md`. Updated historical tests are named and explained there. Use the included security regression suite for future changes. The original frontend markup and styling are preserved; changes within it concern credential storage only.

## References

- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Python http.server documentation: https://docs.python.org/3/library/http.server.html

Consulted 22 September 2026. These references inform design choices; they are not third-party certification of JSCOUP.
