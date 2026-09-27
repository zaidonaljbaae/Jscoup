> This is the historical build log (2.2.0 to 2.3.x). For 1.0.0, see CHANGELOG.md, SECURITY_UPGRADE.md and VALIDATION_231.md. The text below may describe behavior deliberately changed since.

# JSCOUP 2.3.0

Promoted from the 2.3.0rc1 release candidate after closing two concrete defects and
validating the SQL/Mongo storage backends against real servers instead of only mocks
and fakes (see VALIDATION.md). It preserves the project's original license and
authorship. Read VALIDATION.md before deployment.

## Changes in this build (after the 2.3.0 promotion)

Behaviour changes are listed first because they can affect existing integrations.

| Area | Files | Change |
| --- | --- | --- |
| **Live replay is HTTP only** (behaviour change) | simulator.py, healthcheck.py, dashboard/api.py, core.py | JSCoup is middleware and no longer runs Python functions itself. `Simulator.invoke`/`ainvoke` refuse any target that is not an HTTP API; the in-process service code path was removed. The Check APIs sweep skips such targets, and the dashboard, gateway and published-docs target lists contain HTTP APIs only. Watched functions and Lambda handlers are still recorded (calls, errors, SQL). `JSCoup.simulate_lambda` remains as a helper the developer calls directly. |
| **Global docs page and OpenAPI export removed** (behaviour change) | openapi.py (deleted), config.py, dashboard/api.py, static/index.html, `__init__.py` | Removed `GET /gw/docs`, `GET /gw/docs-data`, the `docs_enabled` and `docs_allowed_ips` options, `build_openapi_spec`, `JSCoup.openapi_spec`, `GET /api/openapi.json` and the "Export OpenAPI" button. Published doc groups and the Postman export are unchanged and remain the way to publish documentation. |
| Flask parameter detection | registry.py | Routes now report the parameters they read: `flask_parameter_validation` declarations (`Query`, `Json`, `Form`, `Route`, `File`), with required/optional, defaults and limits, and direct use of `request.args`, `request.get_json()`, `request.form` and `request.files`. Body parameters attach only to methods that carry a body; `Form` parameters are sent urlencoded by the replay. |
| Authentication detection | registry.py | A route is marked as needing a token when a decorator on its original function looks like an auth guard (`authorize.in_group`, `login_required`, `jwt_required`, `permission_required`, `token_required` and similar; CSRF decorators excluded), including through wrappers that do not set `__wrapped__`. |
| Source file per API | registry.py, static/index.html | Each target records the file its function is defined in; the Live Tester groups APIs by it. Wrappers defined in another file of the same app are not mistaken for the API's file. |
| Ordering and layout | static/index.html, static/docs.html | APIs are listed POST, GET, PUT, PATCH, DELETE. The Live Tester list is wider and taller. On the public docs page each parameter is one row (name, in, type, description, value), Parameters come before Expected responses, and the empty "Response" heading no longer shows before a call. |
| Example values | examples.py | String and UUID ids get a UUID-shaped example, integer ids a number, a boolean named like an id stays boolean; a validator's date pattern yields a valid date. |
| Failure hints | static/index.html | The Live Tester explains a 401/403 (a token is needed) and an HTML or plain-text 5xx (the server failed before its own JSON error handling ran). |
| Packaging | pyproject.toml | The `flask` extra now includes `blinker>=1.6`, which `install_flask` needs on Flask 2.2. |
| Docstrings | core.py | `JSCoup.invoke`/`ainvoke` describe HTTP-only replay. |

Tests: 489 collected, 486 passing, 3 skipped for optional packages that are not installed.

**Known open items.** A security review of this build (see the white paper in `docs/`, Section 6.4) recorded twelve findings, S-1 to S-12, none yet addressed in code. The four most significant: the admin login lockout is keyed by user name alone, so a stranger can lock the administrator out (S-1); login timing reveals whether a user name exists (S-2); the dashboard sends no HTTP security headers (S-3); and the SQLite state files are created with default permissions while the gateway file holds downstream tokens in plaintext (S-4).

## Changes since 2.3.0rc1

| Area | Files | Change |
| --- | --- | --- |
| Storage boot race | storage/sql.py | `SqlStorage.__init__` used `metadata.create_all(engine, checkfirst=True)` and, for a schema, `CREATE SCHEMA IF NOT EXISTS` — both check-then-create, not atomic. Several processes constructing `SqlStorage` against the same brand-new database at once (e.g. gunicorn/uvicorn workers forked without `--preload`, each importing the app independently) could each pass the existence check before the winner's `CREATE TABLE`/`CREATE SCHEMA` committed, so the loser raised a duplicate-object error from the database itself (`psycopg2.errors.UniqueViolation` on Postgres) and crashed. Reproduced against a real Postgres server with 8 concurrent processes (7/8 failed); fixed by catching the error and verifying the tables/schema now exist — created by whichever process won — before deciding whether to re-raise. Regression coverage: `tests/test_sql_storage.py`'s threaded and `real_server`-marked tests, plus a standalone multi-*process* reproduction at `tests/tools/concurrent_boot.py` (wired into CI). |
| Mongo summary scalability | storage/mongo.py | `MongoStorage.summary()` loaded every matching document into application memory and counted totals/breakdowns in Python — doesn't scale past a small collection, and was flagged as a known gap in 2.3.0rc1's VALIDATION.md. Replaced with a single server-side `$facet` aggregation pipeline computing totals, distinct-count facets (issues/actors) and every breakdown inside MongoDB itself; only the small, pre-aggregated result crosses the wire now. Distinct-value matching against `actor.subject`/`fingerprint` uses an explicit `{"$type": "string"}` match rather than `{"$ne": None}`, because `$ne: None` was found to diverge between mongomock and a real MongoDB server on documents where the field is entirely absent (verified directly against both — see the `real_server`-marked test in `tests/test_mongo_storage.py`, which runs against a genuine MongoDB in CI, not the mock). |
| CI | .github/workflows/ci.yml (new) | No CI matrix existed before this release. Added: a Python 3.9–3.12 matrix running the full suite against real Postgres and MongoDB service containers (not only SQLite/mongomock), plus a dedicated job reproducing the multi-worker boot race against a real Postgres on every push. |

## Prior changes (2.2.0 → 2.3.0rc1)

| Area | Files | Change |
| --- | --- | --- |
| Privacy | sanitizer.py, redaction.py, dbwatch.py, core.py | Per-instance final sanitization, including after before_store hooks; remove SQL bind values and quoted literals; sanitize previews, URLs and custom secret keys. |
| Session isolation | dashboard/sessions.py, dashboard/api.py, core.py, gateway.py | Realm-bound dashboard sessions; credential changes invalidate sessions; indexed SHA-256 lookup for high-entropy random session tokens. Passwords retain password hashing. |
| Background delivery | publisher.py, core.py, config.py | Optional bounded queue, overflow counters, flush/close, storage-failure counters and explicit sampling. |
| Capture correctness | context.py, models.py, core.py | Query totals survive trace truncation; retain the latest failed query; asynchronous Azure capture waits for completion; context cleanup on cancellation. |
| Frameworks and replay | integrations/django.py, registry.py, simulator.py | Instrument Django connections in the request thread; typed and nested route names; exact placeholder substitution; remove synchronous event polling from async replay. |
| Dashboard | dashboard/api.py, integrations mounts | Validate windows, enforce feature flags, rate-limit gateway logs, route additional gateway HTTP verbs. |
| Configuration | projectconfig.py, storage/connections.py | Fail closed for missing secret environment variables; preserve environment references on save; fail on startup lock timeout; literal percent signs in INI files. |
| SSH | storage/ssh.py, storage/connections.py | Paramiko-based loopback forwarding; reject unknown host keys; bounded forwarding handlers; cleanup on failure. |
| Storage | storage/sql.py, storage/mongo.py | SQL initialization fails explicitly and cleans resources; default database ports; reduce representative-event queries; escape Mongo search input; correct zero limits. |
| Diagnostics | diagnostics.py | At most eight concurrent DNS workers, including timed-out unresolved workers. |

## Migration and operational rules

- Install from this directory with `python -m pip install .` or select extras,
  for example `python -m pip install '.[flask]'` / `'.[django]'`.
- Runtime version is `2.3.0rc1`. Old README examples describe the inherited API;
  this release note takes precedence for changed behavior.
- Existing dashboard and gateway session tokens must log in again after upgrade.
  Dashboard sessions use a new v2 table. Old session tables are not destructively removed.
- Give separate applications distinct `service_name` / `auth_realm_id` values.
  Workers serving the same app must share a session database, configured credentials
  and credential epoch. Auto-generated credentials are process-specific.
- SQL parameters are always omitted. SQL caller stack collection now defaults to
  off; set `capture_query_caller=True` if needed. SQL redaction is heuristic,
  not a complete parser or a guarantee against arbitrary secrets in free text.
- Configure SSH host keys through OpenSSH known_hosts or `known_hosts=...`.
  Unknown hosts are rejected. Mongo URI plus SSH is explicitly unsupported;
  use discrete connection fields. No real SSH server was available for end-to-end validation.
- Abandoned configuration lock files require operator investigation/removal;
  lock age alone no longer authorizes stealing an active writer's lock.
- `sample_rate` is head sampling: unsampled calls, including their errors, are
  not recorded. Use 1.0 when error completeness is required. Explicit exception
  recording is not a promise of whole-application sampling consistency.
- Background mode is best effort, not durable messaging. The queue drops new
  events when full. Monitor `metrics()`. `flush()` confirms completion, not
  success; inspect failed/dropped counters. Call `close(timeout=...)` during
  application shutdown and check its Boolean result. Crashes can lose queued events.
- Construct instances after worker fork. The queue is bounded by item count,
  not a strict byte budget. on_event runs on the delivery thread in background mode;
  callbacks should be fast and must not wait for their own delivery queue.

## High-volume starting point

```python
from jscoup import JSCoup

monitor = JSCoup.high_volume(
    service_name="orders",
    dashboard_username="admin",
    dashboard_password="replace-with-a-secret-from-your-environment",
    event_queue_size=4096,
    sample_rate=1.0,
)

@monitor.watch()
def process_order(order_id):
    return {"order_id": order_id}

# At controlled worker shutdown, after accepting no more requests:
if not monitor.close(timeout=10):
    print("JSCOUP did not finish delivery before shutdown")
```

The preset does not store successful fast calls by default. It still performs
capture work to detect failures/slow operations. Background delivery reduces
storage blocking; it does not make Python instrumentation free.

## Remaining release gates and recommended architecture

Closed in 2.3.0: Mongo summary's in-memory aggregation (gate 2 below, now
server-side); real Postgres and real MongoDB validation, including a genuine
multi-process boot-race reproduction (part of gate 3, now in CI); a CI matrix
across Python 3.9–3.12 (gate 7). Still open, honestly:

1. Run sustained, representative load tests on target hardware. Define requests/sec,
   event bytes, retained fraction, persistence latency, acceptable drop rate and p99
   application overhead. Millions of calls/sec is not an established capability.
2. ~~Mongo summary still reads matching documents into application memory.~~ Fixed
   in 2.3.0 — see RELEASE_NOTES.md's "Changes since 2.3.0rc1". SQL representative
   selection still uses window functions tested only against SQLite/Postgres/MongoDB
   in CI, not MySQL/Oracle/SQL Server — test those specifically before relying on them.
3. Postgres and MongoDB are now tested against real servers in CI (including the
   boot-race fix, reproduced and confirmed fixed against a real Postgres). Still
   untested: real MySQL/Oracle/SQL Server servers, pinned SSH host-key success and
   rejection against a real SSH server, deployed Azure/OCI Functions, and multi-process
   ASGI (Uvicorn with multiple worker processes, as opposed to the multi-*worker*
   gunicorn boot race, which is now covered).
4. Validate UI behavior manually, nested/regex routes and custom converters in your app.
   Regex-based Django replay is not comprehensively supported. Django replay may return
   event_id=null even with a successful response; correlation needs further work.
5. Async replay no longer polls storage synchronously, but invoking a synchronous
   user function from the async API can still block its event loop. Use a worker
   executor or async function for expensive targets.
6. For multi-worker high-volume production: use per-worker bounded collectors feeding
   a durable broker, partitioned consumers doing batch writes, and separate query/read
   services. The local queue/SQLite design is not that distributed system.
7. ~~Add CI across Python versions~~ Done in 2.3.0 (`.github/workflows/ci.yml`,
   Python 3.9–3.12 against real Postgres/MongoDB). Dependency/security scanning and a
   staged canary rollout process for new transport/concurrency behavior are still open.

## Primary design references

- Python bounded queues: https://docs.python.org/3/library/queue.html
- Python thread lifecycle: https://docs.python.org/3/library/threading.html
- Paramiko host key policy: https://docs.paramiko.org/en/stable/api/client.html
- Django database connections: https://docs.djangoproject.com/en/stable/ref/databases/
- Python package version identifiers: https://packaging.python.org/en/latest/specifications/version-specifiers/

These links are design references. The accompanying executable tests and recorded
results are the evidence for this particular implementation.
