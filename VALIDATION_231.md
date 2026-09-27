# JSCOUP 1.0.0 validation (run on the 2.3.1rc1 build it was promoted from)

Date: 24 September 2026. Python 3.12.14, Linux. Baseline source: JSCOUP 2.3.0.

## Automated suite

`PYTHONPATH=. python -m pytest -q --tb=short`

Result: **516 passed, 3 skipped, 1 warning in 95.87s (0:01:35)**.

The 30 new security cases cover all-sink privacy, private public-doc examples,
field encryption, SQL quoting, realm separation, credential storage, file modes,
rotation, source quotas, separate-process and simultaneous-process quotas,
background writes, retention, size limits, Origin checks, header-only legacy
secrets, hash work factor, production cookies, cancellation and batching.

Eight inherited tests were adapted to the intended security contract: URL tokens
are rejected; call logs omit bodies; public examples use safe defaults; stored
downstream credentials require encryption. No test was removed to hide a failure.

Three skips: real PostgreSQL URL absent, real MongoDB URL absent, optional
flask_parameter_validation unavailable. One Starlette/httpx deprecation warning.

## Real local application fixtures

`PYTHONPATH=/absolute/path/to/source python validation/security_231/real_projects.py flask all`

`PYTHONPATH=/absolute/path/to/source python validation/security_231/real_projects.py django all`

Both served actual HTTP requests through local WSGI and exercised database
create/read, 404/500 responses, protected dashboard, login, authenticated access,
SQL capture, exceptions and replay. The Django fixture links replay to its event
following the header-casing fix. These are test applications, not customer
production deployments. JSON evidence is included. Sequential 150-read timing
is smoke evidence only and must not be used as a comparative throughput claim.

## Synthetic burst and backpressure

`PYTHONPATH=/absolute/path/to/source python validation/security_231/benchmark.py`

10000 attempted captures, 2.435 producer seconds,
2.472 seconds including drain, 4296 rows saved,
5704 dropped due to queue saturation.
Flush completed: True. Approximately 4108
attempts/second is NOT a lossless storage rate and NOT HTTP throughput.

Batching up to 100 rows per commit reduces transaction overhead; the burst still
exceeded sustainable ingestion with the default queue in this shared environment.
Use explicit sampling, appropriate queue sizing or an external collector. There
is no claim of millions of calls per second.

## Remaining verification gates

Live PostgreSQL/MongoDB CI, full browser flows and exploit testing, Windows ACLs,
cloud and SSH deployments, dependency vulnerability scanning, sustained realistic
load, reverse-proxy limits/TLS and disaster recovery remain unverified here.
The standalone http.server is development-only.

See SECURITY_UPGRADE.md for security scope, breaking changes and migration.
Historical VALIDATION.md and docs/JSCoup-2.3.0-White-Paper.* are baseline records;
they do not certify the updated candidate.
