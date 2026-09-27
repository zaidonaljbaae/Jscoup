# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Standalone reproduction of the multi-worker boot race found while
embedding this library in three real docker-composed demo services
(Flask + gunicorn -w 2, Django + gunicorn -w 2 — both crash-looped on
first boot before the storage/sql.py fix below).

Spawns N *separate OS processes* (not threads — this is what gunicorn/
uvicorn actually fork, and multiprocessing exercises a fresh Python/driver
state in each one the way threading.Thread never does) that each construct
``JSCoup(storage=SqlStorage(url, schema=...))`` against the same brand-new
Postgres schema at the same instant. Before the fix in
``jscoup/storage/sql.py`` (catch the checkfirst-then-create race and verify
the desired end state instead of always re-raising), this reliably
reproduced::

    psycopg2.errors.UniqueViolation: duplicate key value violates unique
    constraint "pg_class_relname_nsp_index"

Usage: ``JSCOUP_TEST_PG_URL=postgresql+psycopg2://... python
tests/tools/concurrent_boot.py`` — exits non-zero (and prints every worker's
exception) if any of the N processes failed to construct.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import uuid


def _worker(url: str, schema: str, barrier: "multiprocessing.Barrier", out_queue: "multiprocessing.Queue") -> None:
    try:
        from jscoup import JSCoup
        from jscoup.storage.sql import SqlStorage

        barrier.wait()
        bl = JSCoup(
            service_name="concurrent-boot-test",
            storage=SqlStorage(url, schema=schema),
            dashboard_local_dev=True,
        )
        bl.watch()(lambda: 1)()  # exercise the storage path, not just construction
        out_queue.put(("ok", os.getpid()))
    except Exception as exc:  # pragma: no cover - failure path under test
        out_queue.put(("error", f"pid={os.getpid()}: {exc!r}"))


def main(workers: int = 8) -> int:
    url = os.environ.get("JSCOUP_TEST_PG_URL")
    if not url:
        print("JSCOUP_TEST_PG_URL is not set — nothing to test against, skipping.")
        return 0

    schema = f"jscoup_concurrent_boot_{uuid.uuid4().hex[:8]}"
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(workers)
    out_queue = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(url, schema, barrier, out_queue)) for _ in range(workers)]

    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    results = []
    while not out_queue.empty():
        results.append(out_queue.get())
    errors = [r for r in results if r[0] == "error"]

    import sqlalchemy as sa

    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    engine.dispose()

    print(f"{len(results)}/{workers} workers reported back, {len(errors)} failed")
    for _, message in errors:
        print(" -", message)
    return 1 if (errors or len(results) != workers) else 0


if __name__ == "__main__":
    sys.exit(main())
