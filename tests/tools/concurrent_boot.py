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

When a worker does not report back the tool says *where it stopped*: every
worker announces each stage it reaches (imported, barrier, constructed, used),
and a worker still running after ``HANG_DUMP_SECONDS`` prints the stack of
every thread to stderr, so a hang is diagnosable from the CI log alone.
"""

from __future__ import annotations

import faulthandler
import multiprocessing
import os
import queue
import sys
import time
import uuid

HANG_DUMP_SECONDS = 75
BARRIER_TIMEOUT = 90
OVERALL_TIMEOUT = 120


def _worker(index: int, url: str, schema: str, barrier: "multiprocessing.Barrier", out_queue: "multiprocessing.Queue") -> None:
    faulthandler.dump_traceback_later(HANG_DUMP_SECONDS, file=sys.stderr)

    def stage(name: str) -> None:
        out_queue.put(("stage", index, name))

    try:
        from jscoup import JSCoup
        from jscoup.storage.sql import SqlStorage

        stage("imported")
        barrier.wait(timeout=BARRIER_TIMEOUT)
        stage("barrier passed")
        bl = JSCoup(
            service_name="concurrent-boot-test",
            storage=SqlStorage(url, schema=schema),
            dashboard_local_dev=True,
        )
        stage("constructed")
        bl.watch()(lambda: 1)()  # exercise the storage path, not just construction
        stage("used")
        out_queue.put(("ok", index, os.getpid()))
    except BaseException as exc:  # pragma: no cover - failure path under test
        out_queue.put(("error", index, f"pid={os.getpid()}: {exc!r}"))
    finally:
        faulthandler.cancel_dump_traceback_later()


def main(workers: int = 8) -> int:
    url = os.environ.get("JSCOUP_TEST_PG_URL")
    if not url:
        print("JSCOUP_TEST_PG_URL is not set — nothing to test against, skipping.")
        return 0

    schema = f"jscoup_concurrent_boot_{uuid.uuid4().hex[:8]}"
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(workers)
    out_queue = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(i, url, schema, barrier, out_queue)) for i in range(workers)]

    for p in procs:
        p.start()

    # Wait for every worker's final message with get(timeout=...); Queue.empty() is documented as
    # unreliable, so it is never used to decide that everything has arrived.
    final: dict[int, tuple] = {}
    last_stage: dict[int, str] = {}
    deadline = time.monotonic() + OVERALL_TIMEOUT
    while len(final) < workers and time.monotonic() < deadline:
        try:
            message = out_queue.get(timeout=1.0)
        except queue.Empty:
            if not any(p.is_alive() for p in procs):
                # every process has exited: drain what is left, once, then stop waiting
                try:
                    while True:
                        message = out_queue.get(timeout=2.0)
                        if message[0] == "stage":
                            last_stage[message[1]] = message[2]
                        else:
                            final[message[1]] = message
                except queue.Empty:
                    break
            continue
        if message[0] == "stage":
            last_stage[message[1]] = message[2]
        else:
            final[message[1]] = message

    missing = [i for i in range(workers) if i not in final]
    for i in missing:
        procs[i].join(timeout=1)
    errors = [m for m in final.values() if m[0] == "error"]

    for p in procs:
        if p.is_alive():
            p.terminate()
        p.join(timeout=10)

    import sqlalchemy as sa

    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    engine.dispose()

    print(f"{len(final)}/{workers} workers reported back, {len(errors)} failed")
    for m in errors:
        print(f" - worker {m[1]}: {m[2]}")
    for i in missing:
        print(f" - worker {i} never reported: last stage = {last_stage.get(i, 'none (never started)')}, exit code = {procs[i].exitcode}")
    return 1 if (errors or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
