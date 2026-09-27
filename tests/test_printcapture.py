# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.printcapture — print() output bound to the right request.

Most of these exercise the mechanism directly (``record_stdout`` /
``_TeeStdout.write``) rather than the real global ``sys.stdout`` through an
actual ``print()`` call: pytest manages ``sys.stdout`` itself per test, which
fights with any fixture-level monkeypatch of the same object. One true
end-to-end test at the bottom uses ``capsys.disabled()`` specifically to step
outside pytest's own capture for that one assertion.
"""

from __future__ import annotations

import concurrent.futures
import contextvars

import pytest

from jscoup import JSCoup, MemoryStorage
from jscoup.context import record_stdout
from jscoup.printcapture import _TeeStdout, install_print_capture, uninstall_print_capture


@pytest.fixture
def bl():
    return JSCoup("print-test", storage=MemoryStorage(), capture_success=True)


def test_record_stdout_attaches_to_the_active_context(bl):
    with bl.capture(kind="service", name="job") as ctx:
        record_stdout("hello from inside\n")
    assert ctx.stdout_text == "hello from inside\n"
    event = bl.storage.list()[0]
    assert event.stdout_capture == "hello from inside\n"


def test_record_stdout_does_nothing_outside_any_capture():
    record_stdout("nobody is listening")  # must not raise


def test_record_stdout_attaches_to_every_nested_context(bl):
    with bl.capture(kind="http", name="outer") as outer:
        with bl.capture(kind="service", name="inner") as inner:
            record_stdout("from the inner call\n")
    assert "from the inner call" in inner.stdout_text
    assert "from the inner call" in outer.stdout_text  # parent sees it too, like SQL queries do


def test_stdout_is_capped_at_max_print_chars():
    bl = JSCoup("cap-test", storage=MemoryStorage(), capture_success=True, max_print_chars=10)
    with bl.capture(kind="service", name="job") as ctx:
        record_stdout("0123456789ABCDEF")
    assert len(ctx.stdout_text) <= 11  # cap + the truncation marker
    assert ctx.stdout_text.endswith("…")


def test_tee_stdout_forwards_to_the_real_stream_and_the_active_context(bl):
    class _Fake:
        def __init__(self):
            self.written = ""

        def write(self, s):
            self.written += s
            return len(s)

        def flush(self):
            pass

    fake = _Fake()
    tee = _TeeStdout(fake)
    with bl.capture(kind="service", name="job") as ctx:
        tee.write("hello\n")
    assert fake.written == "hello\n"
    assert ctx.stdout_text == "hello\n"


def test_concurrent_contexts_do_not_cross_contaminate(bl):
    """The whole point of reusing the contextvar-stack mechanism: two
    concurrent calls on different threads must each only see their own
    recorded output, exactly like they already don't leak SQL queries into
    each other."""

    def make_call(label):
        with bl.capture(kind="service", name=f"job-{label}"):
            record_stdout(f"output for {label}\n")

    contexts = [contextvars.copy_context() for _ in range(2)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(contexts[0].run, make_call, "a"),
            pool.submit(contexts[1].run, make_call, "b"),
        ]
        for f in futures:
            f.result()

    events = {e.name: e.stdout_capture for e in bl.storage.list(kind="service", limit=10)}
    assert "output for a" in events["job-a"]
    assert "output for b" not in events["job-a"]
    assert "output for b" in events["job-b"]
    assert "output for a" not in events["job-b"]


def test_install_print_capture_is_idempotent_and_restorable():
    import sys

    original = sys.stdout
    try:
        install_print_capture()
        first = sys.stdout
        assert isinstance(first, _TeeStdout)
        install_print_capture()
        assert sys.stdout is first
    finally:
        uninstall_print_capture()
    assert sys.stdout is original


def test_real_print_through_the_global_stream_end_to_end(bl, capsys):
    """The one true end-to-end proof, deliberately stepping outside pytest's
    own stdout capture (which otherwise fights this fixture-level swap)."""
    with capsys.disabled():
        install_print_capture()
        try:
            with bl.capture(kind="service", name="job") as ctx:
                print("through the real stream", end="")
        finally:
            uninstall_print_capture()
    assert ctx.stdout_text == "through the real stream"
