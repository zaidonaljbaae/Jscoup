# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for the exact-source-line extraction added to core.py._culprit()."""

from __future__ import annotations

from jscoup import JSCoup, MemoryStorage


def _bl():
    return JSCoup("culprit-test", storage=MemoryStorage())


def test_event_carries_the_exact_source_line_that_raised():
    bl = _bl()

    @bl.watch(kind="service", reraise=False)
    def broken():
        data = {"a": 1}
        return data["missing_key"]  # <- this is the line that must be quoted

    broken()

    event = bl.storage.list()[0]
    assert event.culprit_line == 'return data["missing_key"]  # <- this is the line that must be quoted'


def test_diagnosis_evidence_includes_the_source_line():
    bl = _bl()

    @bl.watch(kind="service", reraise=False)
    def broken():
        raise KeyError("missing")

    broken()

    event = bl.storage.list()[0]
    assert event.diagnosis is not None
    assert event.diagnosis.evidence.get("source_line") == event.culprit_line


def test_culprit_points_at_the_callers_frame_not_this_librarys_own_code():
    bl = _bl()

    @bl.watch(kind="service", reraise=False)
    def broken():
        raise ValueError("nope")

    broken()

    event = bl.storage.list()[0]
    assert "test_culprit_line.py" in event.culprit
    assert "core.py" not in event.culprit  # never blame the library's own wrapper frame


def test_no_exception_means_no_culprit_line():
    bl = JSCoup("t", storage=MemoryStorage(), capture_success=True)

    @bl.watch(kind="service")
    def fine():
        return 1

    fine()

    event = bl.storage.list()[0]
    assert event.culprit_line is None
