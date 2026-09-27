# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Bind print() output to the request/call that produced it.

Reuses the same contextvar-backed stack ``record_query()`` uses to attach a
SQL statement to every active :class:`~jscoup.context.CaptureContext`, so
concurrent requests' captured output doesn't cross-contaminate.

Known limitation: a ``print()`` from a raw ``threading.Thread`` started
without ``contextvars.copy_context()`` runs in a fresh, empty context and
won't be attributed to anything.
"""

from __future__ import annotations

import sys
import threading
from typing import Any

from .context import record_stdout

_lock = threading.Lock()
_installed = False
_original_stdout: Any = None


class _TeeStdout:
    """Forwards every write to the real stdout (console output is never
    swallowed) and, for output that shouldn't be discarded, to whichever
    CaptureContext(s) are active on the calling context."""

    def __init__(self, original: Any):
        self._original = original

    def write(self, text: str) -> int:
        if text:
            record_stdout(text)
        return self._original.write(text)

    def flush(self) -> None:
        self._original.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


def install_print_capture() -> None:
    """Idempotent — safe to call more than once."""
    global _installed, _original_stdout
    with _lock:
        if _installed:
            return
        _original_stdout = sys.stdout
        sys.stdout = _TeeStdout(_original_stdout)
        _installed = True


def uninstall_print_capture() -> None:
    global _installed
    with _lock:
        if not _installed or _original_stdout is None:
            return
        sys.stdout = _original_stdout
        _installed = False
