# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Storage backends."""

from .base import BaseStorage
from .memory import MemoryStorage
from .sqlite import SQLiteStorage

__all__ = ["BaseStorage", "MemoryStorage", "SQLiteStorage", "SqlStorage"]


def __getattr__(name):  # PEP 562 lazy import — SqlStorage needs SQLAlchemy
    if name == "SqlStorage":
        from .sql import SqlStorage

        return SqlStorage
    raise AttributeError(name)
