# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Dashboard: a framework agnostic JSON API plus a single page UI."""

from .api import DashboardAPI, Response, json_response
from .auth import hash_password, verify_password

__all__ = ["DashboardAPI", "Response", "json_response", "hash_password", "verify_password"]
