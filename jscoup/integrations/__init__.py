# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Framework integrations. Imports are lazy so no framework is a hard dependency."""

__all__ = [
    "install_flask",
    "install_fastapi",
    "install_django",
    "JSCoupMiddleware",
    "jscoup_urls",
    "run_standalone_dashboard",
]


def __getattr__(name):  # PEP 562 lazy imports
    if name == "install_flask":
        from .flask import install_flask
        return install_flask
    if name == "install_fastapi":
        from .fastapi import install_fastapi
        return install_fastapi
    if name in ("install_django", "JSCoupMiddleware", "jscoup_urls"):
        from . import django as dj
        return getattr(dj, name)
    if name == "run_standalone_dashboard":
        from .standalone import run_standalone_dashboard
        return run_standalone_dashboard
    raise AttributeError(name)
