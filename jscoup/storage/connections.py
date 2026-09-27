# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Shared connection-building helpers for every real-database backend
(``SqlStorage`` for Postgres/MySQL/Oracle/MSSQL/SQLite, ``MongoStorage`` for
MongoDB).

Three connection patterns are supported, all funnelling into the same shape
a backend's ``__init__`` already accepts (``url=...`` or discrete keyword
parts):

1. A plain connection URL/DSN string.
2. Discrete parts (host/port/username/password/database/...), safer than
   hand-built string concatenation once a password can contain characters
   like ``@`` or ``/``.
3. A connection file — a JSON/YAML/``.ini`` file holding the same parts.
   ``load_connection_file()`` reads one into a plain dict; the caller (a
   storage backend's ``from_file()`` classmethod) applies it.

SSH tunneling to a database reachable only through a bastion/jump host is
provided by :class:`SSHTunnel`, used the same way by both backends.
"""

from __future__ import annotations

import configparser
import json
import os
from typing import Any, Dict, Optional


def build_sql_url(
    *,
    url: Optional[str] = None,
    drivername: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
    query: Optional[Dict[str, str]] = None,
) -> str:
    """Return a SQLAlchemy connection URL. If ``url`` is given, it's returned
    as-is; otherwise one is built from the discrete parts via
    ``sqlalchemy.engine.URL.create`` — which percent-encodes the username/
    password for you, unlike hand-concatenating an f-string."""
    if url:
        return url
    from sqlalchemy.engine import URL

    if not drivername:
        raise ValueError("build_sql_url needs either `url` or `drivername` (e.g. 'postgresql+psycopg2')")
    return URL.create(
        drivername=drivername, username=username, password=password,
        host=host, port=port, database=database, query=query or {},
    ).render_as_string(hide_password=False)


def load_connection_file(path: str) -> Dict[str, Any]:
    """Load a connection profile from a ``.json``, ``.yaml``/``.yml`` or
    ``.ini`` file into a plain dict of whatever keys it has — ``url``,
    ``drivername``, ``username``, ``password``, ``host``, ``port``,
    ``database``, ``query``, ``ssh_tunnel`` (itself a nested dict, see
    :class:`SSHTunnel`), or backend-specific extras. An ``.ini`` file is read
    from its ``[connection]`` section if present, else its first section.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"No connection file at {path!r}")
    ext = os.path.splitext(path)[1].lower()

    if ext == ".json":
        with open(path, "r", encoding="utf-8") as fh:
            result = json.load(fh)
            if not isinstance(result, dict):
                raise ValueError("Connection profile must be an object")
            return result

    if ext in (".yaml", ".yml"):
        import yaml  # optional: pip install jscoup[yaml]

        with open(path, "r", encoding="utf-8") as fh:
            result = yaml.safe_load(fh) or {}
            if not isinstance(result, dict):
                raise ValueError("Connection profile must be an object")
            return result

    if ext in (".ini", ".cfg", ".conf"):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(path, encoding="utf-8")
        section = "connection" if parser.has_section("connection") else (parser.sections() or [None])[0]
        if section is None:
            return {}
        data = dict(parser.items(section))
        if "port" in data:
            data["port"] = int(data["port"])
        return data

    raise ValueError(f"Unsupported connection file type: {ext!r} (use .json, .yaml or .ini)")


from .ssh import SSHTunnel


def apply_ssh_tunnel(
    ssh_tunnel: Dict[str, Any], *, target_host: str, target_port: int
) -> "tuple[SSHTunnel, str, int]":
    """Start a tunnel described by an ``ssh_tunnel`` dict (the same shape
    ``SSHTunnel.__init__`` takes, plus ``remote_bind_host``/
    ``remote_bind_port`` defaulting to the database's own host/port) and
    return ``(tunnel, local_host, local_port)`` to connect to instead."""
    kwargs = dict(ssh_tunnel)
    kwargs.setdefault("remote_bind_host", target_host)
    kwargs.setdefault("remote_bind_port", target_port)
    tunnel = SSHTunnel(**kwargs)
    local_port = tunnel.start()
    return tunnel, "127.0.0.1", local_port
