# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.storage.connections — the shared connection-building
helpers (URL construction, connection files, SSH tunneling) used by both
SqlStorage and MongoStorage."""

from __future__ import annotations

import json

import pytest

from jscoup.storage.connections import build_sql_url, load_connection_file


def test_build_sql_url_passes_a_plain_url_through_unchanged():
    assert build_sql_url(url="sqlite:///events.db") == "sqlite:///events.db"


def test_build_sql_url_from_discrete_parts():
    pytest.importorskip("sqlalchemy")
    url = build_sql_url(
        drivername="postgresql+psycopg2", username="app", password="secret",
        host="db.internal", port=5432, database="jscoup",
    )
    assert url.startswith("postgresql+psycopg2://app:secret@db.internal:5432/jscoup")


def test_build_sql_url_percent_encodes_special_characters_in_password():
    """A hand-concatenated f-string breaks the moment a password contains
    '@' or '/' — building through SQLAlchemy's URL.create() must not."""
    pytest.importorskip("sqlalchemy")
    url = build_sql_url(
        drivername="postgresql+psycopg2", username="app", password="p@ss/word",
        host="db.internal", port=5432, database="jscoup",
    )
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    assert parsed.password == "p@ss/word"


def test_build_sql_url_requires_url_or_drivername():
    with pytest.raises(ValueError):
        build_sql_url()


def test_load_connection_file_json(tmp_path):
    path = tmp_path / "db.json"
    path.write_text(json.dumps({"url": "sqlite:///x.db"}))
    assert load_connection_file(str(path)) == {"url": "sqlite:///x.db"}


def test_load_connection_file_yaml(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "db.yaml"
    path.write_text("host: db.internal\nport: 5432\nusername: app\n")
    data = load_connection_file(str(path))
    assert data == {"host": "db.internal", "port": 5432, "username": "app"}


def test_load_connection_file_ini(tmp_path):
    path = tmp_path / "db.ini"
    path.write_text("[connection]\nhost = db.internal\nport = 5432\nusername = app\n")
    data = load_connection_file(str(path))
    assert data["host"] == "db.internal"
    assert data["port"] == 5432
    assert data["username"] == "app"


def test_load_connection_file_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_connection_file("/no/such/file.json")


def test_load_connection_file_unsupported_extension(tmp_path):
    path = tmp_path / "db.txt"
    path.write_text("host=db.internal")
    with pytest.raises(ValueError):
        load_connection_file(str(path))


# --------------------------------------------------------------------------- #
# SSH tunnel — orchestration only (start/stop/idempotency), no real SSH server
# --------------------------------------------------------------------------- #


class _FakeForwarder:
    instances = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.started = False
        self.local_bind_port = 54321
        _FakeForwarder.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.started = False


class _FakeSSHClient:
    def load_system_host_keys(self): pass
    def set_missing_host_key_policy(self, policy): self.policy = policy
    def connect(self, **kwargs): self.kwargs = kwargs
    def get_transport(self): return self
    def close(self): pass


def test_ssh_tunnel_starts_once_and_reports_local_port(monkeypatch):
    import paramiko
    client = _FakeSSHClient()
    monkeypatch.setattr(paramiko, "SSHClient", lambda: client)
    from jscoup.storage.connections import SSHTunnel
    tunnel = SSHTunnel(ssh_host="bastion", remote_bind_host="db", remote_bind_port=5432)
    assert isinstance(client.policy, paramiko.RejectPolicy)
    port = tunnel.start()
    try:
        assert port > 0
        assert tunnel.start() == port
        assert tunnel._server.server_address[0] == "127.0.0.1"
    finally:
        tunnel.stop()
    assert tunnel.local_bind_port is None


def test_apply_ssh_tunnel_defaults_remote_bind_to_the_target_host_port(monkeypatch):
    import paramiko
    monkeypatch.setattr(paramiko, "SSHClient", _FakeSSHClient)
    from jscoup.storage.connections import apply_ssh_tunnel
    tunnel, host, port = apply_ssh_tunnel({"ssh_host": "bastion"}, target_host="db", target_port=5432)
    try:
        assert host == "127.0.0.1" and port > 0
        assert tunnel._remote == ("db", 5432)
    finally:
        tunnel.stop()
