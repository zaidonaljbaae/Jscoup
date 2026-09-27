# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Shared boundaries for local state and cross-worker quotas.

SQLite coordination is for workers on one host, not a distributed cluster.
"""
import hashlib
import os
import stat
import time


def private_file(path):
    """Create state without a world-readable creation window; reject symlinks."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('State path must be a regular file')
        if os.name == 'posix':
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    for suffix in ('-wal', '-shm'):
        companion = path + suffix
        if os.path.exists(companion) and os.name == 'posix':
            fd = os.open(companion, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)


def realm_path(path, realm):
    """All tables in a gateway database belong to exactly one realm."""
    stem, extension = os.path.splitext(path)
    digest = hashlib.sha256(realm.encode()).hexdigest()[:32]
    return stem + '.' + digest + (extension or '.db')


def allow_quota(conn, key, limit, window, capacity=10000):
    """Atomic fixed-window quota, bounded state, fail closed at capacity.

    Caller must hold its connection's thread lock. BEGIN IMMEDIATE also
    serializes competing processes. Keys are hashed, never stored verbatim.
    """
    now = time.time()
    key = hashlib.sha256(key.encode()).hexdigest()
    conn.execute('CREATE TABLE IF NOT EXISTS security_quotas '
                 '(key TEXT PRIMARY KEY, hits INTEGER NOT NULL, expires REAL NOT NULL)')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_quotas_expiry ON security_quotas(expires)")
    conn.commit()
    conn.execute('BEGIN IMMEDIATE')
    try:
        conn.execute('DELETE FROM security_quotas WHERE expires <= ?', (now,))
        row = conn.execute('SELECT hits FROM security_quotas WHERE key = ?', (key,)).fetchone()
        if row is None:
            if conn.execute('SELECT COUNT(*) FROM security_quotas').fetchone()[0] >= capacity:
                conn.commit()
                return False
            conn.execute('INSERT INTO security_quotas VALUES (?,?,?)', (key, 1, now + window))
            permitted = True
        else:
            permitted = row[0] < limit
            if permitted:
                conn.execute('UPDATE security_quotas SET hits = hits + 1 WHERE key = ?', (key,))
        conn.commit()
        return permitted
    except BaseException:
        conn.rollback()
        raise
