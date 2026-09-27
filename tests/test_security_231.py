# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Regression tests for the 2.3.0 assessment, using synthetic data."""
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
import pytest
from jscoup import JSCoup, MemoryStorage
from jscoup.crypto import generate_key
from jscoup.dashboard.auth import hash_password
from jscoup.gateway import GatewayStore
from jscoup.calllog import CallLogStore
from jscoup.sanitizer import sql_shape


def make(**kw):
    options = dict(storage=MemoryStorage(), dashboard_username='admin', dashboard_password='password',
                   gateway_enabled=True, capture_success=True)
    options.update(kw)
    return JSCoup('security-test', **options)


def capture(bl):
    ctx = bl.begin(kind='http', name='GET /profile', path='/profile', method='GET')
    ctx.status_code = 200
    ctx.response_preview = '{"medical":"PRIVATE_MEDICAL","password":"PRIVATE_SECRET"}'
    return bl.end(ctx)


@pytest.mark.parametrize('capture_success', [True, False])
def test_privacy_drop_applies_to_every_sink(capture_success):
    bl = make(before_store=lambda e: None, capture_success=capture_success)
    capture(bl)
    assert bl.call_log.count() == bl.storage.count() == 0
    bl.close()


def test_failing_privacy_hook_is_fail_closed():
    def broken(event):
        raise RuntimeError('policy failure')
    bl = make(before_store=broken)
    capture(bl)
    assert bl.call_log.count() == bl.storage.count() == 0
    assert bl.metrics()['before_store_failures'] == 1
    bl.close()


def test_private_response_never_enters_public_docs_even_from_legacy_rows():
    from flask import Flask, jsonify, request
    app = Flask(__name__)
    @app.get('/profile')
    def profile():
        if request.headers.get('Authorization') != 'Bearer owner':
            return jsonify(error='denied'), 401
        return jsonify(medical='PRIVATE_MEDICAL')
    bl = make()
    bl.install(app)
    client = app.test_client()
    assert client.get('/profile', headers={'Authorization': 'Bearer owner'}).status_code == 200
    target = next(t for t in bl.registry.all() if t.path == '/profile')
    bl.gateway.create_doc_group('public-guide', 'Public guide', [target.id])
    bl.call_log.conn.execute("UPDATE call_log SET response_preview = ?", ('{"medical":"PRIVATE_MEDICAL"}',))
    bl.call_log.conn.commit()
    result = client.get('/__jscoup/public-guide/data')
    assert result.status_code == 200 and b'PRIVATE_MEDICAL' not in result.data
    assert client.get('/profile').status_code == 401
    bl.close()


def test_metadata_only_logs_and_encrypted_event():
    inner = MemoryStorage()
    bl = make(storage=inner, encryption_key=generate_key())
    capture(bl)
    row = bl.call_log.recent()[0]
    assert row['response_preview'] is row['actor'] is None
    assert 'PRIVATE_MEDICAL' not in json.dumps(inner.list()[0].to_dict())
    assert 'PRIVATE_SECRET' not in json.dumps(bl.storage.list()[0].to_dict())
    bl.close()


def test_sql_double_quoted_values_are_not_retained():
    assert 'PRIVATE_NAME' not in sql_shape('SELECT * FROM t WHERE name="PRIVATE_NAME"')


def test_gateway_isolates_all_state_and_tokens():
    a, b = make(auth_realm_id='a'), make(auth_realm_id='b')
    a.gateway.create_user('A', 'alice', 'pw', '*')
    a.gateway.set_public('http:GET:/profile', True)
    token = a.gateway.login('alice', 'pw')['token']
    assert b.gateway.authenticate(token) is None
    assert not b.gateway.list_users() and not b.gateway.is_public('http:GET:/profile')
    assert a.gateway.db_path != b.gateway.db_path
    a.close(); b.close()


def test_gateway_downstream_credential_requires_encryption():
    store = GatewayStore('plain.db')
    with pytest.raises(ValueError, match='requires encryption_key'):
        store.create_user('A', 'alice', 'pw', '*', downstream_token='SECRET')
    assert store.list_users() == []
    store.close()


def test_gateway_credential_roundtrip_never_writes_plaintext():
    store = GatewayStore('encrypted.db', encryption_key=generate_key())
    store.create_user('A', 'alice', 'pw', '*', downstream_token='DOWNSTREAM_SECRET')
    persisted = store.conn.execute('SELECT downstream_token FROM gateway_users').fetchone()[0]
    assert persisted.startswith('enc:') and 'DOWNSTREAM_SECRET' not in persisted
    assert store.login('alice', 'pw')['user'].downstream_token == 'DOWNSTREAM_SECRET'
    store.close()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permissions')
def test_local_state_permissions_with_permissive_umask():
    old = os.umask(0o022)
    try:
        bl = make()
        capture(bl)
        stores = [bl.gateway, bl.dashboard._sessions, bl.call_log]
        from jscoup.storage.sqlite import SQLiteStorage
        stores.append(SQLiteStorage('events.db'))
        for store in stores:
            assert stat.S_IMODE(os.stat(store.db_path).st_mode) == 0o600
            for suffix in ('-wal', '-shm'):
                if os.path.exists(store.db_path + suffix):
                    assert stat.S_IMODE(os.stat(store.db_path + suffix).st_mode) == 0o600
        stores[-1].close()
        bl.close()
    finally:
        os.umask(old)


def test_runtime_rotation_invalidates_cookie():
    bl = make()
    r = bl.dashboard.handle('/api/login', 'POST', body=b'{"username":"admin","password":"password"}')
    cookie = r.headers['Set-Cookie'].split(';')[0]
    bl.config.dashboard_password_hash = hash_password('new-password')
    bl.config.credential_epoch = '2'
    assert bl.dashboard.handle('/api/health', headers={'Cookie': cookie}).status == 401
    bl.close()


def test_source_lockout_does_not_lock_out_other_source():
    bl = make()
    for _ in range(5):
        assert bl.dashboard.handle('/api/login', 'POST', body=b'{"username":"admin","password":"wrong"}', client_ip='192.0.2.1').status == 401
    r = bl.dashboard.handle('/api/login', 'POST', body=b'{"username":"admin","password":"password"}', client_ip='192.0.2.2')
    assert r.status == 200
    bl.close()


def test_quotas_shared_across_processes():
    store = GatewayStore('quota.db')
    assert store.allow_rate('same', 2, 60)
    import jscoup
    env = dict(os.environ, PYTHONPATH=str(Path(jscoup.__file__).resolve().parents[1]))
    code = "from jscoup.gateway import GatewayStore; s=GatewayStore('quota.db'); print(s.allow_rate('same',2,60)); s.close()"
    outputs = [subprocess.check_output([sys.executable, '-c', code], env=env, text=True).strip() for _ in range(2)]
    assert outputs == ['True', 'False']
    store.close()


def test_quota_capacity_is_bounded_and_expiry_recovers():
    from jscoup.security import allow_quota
    store = GatewayStore('quota.db')
    assert allow_quota(store.conn, 'a', 1, 60, capacity=2)
    assert allow_quota(store.conn, 'b', 1, 60, capacity=2)
    assert not allow_quota(store.conn, 'c', 1, 60, capacity=2)
    store.conn.execute('UPDATE security_quotas SET expires = 0')
    store.conn.commit()
    assert allow_quota(store.conn, 'c', 1, 60, capacity=2)
    store.close()


def test_async_call_log_does_not_wait_on_disk_and_flushes():
    bl = make(async_storage=True)
    entered, release = threading.Event(), threading.Event()
    original = bl.call_log.record
    def blocked(**row):
        entered.set()
        assert release.wait(5)
        original(**row)
    bl.call_log.record = blocked
    capture(bl)
    assert entered.wait(2)
    assert not bl.flush(.01)
    release.set()
    assert bl.flush(5) and bl.call_log.count() == 1
    assert bl.close()


def test_call_log_max_rows():
    store = CallLogStore('calls.db', max_rows=3)
    for _ in range(8):
        store.record(kind='http', name='GET /x', method='GET', path='/x', status_code=200, ok=True, duration_ms=1, actor=None, response_preview='SECRET')
    assert store.count() == 3
    assert all(r['response_preview'] is None for r in store.recent())
    store.close()


def test_direct_dashboard_body_limit_and_origin():
    bl = make(dashboard_max_body_bytes=64)
    assert bl.dashboard.handle('/api/login', 'POST', body=b'x'*65).status == 413
    assert bl.dashboard.handle('/api/logout', 'POST', headers={'Origin':'https://evil.test'}, base_url='https://app.test').status == 403
    assert bl.dashboard.handle('/api/login','POST',headers={'Sec-Fetch-Site':'cross-site'}).status == 403
    bl.close()


def test_legacy_token_is_header_only():
    bl = JSCoup(storage=MemoryStorage(), dashboard_token='secret')
    assert bl.dashboard.handle('/api/health', query={'token':'secret'}).status == 401
    assert bl.dashboard.handle('/api/health', headers={'X-JSCoup-Token':'secret'}).status == 200
    bl.close()


def test_password_work_factor_and_secure_production_cookie():
    from jscoup.config import JSCoupConfig
    assert hash_password('example').split('$')[1] == '600000'
    bl = make(environment='production')
    assert bl.config.dashboard_cookie_secure is True
    assert JSCoupConfig().dashboard_cookie_secure is False
    bl.close()


def test_response_read_is_bounded():
    from jscoup.simulator import _read_response
    import io
    assert _read_response(io.BytesIO(b'123'), 3) == b'123'
    with pytest.raises(ValueError):
        _read_response(io.BytesIO(b'1234'), 3)


def test_publisher_drops_oversized_item_and_reports_it():
    from jscoup.publisher import EventPublisher
    publisher = EventPublisher(MemoryStorage(), max_bytes=128)
    assert not publisher.submit({'body':'x'*1024})
    assert publisher.metrics()['dropped'] == 1 and publisher.metrics()['pending_bytes'] == 0
    assert publisher.close()


def test_flask_request_limit_and_security_headers():
    from flask import Flask
    app = Flask(__name__)
    bl = make(dashboard_max_body_bytes=64)
    bl.install(app)
    assert app.test_client().post('/__jscoup/api/login', data=b'x'*65).status_code == 413
    response = app.test_client().get('/__jscoup/')
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    bl.close()


def test_fastapi_request_limit_stream():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    bl = make(dashboard_max_body_bytes=64)
    bl.install(app)
    with TestClient(app) as client:
        assert client.post('/__jscoup/api/login', content=b'x'*65).status_code == 413
    bl.close()


def test_explicit_rotation_api_revokes_session():
    bl = make()
    r = bl.dashboard.handle('/api/login', 'POST', body=b'{"username":"admin","password":"password"}')
    cookie = r.headers['Set-Cookie'].split(';')[0]
    bl.rotate_dashboard_credentials('new-password', 'deployment-2')
    assert bl.dashboard.handle('/api/health', headers={'Cookie':cookie}).status == 401
    assert bl.dashboard.handle('/api/login', 'POST', body=b'{"username":"admin","password":"new-password"}').status == 200
    bl.close()


def test_concurrent_process_quotas_are_atomic():
    import jscoup
    store = GatewayStore('concurrent.db')
    store.allow_rate('initialize', 1, 60)
    env = dict(os.environ, PYTHONPATH=str(Path(jscoup.__file__).resolve().parents[1]))
    code = "from jscoup.gateway import GatewayStore; s=GatewayStore('concurrent.db'); print(s.allow_rate('shared',3,60)); s.close()"
    children = [subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True) for _ in range(8)]
    results = []
    for child in children:
        out, err = child.communicate(timeout=15)
        assert child.returncode == 0, err
        results.append(out.strip())
    assert results.count('True') == 3 and results.count('False') == 5
    store.close()


def test_concurrency_cap_releases_after_completion(monkeypatch):
    bl = make(invoke_max_concurrency=1)
    target = bl.registry.add_manual('GET', '/x').id
    started, release = threading.Event(), threading.Event()
    def blocked(*args):
        started.set()
        assert release.wait(5)
        return {'ok':True}
    monkeypatch.setattr(bl.simulator, '_invoke_http_inner', blocked)
    thread = threading.Thread(target=lambda: bl.invoke(target))
    thread.start()
    assert started.wait(2)
    assert 'concurrency limit' in bl.invoke(target)['error']
    release.set(); thread.join(5)
    assert bl.invoke(target)['ok']
    bl.close()


def test_async_cancellation_keeps_network_slot_until_thread_finishes(monkeypatch):
    import asyncio
    bl = make(invoke_max_concurrency=1)
    target = bl.registry.add_manual('GET', '/x').id
    started, release, done = threading.Event(), threading.Event(), threading.Event()
    def blocked(*args):
        started.set()
        assert release.wait(5)
        done.set()
        return {'ok':True}
    monkeypatch.setattr(bl.simulator, '_invoke_http_inner', blocked)
    async def exercise():
        task = asyncio.create_task(bl.ainvoke(target))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 'concurrency limit' in bl.invoke(target)['error']
        release.set()
        assert await asyncio.to_thread(done.wait, 2)
    asyncio.run(exercise())
    assert bl.invoke(target)['ok']
    bl.close()


def test_upload_checks_encoded_size_before_decode_and_aggregate(monkeypatch):
    import base64
    import jscoup.simulator as simulator
    monkeypatch.setattr(simulator, 'MAX_UPLOAD_BYTES', 1024)
    with pytest.raises(ValueError, match='Encoded file'):
        simulator._encode_multipart({}, {'file':{'filename':'x', 'data':'A'*2000}})
    encoded = base64.b64encode(b'x'*600).decode()
    with pytest.raises(ValueError, match='Aggregate upload'):
        simulator._encode_multipart({}, {'a':{'filename':'a','data':encoded}, 'b':{'filename':'b','data':encoded}})


def test_closed_instance_does_not_reopen_capture_storage():
    bl = make()
    assert bl.close()
    assert capture(bl) is None
    assert not hasattr(bl, '_call_log')


def test_batched_call_log_commits_once_and_omits_bodies():
    store = CallLogStore('batch.db', max_rows=25)
    statements = []
    store.conn.set_trace_callback(statements.append)
    row = dict(kind='http', name='GET /x', method='GET', path='/x', status_code=200, ok=True, duration_ms=1, actor='PRIVATE_PERSON', response_preview='PRIVATE_BODY')
    store.record_many([row] * 100)
    assert sum(s == 'COMMIT' for s in statements) == 1
    assert store.count() == 25
    assert all(r['actor'] is r['response_preview'] is None for r in store.recent())
    store.close()
