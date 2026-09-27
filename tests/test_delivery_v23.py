# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
import threading
from jscoup.publisher import EventPublisher
from jscoup.dashboard.sessions import SessionStore
from jscoup import JSCoup, MemoryStorage


def test_bounded_delivery_and_flush():
    entered = threading.Event()
    release = threading.Event()
    class Storage:
        def __init__(self): self.items = []; self.closed = False
        def save(self, event):
            entered.set()
            assert release.wait(2)
            self.items.append(event)
        def close(self): self.closed = True
    store = Storage()
    publisher = EventPublisher(store, capacity=1)
    original = {'value': [1]}
    assert publisher.submit(original)
    assert entered.wait(2)
    original['value'].append(2)
    assert publisher.submit({'value': [3]})
    assert not publisher.submit({'value': [4]})
    assert not publisher.flush(.01)
    release.set()
    assert publisher.close(2)
    assert store.items == [{'value': [1]}, {'value': [3]}]
    assert store.closed
    stats = publisher.metrics()
    assert stats['saved'] == 2 and stats['dropped'] == 1 and stats['pending'] == 0


def test_delivery_failure_is_counted():
    class Storage:
        def save(self, event): raise OSError('unavailable')
        def close(self): pass
    p = EventPublisher(Storage())
    assert p.submit({})
    assert p.close(2)
    assert p.metrics()['failed'] == 1


def test_revoke_all_is_scoped_to_realm(tmp_path):
    a = SessionStore(str(tmp_path/'sessions.db'), 'a')
    b = SessionStore(str(tmp_path/'sessions.db'), 'b')
    token_a = a.create('admin',60)
    token_b = b.create('admin',60)
    assert a.verify(token_b) is None
    a.revoke_all()
    assert a.verify(token_a) is None
    assert b.verify(token_b) == 'admin'
    a.close(); b.close()


def test_generated_credentials_have_distinct_realms():
    a = JSCoup(storage=MemoryStorage())
    b = JSCoup(storage=MemoryStorage())
    assert a._auth_credential_id and a._auth_credential_id != b._auth_credential_id


def test_zero_sampling_preserves_return_and_exception():
    x = JSCoup(storage=MemoryStorage(), sample_rate=0, dashboard_local_dev=True)
    @x.watch()
    def work(fail=False):
        if fail: raise ValueError('expected')
        return 42
    assert work() == 42
    import pytest
    with pytest.raises(ValueError): work(True)
    with x.capture(name='manual'): pass
    assert x.storage.list() == []
