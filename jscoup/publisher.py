# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Bounded, best-effort background delivery with observable backpressure."""
import copy
import os
import queue
import sys
import threading
import time
from dataclasses import fields, is_dataclass


def _resident_size(value, seen=None):
    """Python-object accounting; not a process RSS guarantee."""
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if is_dataclass(value):
        return size + sum(_resident_size(getattr(value, f.name), seen) for f in fields(value))
    if isinstance(value, dict):
        return size + sum(_resident_size(k, seen) + _resident_size(v, seen) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return size + sum(_resident_size(v, seen) for v in value)
    return size


class EventPublisher:
    def __init__(self, storage, capacity=4096, on_event=None, max_bytes=16 * 1024 * 1024):
        self.storage = storage
        self.capacity = capacity
        self.on_event = on_event
        self.max_bytes = max_bytes
        self._pid = os.getpid()
        self._queue = queue.Queue(capacity)
        self._condition = threading.Condition()
        self._thread = None
        self._closing = False
        self._pending = 0
        self._pending_bytes = 0
        self._metrics = dict(accepted=0, saved=0, dropped=0, failed=0, callback_failed=0)

    def submit(self, event):
        if os.getpid() != self._pid:
            raise RuntimeError('Create JSCoup in each worker after fork')
        size = _resident_size(event)
        with self._condition:
            if self._closing or self._pending_bytes + size > self.max_bytes or self._queue.full():
                self._metrics['dropped'] += 1
                return False
            snapshot = copy.deepcopy(event)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True, name='jscoup-publisher')
                self._thread.start()
            self._queue.put_nowait((snapshot, size))
            self._pending += 1
            self._pending_bytes += size
            self._metrics['accepted'] += 1
            return True

    def _run(self):
        try:
            while True:
                try:
                    event, size = self._queue.get(timeout=.05)
                except queue.Empty:
                    with self._condition:
                        if self._closing:
                            return
                    continue
                batch = [(event, size)]
                if hasattr(self.storage, 'save_batch'):
                    while len(batch) < 100:
                        try:
                            batch.append(self._queue.get_nowait())
                        except queue.Empty:
                            break
                try:
                    if len(batch) > 1:
                        self.storage.save_batch([item for item, _ in batch])
                    else:
                        self.storage.save(event)
                    with self._condition:
                        self._metrics['saved'] += len(batch)
                    if self.on_event:
                        for item, _ in batch:
                            try:
                                self.on_event(item)
                            except Exception:
                                with self._condition:
                                    self._metrics['callback_failed'] += 1
                except Exception:
                    with self._condition:
                        self._metrics['failed'] += len(batch)
                finally:
                    with self._condition:
                        self._pending -= len(batch)
                        self._pending_bytes -= sum(item_size for _, item_size in batch)
                        self._condition.notify_all()
                    for _ in batch:
                        self._queue.task_done()
        finally:
            self.storage.close()

    def flush(self, timeout=5):
        deadline = time.monotonic() + max(0, timeout)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def close(self, timeout=5):
        with self._condition:
            self._closing = True
        if threading.current_thread() is self._thread:
            return False
        deadline = time.monotonic() + max(0, timeout)
        complete = self.flush(timeout)
        if self._thread:
            self._thread.join(max(0, deadline - time.monotonic()))
        else:
            self.storage.close()
        return complete and (self._thread is None or not self._thread.is_alive())

    def metrics(self):
        with self._condition:
            return {**self._metrics, 'pending': self._pending, 'capacity': self.capacity,
                    'pending_bytes': self._pending_bytes, 'max_bytes': self.max_bytes,
                    'closed': self._closing}
