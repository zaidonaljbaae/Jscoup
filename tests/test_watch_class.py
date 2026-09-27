# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for JSCoup.watch_class and watch_module's class support."""

from __future__ import annotations

import sys
import types

from jscoup import JSCoup, MemoryStorage


def _bl(**overrides):
    return JSCoup("class-test", storage=MemoryStorage(), **overrides)


def _fake_module(name, **members):
    module = types.ModuleType(name)
    for member_name, obj in members.items():
        obj.__module__ = name
        if isinstance(obj, type):
            obj.__qualname__ = member_name
        else:
            obj.__name__ = member_name
            obj.__qualname__ = member_name
        setattr(module, member_name, obj)
    sys.modules[name] = module
    return module


def test_watch_class_wraps_instance_methods_and_captures_failures():
    bl = _bl()

    class ActionService:
        def run(self, amount):
            if amount < 0:
                raise ValueError("negative amount")
            return amount * 2

    bl.watch_class(ActionService)
    service = ActionService()

    assert service.run(3) == 6
    try:
        service.run(-1)
    except ValueError:
        pass

    events = bl.storage.list()
    assert len(events) == 1
    assert events[0].error_type == "ValueError"
    assert "run" in events[0].name


def test_watch_class_excludes_self_from_captured_params():
    bl = _bl(capture_success=True)

    class Thing:
        def do(self, x):
            return x

    bl.watch_class(Thing)
    Thing().do(5)

    event = bl.storage.list()[0]
    assert event.params == {"x": 5}
    assert "self" not in event.params


def test_watch_class_is_idempotent():
    bl = _bl()

    class Thing:
        def do(self):
            return 1

    assert bl.watch_class(Thing) == 1
    assert bl.watch_class(Thing) == 0  # already wrapped


def test_watch_class_skips_dunders_and_private_by_default():
    bl = _bl()

    class Thing:
        def public(self):
            return 1

        def _private(self):
            return 2

        def __repr__(self):
            return "Thing()"

    wrapped = bl.watch_class(Thing)

    assert wrapped == 1  # only "public"


def test_watch_module_now_also_wraps_classes_defined_in_it():
    bl = _bl()

    class ActionService:
        def run(self):
            raise RuntimeError("boom")

    module = _fake_module("_wc_module_a", ActionService=ActionService)
    try:
        count = bl.watch_module(module)
        assert count == 1

        service = module.ActionService()
        try:
            service.run()
        except RuntimeError:
            pass

        events = bl.storage.list()
        assert len(events) == 1
        assert events[0].error_type == "RuntimeError"
    finally:
        del sys.modules["_wc_module_a"]


def test_registry_does_not_list_self_as_a_parameter():
    bl = _bl()

    class Thing:
        def do(self, value):
            return value

    bl.watch_class(Thing)
    target = bl.registry.get(f"service:{Thing.__module__}.{Thing.__qualname__}.do")

    assert target is not None
    assert [p.name for p in target.params] == ["value"]
