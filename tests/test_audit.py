# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for the static naming/style auditor and the route-collision check."""

from __future__ import annotations

from jscoup.audit import audit_code, audit_paths, audit_routes
from jscoup.registry import Registry, Target


def _write(tmp_path, name, source):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return str(path)


def _kinds(findings):
    return {f.kind for f in findings}


def test_clean_code_has_no_findings(tmp_path):
    _write(
        tmp_path, "clean.py",
        "class GoodClass:\n"
        "    def good_method(self, user_id, count=0):\n"
        "        return user_id, count\n",
    )
    assert audit_paths([str(tmp_path)]) == []


def test_function_naming_flags_non_snake_case(tmp_path):
    path = _write(tmp_path, "sample.py", "def BadName():\n    pass\n")
    findings = audit_paths([path])
    assert "function_naming" in _kinds(findings)
    hit = next(f for f in findings if f.kind == "function_naming")
    assert hit.name == "BadName"
    assert hit.suggestion  # a rename suggestion is always provided


def test_dunder_functions_are_not_flagged(tmp_path):
    path = _write(tmp_path, "sample.py", "class C:\n    def __init__(self):\n        pass\n")
    assert audit_paths([path]) == []


def test_class_naming_flags_non_pascal_case(tmp_path):
    path = _write(tmp_path, "sample.py", "class bad_class_name:\n    pass\n")
    findings = audit_paths([path])
    hit = next(f for f in findings if f.kind == "class_naming")
    assert hit.name == "bad_class_name"
    assert hit.suggestion == "Rename to 'BadClassName' to match PEP 8."


def test_parameter_naming_flags_non_snake_case(tmp_path):
    path = _write(tmp_path, "sample.py", "def f(BadParam):\n    pass\n")
    findings = audit_paths([path])
    hit = next(f for f in findings if f.kind == "parameter_naming")
    assert hit.name == "BadParam"


def test_ambiguous_parameter_name_flagged_instead_of_generic_naming(tmp_path):
    path = _write(tmp_path, "sample.py", "def f(l):\n    pass\n")
    findings = audit_paths([path])
    kinds = _kinds(findings)
    assert "ambiguous_parameter_name" in kinds
    assert "parameter_naming" not in kinds  # not double-reported for the same name


def test_shadowed_builtin_parameter_is_flagged(tmp_path):
    path = _write(tmp_path, "sample.py", "def f(list):\n    pass\n")
    findings = audit_paths([path])
    hit = next(f for f in findings if f.kind == "shadowed_builtin")
    assert hit.name == "list"


def test_self_and_cls_are_never_flagged(tmp_path):
    path = _write(
        tmp_path, "sample.py",
        "class C:\n    def m(self):\n        pass\n    @classmethod\n    def n(cls):\n        pass\n",
    )
    assert audit_paths([path]) == []


def test_mutable_default_arguments_are_flagged(tmp_path):
    path = _write(
        tmp_path, "sample.py",
        "def f(a=[], b={}, c={1, 2}, d=None, e=3):\n    pass\n",
    )
    findings = [f for f in audit_paths([path]) if f.kind == "mutable_default_argument"]
    names = {f.name for f in findings}
    assert names == {"a", "b", "c"}  # d=None and e=3 are fine, not flagged


def test_bare_except_is_flagged(tmp_path):
    path = _write(tmp_path, "sample.py", "try:\n    pass\nexcept:\n    pass\n")
    findings = audit_paths([path])
    assert "bare_except" in _kinds(findings)


def test_silent_exception_swallow_is_flagged(tmp_path):
    path = _write(tmp_path, "sample.py", "try:\n    pass\nexcept Exception:\n    pass\n")
    findings = audit_paths([path])
    assert "silent_exception" in _kinds(findings)


def test_except_with_logging_is_not_flagged_as_silent(tmp_path):
    path = _write(
        tmp_path, "sample.py",
        "try:\n    pass\nexcept Exception:\n    log(1)\n",
    )
    findings = [f for f in audit_paths([path]) if f.kind == "silent_exception"]
    assert findings == []


def test_unparseable_file_is_skipped_not_fatal(tmp_path):
    _write(tmp_path, "broken.py", "def bad(:\n")
    _write(tmp_path, "ok.py", "def BadName():\n    pass\n")
    findings = audit_paths([str(tmp_path)])
    assert any(f.kind == "function_naming" and f.name == "BadName" for f in findings)


def test_venv_and_similar_directories_are_skipped(tmp_path):
    vendored_dir = tmp_path / ".venv" / "lib"
    vendored_dir.mkdir(parents=True)
    (vendored_dir / "vendored.py").write_text("def BadName():\n    pass\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def good_name():\n    pass\n", encoding="utf-8")
    findings = audit_paths([str(tmp_path)])
    assert not any("vendored.py" in f.file for f in findings)


def test_audit_paths_accepts_a_single_file_path(tmp_path):
    path = _write(tmp_path, "sample.py", "def BadName():\n    pass\n")
    findings = audit_paths([path])
    assert len(findings) == 1
    assert findings[0].file == path


# --------------------------------------------------------------------------- #
# route collisions
# --------------------------------------------------------------------------- #


def test_audit_routes_flags_method_path_collisions():
    registry = Registry()
    registry.add(Target(id="http:GET:/x:a", kind="http", name="view_a", method="GET", path="/x"))
    registry.add(Target(id="http:GET:/x:b", kind="http", name="view_b", method="GET", path="/x"))
    registry.add(Target(id="http:GET:/y", kind="http", name="view_c", method="GET", path="/y"))

    findings = audit_routes(registry)
    assert len(findings) == 1
    assert findings[0].kind == "route_collision"
    assert "view_a" in findings[0].message
    assert "view_b" in findings[0].message


def test_audit_routes_flags_a_collision_even_with_identical_target_ids():
    """The realistic case: discover_flask/fastapi/django build a target id
    as f"http:{method}:{path}" with no other differentiator, so two
    genuinely colliding routes get the *same* id — the second add() used to
    silently overwrite the first in the id-keyed dict, erasing all trace of
    the first registration before audit_routes ever ran."""
    registry = Registry()
    registry.add(Target(id="http:GET:/x", kind="http", name="view_a", method="GET", path="/x"))
    registry.add(Target(id="http:GET:/x", kind="http", name="view_b", method="GET", path="/x"))

    # the id-keyed lookup still only reaches one of them, by design —
    # that's the real, acknowledged "only one will ever handle a request"
    assert registry.get("http:GET:/x").name in {"view_a", "view_b"}

    findings = audit_routes(registry)
    assert len(findings) == 1
    assert "view_a" in findings[0].message
    assert "view_b" in findings[0].message


def test_audit_routes_ignores_service_targets():
    registry = Registry()
    registry.add(Target(id="service:a", kind="service", name="task_a", method="CALL", path=""))
    registry.add(Target(id="service:b", kind="service", name="task_b", method="CALL", path=""))
    assert audit_routes(registry) == []


def test_audit_routes_handles_none_registry():
    assert audit_routes(None) == []


def test_audit_code_combines_file_and_route_findings(tmp_path):
    path = _write(tmp_path, "sample.py", "def BadName():\n    pass\n")
    registry = Registry()
    registry.add(Target(id="http:GET:/x:a", kind="http", name="view_a", method="GET", path="/x"))
    registry.add(Target(id="http:GET:/x:b", kind="http", name="view_b", method="GET", path="/x"))

    findings = audit_code(paths=[path], registry=registry)
    kinds = _kinds(findings)
    assert "function_naming" in kinds
    assert "route_collision" in kinds
