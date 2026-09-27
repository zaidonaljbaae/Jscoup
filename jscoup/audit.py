# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Static naming/style audit + route-collision check.

Unlike everything under :mod:`jscoup.analyzers`, this module never looks at a
captured runtime event; it reads source code with the stdlib ``ast`` module.
Findings are computed on demand (``JSCoup.audit_code(...)`` / the dashboard's
"Code Audit" action) and are not persisted.
"""

from __future__ import annotations

import ast
import builtins
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

_SKIP_DIRS = {
    ".venv", "venv", "env", "__pycache__", ".git", "site-packages",
    "node_modules", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
}

_SNAKE_CASE = re.compile(r"^[a-z_][a-z0-9_]*$")
_PASCAL_CASE = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
_AMBIGUOUS_NAMES = {"l", "O", "I"}  # PEP 8: visually confusable with 1 / 0 / l
_SKIP_PARAM_NAMES = {"self", "cls"}
_BUILTIN_NAMES = frozenset(dir(builtins))


@dataclass
class AuditFinding:
    file: str
    line: int
    kind: str
    name: str
    message: str
    suggestion: str
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "name": self.name,
            "message": self.message,
            "suggestion": self.suggestion,
            "severity": self.severity,
        }


# --------------------------------------------------------------------------- #
# file discovery
# --------------------------------------------------------------------------- #


def _iter_python_files(paths: List[str]):
    for path in paths:
        if os.path.isfile(path):
            if path.endswith(".py"):
                yield path
            continue
        for root, dirnames, filenames in os.walk(path):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for filename in filenames:
                if filename.endswith(".py"):
                    yield os.path.join(root, filename)


# --------------------------------------------------------------------------- #
# naming helpers (best-effort suggestions, not a formatter)
# --------------------------------------------------------------------------- #


def _to_snake_case(name: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name)
    return re.sub(r"_+", "_", snake).lower()


def _to_pascal_case(name: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[_\s]+", name) if part)


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #


def _mutable_default_findings(node: Any, file: str) -> List[AuditFinding]:
    findings: List[AuditFinding] = []
    positional = list(node.args.posonlyargs) + list(node.args.args)
    defaults = list(node.args.defaults)
    paired = list(zip(positional[len(positional) - len(defaults):], defaults))
    paired += [(a, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None]
    for arg, default in paired:
        if isinstance(default, (ast.List, ast.Dict, ast.Set)):
            kind_name = type(default).__name__.lower()
            findings.append(
                AuditFinding(
                    file=file,
                    line=getattr(default, "lineno", node.lineno),
                    kind="mutable_default_argument",
                    name=arg.arg,
                    message=f"Parameter '{arg.arg}' of {node.name}() defaults to a mutable {kind_name}.",
                    suggestion=f"Default to None and create the {kind_name} inside the function body — "
                    "a mutable default is created once and shared/mutated across every call.",
                    severity="warning",
                )
            )
    return findings


def _function_findings(node: Any, file: str) -> List[AuditFinding]:
    findings: List[AuditFinding] = []
    if not node.name.startswith("__") and not _SNAKE_CASE.match(node.name):
        findings.append(
            AuditFinding(
                file=file,
                line=node.lineno,
                kind="function_naming",
                name=node.name,
                message=f"Function '{node.name}' is not snake_case.",
                suggestion=f"Rename to '{_to_snake_case(node.name)}' to match PEP 8.",
                severity="info",
            )
        )

    params = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    if node.args.vararg:
        params.append(node.args.vararg)
    if node.args.kwarg:
        params.append(node.args.kwarg)

    for arg in params:
        name = arg.arg
        if name in _SKIP_PARAM_NAMES:
            continue
        if name in _AMBIGUOUS_NAMES:
            findings.append(
                AuditFinding(
                    file=file,
                    line=arg.lineno,
                    kind="ambiguous_parameter_name",
                    name=name,
                    message=f"Parameter '{name}' of {node.name}() is visually ambiguous (looks like 1/0/I).",
                    suggestion="Use a descriptive name — PEP 8 explicitly discourages 'l', 'O' and 'I'.",
                    severity="warning",
                )
            )
        elif not _SNAKE_CASE.match(name):
            findings.append(
                AuditFinding(
                    file=file,
                    line=arg.lineno,
                    kind="parameter_naming",
                    name=name,
                    message=f"Parameter '{name}' of {node.name}() is not snake_case.",
                    suggestion=f"Rename to '{_to_snake_case(name)}'.",
                    severity="info",
                )
            )
        if name in _BUILTIN_NAMES:
            findings.append(
                AuditFinding(
                    file=file,
                    line=arg.lineno,
                    kind="shadowed_builtin",
                    name=name,
                    message=f"Parameter '{name}' of {node.name}() shadows the builtin '{name}()'.",
                    suggestion=f"Rename it (e.g. '{name}_' or something more specific) if the builtin is "
                    "still needed inside this function.",
                    severity="info",
                )
            )

    findings.extend(_mutable_default_findings(node, file))
    return findings


def _class_findings(node: ast.ClassDef, file: str) -> List[AuditFinding]:
    if _PASCAL_CASE.match(node.name):
        return []
    return [
        AuditFinding(
            file=file,
            line=node.lineno,
            kind="class_naming",
            name=node.name,
            message=f"Class '{node.name}' is not PascalCase.",
            suggestion=f"Rename to '{_to_pascal_case(node.name)}' to match PEP 8.",
            severity="info",
        )
    ]


def _except_finding(node: ast.ExceptHandler, file: str) -> Optional[AuditFinding]:
    body_is_just_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
    if node.type is None:
        return AuditFinding(
            file=file,
            line=node.lineno,
            kind="bare_except",
            name="except",
            message="Bare 'except:' catches everything, including SystemExit/KeyboardInterrupt.",
            suggestion="Catch the specific exception type(s) you expect, or at least 'except Exception:'.",
            severity="warning",
        )
    if body_is_just_pass and isinstance(node.type, ast.Name) and node.type.id == "Exception":
        return AuditFinding(
            file=file,
            line=node.lineno,
            kind="silent_exception",
            name="except Exception",
            message="'except Exception: pass' silently discards every error with no trace.",
            suggestion="At minimum log the exception (e.g. logging.exception(...)) before continuing.",
            severity="warning",
        )
    return None


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #


def audit_paths(paths: List[str]) -> List[AuditFinding]:
    """Walk ``paths`` (files or directories) and apply the naming/style rules."""
    findings: List[AuditFinding] = []
    for file in _iter_python_files(paths):
        try:
            with open(file, "r", encoding="utf-8") as handle:
                source = handle.read()
            tree = ast.parse(source, filename=file)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue  # a file that can't be parsed is skipped, not fatal to the run
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(_function_findings(node, file))
            elif isinstance(node, ast.ClassDef):
                findings.extend(_class_findings(node, file))
            elif isinstance(node, ast.ExceptHandler):
                finding = _except_finding(node, file)
                if finding is not None:
                    findings.append(finding)
    return findings


def audit_routes(registry: Any) -> List[AuditFinding]:
    """Flag HTTP targets in ``registry`` that share the same (method, path).

    Reads ``registry.http_collisions()`` rather than grouping
    ``registry.all()`` itself, since ``all()`` only shows one Target per id
    and a collision would already be overwritten by the time it's iterated.
    """
    if registry is None or not hasattr(registry, "http_collisions"):
        return []
    findings: List[AuditFinding] = []
    for (method, path), targets in registry.http_collisions().items():
        if len(targets) > 1:
            names = ", ".join(sorted({t.name for t in targets}))
            findings.append(
                AuditFinding(
                    file="",
                    line=0,
                    kind="route_collision",
                    name=f"{method} {path}",
                    message=f"{len(targets)} handlers are registered for {method} {path}: {names}",
                    suggestion="Only one of these will ever actually handle a request — remove or merge the duplicates.",
                    severity="warning",
                )
            )
    return findings


def audit_code(paths: Optional[List[str]] = None, registry: Any = None) -> List[AuditFinding]:
    """Run the full audit: naming/style rules over ``paths`` plus route collisions."""
    findings = audit_paths(paths or [os.getcwd()])
    findings.extend(audit_routes(registry))
    return findings
