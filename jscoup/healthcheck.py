# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Sweep every discovered API/function target and report pass/fail at once,
reusing the same :class:`~jscoup.simulator.Simulator` invocation path as a
manual "Run and capture" click. A target is only called if it needs no
required parameters (or ``include_params=True`` is passed); otherwise it is
reported as skipped rather than called with invented data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ApiCheckResult:
    target_id: str
    kind: str
    method: str
    path: str
    ok: Optional[bool]  # None means "skipped", not attempted at all
    status_code: Optional[int] = None
    duration_ms: Optional[float] = None
    response_preview: Optional[str] = None
    skipped_reason: Optional[str] = None
    diagnosis: Optional[Dict[str, Any]] = None
    event_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "kind": self.kind,
            "method": self.method,
            "path": self.path,
            "ok": self.ok,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "response_preview": self.response_preview,
            "skipped_reason": self.skipped_reason,
            "diagnosis": self.diagnosis,
            "event_id": self.event_id,
        }


def _preview(value: Any, limit: int = 500) -> Optional[str]:
    if value is None:
        return None
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def check_apis(
    registry: Any,
    simulator: Any,
    storage: Any,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    include_params: bool = False,
) -> List[ApiCheckResult]:
    """Call every target in ``registry`` that needs no required parameters,
    with ``token`` applied to all of them, and report the outcome of each,
    including the full diagnosis for anything that failed.
    """
    results: List[ApiCheckResult] = []
    for target in registry.all():
        if target.kind != "http":
            # JSCoup only calls APIs over HTTP — it never runs functions itself.
            results.append(
                ApiCheckResult(
                    target_id=target.id,
                    kind=target.kind,
                    method=target.method,
                    path=target.path or target.name,
                    ok=None,
                    skipped_reason="not an HTTP API",
                )
            )
            continue
        if not target.healthcheck_allowed:
            # Only a target explicitly opted in via healthcheck_allowed=True
            # is ever called here.
            results.append(
                ApiCheckResult(
                    target_id=target.id,
                    kind=target.kind,
                    method=target.method,
                    path=target.path or target.name,
                    ok=None,
                    skipped_reason="not marked healthcheck_allowed",
                )
            )
            continue
        required = [p for p in target.params if p.required]
        if required and not include_params:
            results.append(
                ApiCheckResult(
                    target_id=target.id,
                    kind=target.kind,
                    method=target.method,
                    path=target.path or target.name,
                    ok=None,
                    skipped_reason="needs parameter(s): " + ", ".join(p.name for p in required),
                )
            )
            continue
        try:
            outcome = simulator.invoke(target.id, params={}, token=token, base_url=base_url)
        except Exception as exc:  # one broken target must never abort the sweep
            results.append(
                ApiCheckResult(
                    target_id=target.id,
                    kind=target.kind,
                    method=target.method,
                    path=target.path or target.name,
                    ok=False,
                    response_preview=f"{type(exc).__name__}: {exc}",
                )
            )
            continue

        diagnosis = None
        event_id = outcome.get("event_id")
        if event_id:
            event = storage.get(event_id)
            if event is not None and event.diagnosis is not None:
                diagnosis = event.diagnosis.to_dict()

        response_value = outcome.get("response")
        if response_value is None:
            response_value = outcome.get("result", outcome.get("error"))

        results.append(
            ApiCheckResult(
                target_id=target.id,
                kind=target.kind,
                method=target.method,
                path=target.path or target.name,
                ok=bool(outcome.get("ok")),
                status_code=outcome.get("status_code"),
                duration_ms=outcome.get("duration_ms"),
                response_preview=_preview(response_value),
                diagnosis=diagnosis,
                event_id=event_id,
            )
        )
    return results
