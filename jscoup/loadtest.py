# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Concurrent traffic generation across multiple independent services.

Stdlib only (``concurrent.futures.ThreadPoolExecutor`` + ``urllib.request``),
so this adds no dependency and works against any HTTP service,
JSCoup-instrumented or not.
"""

from __future__ import annotations

import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from itertools import cycle
from typing import Any, Dict, List, Optional, TypedDict


class Target(TypedDict, total=False):
    base_url: str
    path: str
    method: str
    label: str  # defaults to base_url if omitted — what the summary groups by


@dataclass
class TargetStats:
    label: str
    requests: int = 0
    errors: int = 0
    latencies_ms: List[float] = field(default_factory=list)

    def record(self, latency_ms: float, ok: bool) -> None:
        self.requests += 1
        if not ok:
            self.errors += 1
        self.latencies_ms.append(latency_ms)

    def percentile(self, pct: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(int(len(ordered) * pct), len(ordered) - 1)
        return ordered[index]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "requests": self.requests,
            "errors": self.errors,
            "error_rate": round(self.errors / self.requests, 4) if self.requests else 0.0,
            "p50_ms": round(self.percentile(0.50), 1),
            "p95_ms": round(self.percentile(0.95), 1),
            "max_ms": round(max(self.latencies_ms), 1) if self.latencies_ms else 0.0,
        }


def _call_once(target: Target, timeout: float) -> "tuple[float, bool]":
    url = target["base_url"].rstrip("/") + "/" + target.get("path", "").lstrip("/")
    method = target.get("method", "GET").upper()
    request = urllib.request.Request(url, method=method, headers={"Accept": "application/json"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            ok = 200 <= response.status < 400
    except urllib.error.HTTPError as exc:
        ok = 200 <= exc.code < 400
    except Exception:
        ok = False
    return (time.perf_counter() - started) * 1000, ok


def run_load_test(
    targets: List[Target],
    concurrency: int = 10,
    duration_seconds: float = 30.0,
    request_timeout: float = 10.0,
) -> Dict[str, Any]:
    """Round-robins every target in ``targets`` across ``concurrency``
    worker threads for ``duration_seconds``, recording per-target latency
    and error rate. ``targets`` may span any number of independent
    services — this is the "many servers, many services" traffic test, not
    a single-target benchmark.

    Returns a plain dict — see :func:`format_report` for a printable table.
    """
    if not targets:
        raise ValueError("run_load_test needs at least one target")

    stats: Dict[str, TargetStats] = {
        (t.get("label") or t["base_url"]): TargetStats(label=t.get("label") or t["base_url"])
        for t in targets
    }
    target_cycle = cycle(targets)
    deadline = time.monotonic() + duration_seconds

    def worker() -> None:
        while time.monotonic() < deadline:
            target = next(target_cycle)
            latency_ms, ok = _call_once(target, request_timeout)
            stats[target.get("label") or target["base_url"]].record(latency_ms, ok)

    started_at = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(concurrency)]
        for f in futures:
            f.result()

    total_requests = sum(s.requests for s in stats.values())
    total_errors = sum(s.errors for s in stats.values())
    return {
        "started_at": started_at,
        "duration_seconds": duration_seconds,
        "concurrency": concurrency,
        "total_requests": total_requests,
        "total_errors": total_errors,
        "requests_per_second": round(total_requests / duration_seconds, 1) if duration_seconds else 0.0,
        "targets": [s.to_dict() for s in stats.values()],
    }


def format_report(result: Dict[str, Any]) -> str:
    """A plain-text summary table, e.g. for a CLI or a log line."""
    lines = [
        f"{result['total_requests']} requests over {result['duration_seconds']:.0f}s "
        f"({result['requests_per_second']}/s, {result['concurrency']} workers) "
        f"— {result['total_errors']} errors",
        "",
        f"{'target':<40} {'reqs':>7} {'errs':>6} {'p50 ms':>8} {'p95 ms':>8} {'max ms':>8}",
    ]
    for t in result["targets"]:
        lines.append(
            f"{t['label']:<40} {t['requests']:>7} {t['errors']:>6} "
            f"{t['p50_ms']:>8} {t['p95_ms']:>8} {t['max_ms']:>8}"
        )
    return "\n".join(lines)


def _main() -> None:  # pragma: no cover - CLI entry point
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="JSON file: a list of {base_url, path, method, label} objects")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--duration", type=float, default=30.0)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as handle:
        targets: List[Target] = json.load(handle)

    result = run_load_test(targets, concurrency=args.concurrency, duration_seconds=args.duration)
    print(format_report(result))


if __name__ == "__main__":  # pragma: no cover
    _main()
