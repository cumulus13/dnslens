"""Multi-resolver tools: propagation check, latency benchmark, wait-for-change."""
from __future__ import annotations

import secrets
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple

from .core import Answer, QueryOpts, Target, norm_value, query_target


def run_many(
    targets: Sequence[Target],
    qname: str,
    rdtype: str,
    opts: QueryOpts,
    rd: bool = True,
    max_workers: int = 16,
) -> List[Tuple[Target, Answer]]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(targets))) as ex:
        answers = list(ex.map(lambda t: query_target(t, qname, rdtype, opts, rd), targets))
    return list(zip(targets, answers))


def normalise_expected(rdtype: str, expected: Sequence[str]) -> FrozenSet[str]:
    return frozenset(norm_value(rdtype.upper(), e) for e in expected)


# --------------------------------------------------------------------------- #
# propagate
# --------------------------------------------------------------------------- #


@dataclass
class PropagationReport:
    qname: str
    rdtype: str
    results: List[Tuple[Target, Answer]]
    expected: Optional[FrozenSet[str]] = None
    strict: bool = False
    groups: Dict[FrozenSet[str], List[str]] = field(default_factory=dict)
    failed: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for t, a in self.results:
            if a.responded:
                self.groups.setdefault(a.values(), []).append(t.name)
            else:
                self.failed.append(t.name)

    @property
    def responders(self) -> int:
        return sum(len(v) for v in self.groups.values())

    @property
    def consistent(self) -> bool:
        return len(self.groups) == 1

    @property
    def matches_expected(self) -> Optional[bool]:
        if self.expected is None:
            return None
        return bool(self.groups) and all(g == self.expected for g in self.groups)

    @property
    def ok(self) -> bool:
        if self.responders == 0:
            return False
        if self.strict and self.failed:
            return False
        if self.expected is not None:
            return bool(self.matches_expected)
        return self.consistent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qname": self.qname,
            "type": self.rdtype,
            "ok": self.ok,
            "consistent": self.consistent,
            "expected": sorted(self.expected) if self.expected is not None else None,
            "unreachable": self.failed,
            "groups": [
                {"values": sorted(v), "resolvers": names} for v, names in self.groups.items()
            ],
            "results": [dict(a.to_dict(), resolver=t.name) for t, a in self.results],
        }


def propagate(
    targets: Sequence[Target],
    qname: str,
    rdtype: str,
    opts: QueryOpts,
    expected: Optional[Sequence[str]] = None,
    strict: bool = False,
) -> PropagationReport:
    exp = normalise_expected(rdtype, expected) if expected else None
    return PropagationReport(
        qname, rdtype.upper(), run_many(targets, qname, rdtype, opts), exp, strict
    )


# --------------------------------------------------------------------------- #
# bench
# --------------------------------------------------------------------------- #


@dataclass
class BenchResult:
    target: Target
    sent: int
    answered: int
    times: List[float]
    first_error: Optional[str] = None

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - self.answered) / self.sent if self.sent else 100.0

    def _stat(self, fn: Callable[[List[float]], float]) -> Optional[float]:
        return fn(self.times) if self.times else None

    @property
    def stats(self) -> Dict[str, Optional[float]]:
        def p95(v: List[float]) -> float:
            s = sorted(v)
            return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]

        return {
            "min": self._stat(min),
            "avg": self._stat(statistics.fmean),
            "median": self._stat(statistics.median),
            "p95": self._stat(p95),
            "max": self._stat(max),
        }

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "resolver": self.target.name,
            "address": self.target.address,
            "sent": self.sent,
            "answered": self.answered,
            "loss_pct": round(self.loss_pct, 1),
            "error": self.first_error,
        }
        d.update({k: (round(v, 2) if v is not None else None) for k, v in self.stats.items()})
        return d


DEFAULT_BENCH_DOMAINS = ["example.com", "google.com", "cloudflare.com", "github.com", "wikipedia.org"]


def _bench_one(
    target: Target, domains: Sequence[str], count: int, opts: QueryOpts, uncached: bool
) -> BenchResult:
    times: List[float] = []
    first_err: Optional[str] = None
    for i in range(count):
        dom = domains[i % len(domains)]
        qname = f"{secrets.token_hex(5)}.{dom}" if uncached else dom
        a = query_target(target, qname, "A", opts)
        if a.responded:
            times.append(a.elapsed_ms)
        elif first_err is None:
            first_err = a.error or a.rcode
    return BenchResult(target, count, len(times), times, first_err)


def bench(
    targets: Sequence[Target],
    domains: Sequence[str],
    count: int,
    opts: QueryOpts,
    uncached: bool = False,
) -> List[BenchResult]:
    opts = replace(opts, retries=0)
    domains = list(domains) or DEFAULT_BENCH_DOMAINS
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(targets)))) as ex:
        results = list(ex.map(lambda t: _bench_one(t, domains, count, opts, uncached), targets))
    results.sort(key=lambda r: (r.stats["median"] is None, r.stats["median"] or 0.0))
    return results


# --------------------------------------------------------------------------- #
# wait
# --------------------------------------------------------------------------- #


def satisfied(
    results: Sequence[Tuple[Target, Answer]],
    expected: Optional[FrozenSet[str]],
    subset: bool,
    absent: bool,
) -> Tuple[int, int]:
    """Return (matching, total) resolvers."""
    good = 0
    for _, a in results:
        if not a.responded:
            continue
        vals = a.values()
        if absent:
            ok = not vals
        elif expected is None:
            ok = bool(vals)
        elif subset:
            ok = expected <= vals
        else:
            ok = vals == expected
        good += ok
    return good, len(results)


def wait(
    targets: Sequence[Target],
    qname: str,
    rdtype: str,
    opts: QueryOpts,
    expected: Optional[Sequence[str]] = None,
    subset: bool = False,
    absent: bool = False,
    interval: float = 5.0,
    max_wait: float = 300.0,
    progress: Optional[Callable[[float, int, int], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Tuple[bool, List[Tuple[Target, Answer]]]:
    exp = normalise_expected(rdtype, expected) if expected else None
    start = time.monotonic()
    while True:
        results = run_many(targets, qname, rdtype, opts)
        good, total = satisfied(results, exp, subset, absent)
        elapsed = time.monotonic() - start
        if progress:
            progress(elapsed, good, total)
        if good == total:
            return True, results
        if elapsed + interval > max_wait:
            return False, results
        sleep(interval)
