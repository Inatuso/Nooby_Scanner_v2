"""Unified parallel scan engine for every probe kind, with checkpoint support.

A job is (probe, ip, port). Web probes contribute one job per host (port=None,
they try 443/80 themselves); VNC/RDP/SSH contribute one job per (host, port).
Each job has a stable key so an interrupted run can skip what's already done.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from .checkpoint import Checkpoint
from .result import ScanResult


def job_key(probe_name: str, ip: str, port: int | None) -> str:
    return f"{probe_name}|{ip}|{port if port is not None else '-'}"


def build_jobs(probes: list, targets: list[str]) -> list[tuple]:
    """All (probe, ip, port, key) tuples for this run (before checkpoint filtering)."""
    jobs: list[tuple] = []
    for ip in targets:
        for probe in probes:
            for port in probe.target_ports():
                jobs.append((probe, ip, port, job_key(probe.name, ip, port)))
    return jobs


def run_scans(
    probes: list,
    targets: list[str],
    *,
    check_auth: bool = False,
    workers: int = 30,
    checkpoint: Optional[Checkpoint] = None,
    on_result: Optional[Callable[[ScanResult], None]] = None,
) -> list[ScanResult]:
    """Run every pending job in parallel. Completed jobs are marked in the
    checkpoint (if given) and streamed to ``on_result`` for live reporting."""
    all_jobs = build_jobs(probes, targets)
    pending = [j for j in all_jobs if not (checkpoint and checkpoint.is_done(j[3]))]
    if not pending:
        return []

    workers = max(1, min(workers, len(pending)))
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe.scan, ip, port, check_auth): (probe, ip, port, key)
            for (probe, ip, port, key) in pending
        }
        for future in as_completed(futures):
            probe, ip, port, key = futures[future]
            try:
                r = future.result()
            except Exception as exc:                       # never let one host kill the run
                r = ScanResult(ip=ip, service=probe.name, port=port,
                               error=f"{type(exc).__name__}: {exc}")
            r.key = key
            results.append(r)
            if checkpoint is not None:
                checkpoint.mark(key)
            if on_result is not None:
                on_result(r)

    return results


def total_jobs(probes: list, targets: list[str]) -> int:
    return sum(len(probe.target_ports()) for probe in probes) * len(targets)
