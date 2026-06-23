"""Persistent scan history — a small JSON index of every run.

Each run gets one record (keyed by runid). It is created when a scan starts and
updated as it progresses / finishes, so ``nooby history`` can list past scans
and ``nooby resume`` can find the ones that didn't complete.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

STATUS_RUNNING = "running"
STATUS_DONE = "completed"
STATUS_INTERRUPTED = "interrupted"


class History:
    def __init__(self, results_dir: Path):
        self.results_dir = results_dir
        self.path = results_dir / "history.json"
        results_dir.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save(self, runs: list[dict]) -> None:
        self.path.write_text(json.dumps(runs, indent=2), encoding="utf-8")

    # -- public API ---------------------------------------------------------

    def start(self, runid: str, meta: dict) -> None:
        runs = self._load()
        runs = [r for r in runs if r.get("runid") != runid]
        runs.append({
            "runid": runid,
            "status": STATUS_RUNNING,
            "started": datetime.now().isoformat(timespec="seconds"),
            "finished": None,
            **meta,
        })
        self._save(runs)

    def update(self, runid: str, **fields) -> None:
        runs = self._load()
        for r in runs:
            if r.get("runid") == runid:
                r.update(fields)
                break
        self._save(runs)

    def finish(self, runid: str, status: str, **fields) -> None:
        self.update(runid, status=status,
                    finished=datetime.now().isoformat(timespec="seconds"), **fields)

    def get(self, runid: str) -> dict | None:
        for r in self._load():
            if r.get("runid") == runid:
                return r
        return None

    def all(self) -> list[dict]:
        return sorted(self._load(), key=lambda r: r.get("started", ""), reverse=True)

    def resumable(self) -> list[dict]:
        return [r for r in self.all()
                if r.get("status") in (STATUS_RUNNING, STATUS_INTERRUPTED)]
