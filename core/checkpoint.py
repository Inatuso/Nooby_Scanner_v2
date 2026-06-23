"""Crash-safe checkpointing so an interrupted scan can resume where it stopped.

Design (deliberately dumb so it survives a hard kill):
  * ``<runid>.meta.json`` — the run config (targets file, probes, options …).
  * ``<runid>.done``      — append-only log, ONE completed job key per line,
                            flushed after every write.

To resume, we reload the meta, rebuild the full job list from the same config,
and skip any job whose key is already in the ``.done`` set. Because the done log
is append-only and flushed per job, a power-loss at any instant leaves a valid
(if shorter) file — at worst one job is re-run.
"""

from __future__ import annotations

import json
from pathlib import Path


class Checkpoint:
    def __init__(self, state_dir: Path, runid: str, resume: bool = False):
        self.runid = runid
        self.state_dir = state_dir
        self.meta_path = state_dir / f"{runid}.meta.json"
        self.done_path = state_dir / f"{runid}.done"
        state_dir.mkdir(parents=True, exist_ok=True)

        self.done: set[str] = set()
        if resume and self.done_path.exists():
            for line in self.done_path.read_text(encoding="utf-8").splitlines():
                key = line.strip()
                if key:
                    self.done.add(key)
        mode = "a" if resume else "w"
        self._fh = open(self.done_path, mode, encoding="utf-8")

    # -- meta ---------------------------------------------------------------

    def save_meta(self, meta: dict) -> None:
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def load_meta(self) -> dict:
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    # -- progress -----------------------------------------------------------

    def is_done(self, key: str) -> bool:
        return key in self.done

    def mark(self, key: str) -> None:
        self.done.add(key)
        self._fh.write(key + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    @staticmethod
    def meta_for(state_dir: Path, runid: str) -> dict | None:
        p = state_dir / f"{runid}.meta.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
