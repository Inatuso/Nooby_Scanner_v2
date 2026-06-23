"""Live reporting for the fused scanner.

Streams every finding to a CSV (flushed per hit, append-on-resume so an
interrupted run keeps its earlier hits), prints live notifications tailored to
each probe kind, and produces both a per-run summary and a "global recap"
(optimised, per-service / per-severity rollup) at the end.
"""

from __future__ import annotations

import csv
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from .result import ScanResult

CSV_FIELDS = [
    "timestamp", "ip", "port", "service", "detected", "url",
    "proto", "security", "auth", "username", "password", "error", "info",
]


class ScanReport:
    def __init__(self, out_path: Path, total: int, console: Console,
                 *, check_auth: bool, resume: bool = False, progress_every: int = 2000):
        self.out_path = out_path
        self.total = total
        self.console = console
        self.check_auth = check_auth
        self.progress_every = max(1, progress_every)
        self.start = time.monotonic()

        # counters
        self.scanned = 0
        self.detected = 0
        self.auth_success = 0
        self.auth_failed = 0
        self.errors = 0
        self.clean = 0
        self.critical = 0

        # per-service rollup for the global recap: name -> {detected, auth, critical}
        self.by_service: dict[str, dict] = defaultdict(
            lambda: {"detected": 0, "auth": 0, "critical": 0})
        # detected results kept for the end-of-run table (current session only)
        self.findings: list[ScanResult] = []

        out_path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not (resume and out_path.exists())
        self._fh = open(out_path, "a" if not new_file else "w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_FIELDS)
        if new_file:
            self._writer.writeheader()
            self._fh.flush()

    # -- per-result ---------------------------------------------------------

    def record(self, r: ScanResult) -> None:
        self.scanned += 1

        if r.error and not r.detected:
            self.errors += 1
        elif r.detected:
            self.detected += 1
            self.findings.append(r)
            svc = self.by_service[r.service]
            svc["detected"] += 1
            if r.auth_success:
                self.auth_success += 1
                svc["auth"] += 1
            elif self.check_auth and r.security == "vncauth" and not r.error:
                self.auth_failed += 1
            elif self.check_auth and r.service in _WEB_AUTH_SERVICES and not r.error:
                self.auth_failed += 1
            if r.severity == "critical":
                self.critical += 1
                svc["critical"] += 1
            self._write_hit(r)
            self._notify(r)
        else:
            self.clean += 1

        if self.scanned % self.progress_every == 0:
            self._print_progress()

    def _auth_label(self, r: ScanResult) -> str:
        if not r.auth_applicable:
            return "n/a"
        if r.auth_success:
            return "SUCCESS"
        if r.security == "none":
            return "OPEN"
        if self.check_auth and r.detected:
            return "failed"
        return ""

    def _write_hit(self, r: ScanResult) -> None:
        user = r.winner[0] if r.winner else ""
        pwd = (r.winner[1] if r.winner else "") or ""
        self._writer.writerow({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "ip": r.ip,
            "port": r.port if r.port is not None else "",
            "service": r.service,
            "detected": "yes" if r.detected else "no",
            "url": r.url or "",
            "proto": r.proto or "",
            "security": r.security or "",
            "auth": self._auth_label(r),
            "username": user,
            "password": pwd,
            "error": r.error or "",
            "info": r.info or "",
        })
        self._fh.flush()

    def _notify(self, r: ScanResult) -> None:
        tag = r.service
        loc = r.url or f"{r.ip}:{r.port}" if r.port else r.ip
        if r.auth_success and r.winner:
            cred = r.winner[1] or "<empty>"
            who = f"{r.winner[0]}:" if r.winner[0] and r.winner[0] != "password" else ""
            self.console.print(
                f"[bold red]CRACKED[/bold red] [magenta]{tag}[/magenta] "
                f"[blue]{loc}[/blue] [dim]({r.proto or ''})[/dim] → [bold]{who}{cred}[/bold]"
            )
        elif r.security in ("none", "open"):
            self.console.print(
                f"[bold red]OPEN[/bold red]    [magenta]{tag}[/magenta] "
                f"[blue]{loc}[/blue] [dim](no authentication!)[/dim]"
            )
        else:
            extra = f" [dim]({r.security or r.proto or 'detected'})[/dim]"
            self.console.print(
                f"[green]FOUND[/green]   [magenta]{tag}[/magenta] [blue]{loc}[/blue]{extra}"
            )

    def _print_progress(self) -> None:
        pct = (self.scanned / self.total * 100) if self.total else 0.0
        elapsed = time.monotonic() - self.start
        rate = self.scanned / elapsed if elapsed else 0.0
        self.console.print(
            f"[dim]  …{self.scanned}/{self.total} ({pct:4.1f}%)  "
            f"found={self.detected} cracked/open={self.critical} "
            f"errors={self.errors}  {rate:.0f}/s[/dim]"
        )

    # -- finalize -----------------------------------------------------------

    def close(self) -> None:
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass

    def stats(self) -> dict:
        elapsed = time.monotonic() - self.start
        return {
            "scanned": self.scanned,
            "total": self.total,
            "detected": self.detected,
            "auth_success": self.auth_success,
            "auth_failed": self.auth_failed,
            "errors": self.errors,
            "clean": self.clean,
            "critical": self.critical,
            "elapsed": round(elapsed, 1),
            "rate": round(self.scanned / elapsed, 1) if elapsed else 0.0,
            "by_service": {k: dict(v) for k, v in self.by_service.items()},
        }

    def summary(self) -> Table:
        elapsed = time.monotonic() - self.start
        rate = self.scanned / elapsed if elapsed else 0.0

        t = Table(title="Scan Summary", box=box.ROUNDED, show_header=False, title_style="bold")
        t.add_column("metric", style="bold")
        t.add_column("value", justify="right")
        t.add_row("Scanned", f"{self.scanned}/{self.total}")
        t.add_row("Found (detected)", f"[green]{self.detected}[/green]")
        t.add_row("Cracked / open", f"[bold red]{self.critical}[/bold red]")
        if self.check_auth:
            t.add_row("Auth success", f"[bold red]{self.auth_success}[/bold red]")
            t.add_row("Auth failed", f"[yellow]{self.auth_failed}[/yellow]")
        t.add_row("No detection", f"[dim]{self.clean}[/dim]")
        t.add_row("Errors / unreachable", f"[red]{self.errors}[/red]")
        t.add_row("Elapsed", f"{elapsed:.0f}s ({rate:.0f}/s)")
        t.add_row("Hits CSV", f"[blue]{self.out_path}[/blue]")
        return t

    def global_recap(self) -> Table:
        """Optimised per-service rollup — the 'recap global' view."""
        t = Table(title="Global Recap (per service)", box=box.ROUNDED,
                  show_lines=False, title_style="bold")
        t.add_column("Service", style="magenta")
        t.add_column("Found", justify="right", style="green")
        t.add_column("Cracked/Open", justify="right", style="bold red")
        if self.check_auth:
            t.add_column("Auth OK", justify="right", style="red")
        for name in sorted(self.by_service, key=lambda n: -self.by_service[n]["detected"]):
            row = self.by_service[name]
            cells = [name, str(row["detected"]), str(row["critical"])]
            if self.check_auth:
                cells.append(str(row["auth"]))
            t.add_row(*cells)
        if not self.by_service:
            t.add_row("[dim]nothing detected[/dim]", "0", "0", *(["0"] if self.check_auth else []))
        return t


# Web services that perform a credential test (everything except CiscoVoIP).
_WEB_AUTH_SERVICES = {
    "iLO", "InfoPrint", "XPort", "SATO", "Zebra",
    "ThousandEyes", "PATLITE", "Crestron", "Schneider",
}
