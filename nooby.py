#!/usr/bin/env python3
"""Nooby Scanner v2 — one tool that fuses the web-service scanner and the VNC
scanner, adds RDP/SSH port checks, crash-safe resume, scan history, and an HTML
report.

Run with NO arguments for the interactive menu (easiest):

    python nooby.py

Or drive it from the CLI:

    python nooby.py scan targets.txt --check-auth --probes all
    python nooby.py scan targets.txt --probes vnc,rdp,ssh --vnc-ports 5900-5905
    python nooby.py history
    python nooby.py resume <runid>          # or:  --resume-last
    python nooby.py report <runid>          # regenerate + open the HTML
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

# Windows consoles default to cp1252 and choke on the box-drawing / symbol
# characters Rich emits. Force UTF-8 so output is identical everywhere.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from core import __version__, htmlreport, runner, targets as targets_mod
from core.checkpoint import Checkpoint
from core.history import History, STATUS_DONE, STATUS_INTERRUPTED
from core.registry import ALL_NAMES, WEB_NAMES, build_probes, resolve_selection

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"
DEFAULT_VNC_CREDS = ROOT / "creds" / "vnc.txt"

console = Console()


# ---------------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------------- #
def banner() -> None:
    console.print(Panel.fit(
        "[bold white on rgb(39,80,155)] MICHELIN [/]  "
        "[bold rgb(39,80,155)]Network Security Scanner[/]  "
        f"[dim]v{__version__}[/dim]\n"
        "[rgb(39,80,155)]web services · VNC · RDP · SSH[/]  "
        "[dim]— detect, test default creds, report[/dim]",
        border_style="rgb(39,80,155)", box=box.HEAVY,
    ))
    console.print("[dim]Authorized testing only.[/dim]\n")


def load_vnc_passwords(creds_path: Path, inline: list[str] | None) -> list[str]:
    if inline:
        return inline
    if not creds_path.exists():
        return []
    out: list[str] = []
    for line in creds_path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            out.append(line.rstrip("\n"))
    return out


def new_runid() -> str:
    return f"scan_{datetime.now():%Y%m%d_%H%M%S}"


def open_in_browser(path: Path) -> None:
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception:
        pass


# ---------------------------------------------------------------------------- #
# Core orchestration — shared by CLI, menu and resume
# ---------------------------------------------------------------------------- #
def execute_run(cfg: dict, *, resume: bool = False, auto_retry: int = 3) -> None:
    """Run (or resume) a scan described by ``cfg`` and produce the HTML report.

    On an unexpected crash mid-run the scan auto-continues from the checkpoint
    (up to ``auto_retry`` times). Ctrl+C stops cleanly and leaves the run
    resumable later.
    """
    from core.report import ScanReport          # local import keeps startup snappy

    targets = targets_mod.load(cfg["targets_file"])
    if not targets:
        console.print(f"[red]No valid targets in {cfg['targets_file']}.[/red]")
        return

    probes = build_probes(
        cfg["probes"], data_dir=DATA_DIR,
        vnc_passwords=cfg.get("vnc_passwords"), vnc_ports=cfg.get("vnc_ports"),
        rdp_ports=cfg.get("rdp_ports"), ssh_ports=cfg.get("ssh_ports"),
        timeout=cfg.get("timeout", 6.0),
    )
    if not probes:
        console.print("[red]No probes selected.[/red]")
        return

    runid = cfg["runid"]
    total = runner.total_jobs(probes, targets)
    csv_path = RESULTS_DIR / f"{runid}.csv"
    html_path = RESULTS_DIR / f"{runid}.html"

    history = History(RESULTS_DIR)
    checkpoint = Checkpoint(RESULTS_DIR, runid, resume=resume)

    meta = {
        "runid": runid,
        "targets_file": str(cfg["targets_file"]),
        "targets_count": len(targets),
        "probes": cfg["probes"],
        "check_auth": cfg["check_auth"],
        "workers": cfg["workers"],
        "timeout": cfg.get("timeout", 6.0),
        "vnc_ports": cfg.get("vnc_ports"),
        "rdp_ports": cfg.get("rdp_ports"),
        "ssh_ports": cfg.get("ssh_ports"),
        "vnc_passwords": cfg.get("vnc_passwords") or [],
        "csv": str(csv_path),
        "html": str(html_path),
        "total": total,
        "status": "running",
    }
    checkpoint.save_meta(meta)
    if resume:
        history.update(runid, status="running")
    else:
        history.start(runid, meta)

    done_before = len(checkpoint.done)
    remaining = total - done_before
    console.print(
        f"[bold]{len(targets)} target(s) × {len(probes)} probe(s) = {total} job(s)[/bold]"
        + (f"  [yellow](resuming — {done_before} already done, {remaining} left)[/yellow]"
           if resume and done_before else "")
        + f"  with {cfg['workers']} worker(s)\n"
    )

    report = ScanReport(csv_path, total, console, check_auth=cfg["check_auth"], resume=resume)
    # account for jobs completed in a previous session
    report.scanned = done_before

    status = STATUS_DONE
    attempt = 0
    try:
        while True:
            try:
                runner.run_scans(
                    probes, targets, check_auth=cfg["check_auth"],
                    workers=cfg["workers"], checkpoint=checkpoint,
                    on_result=report.record,
                )
                break                                    # finished cleanly
            except KeyboardInterrupt:
                status = STATUS_INTERRUPTED
                console.print("\n[yellow]Interrupted — progress saved. "
                              "Re-run and choose resume to continue.[/yellow]")
                break
            except Exception as exc:                      # unexpected — auto-continue
                attempt += 1
                if attempt > auto_retry:
                    status = STATUS_INTERRUPTED
                    console.print(f"\n[red]Run failed after {auto_retry} retries: {exc}[/red]")
                    break
                console.print(f"\n[yellow]Crash ({exc!r}) — auto-continuing from checkpoint "
                              f"(retry {attempt}/{auto_retry})…[/yellow]")
                time.sleep(2)
    finally:
        report.close()
        checkpoint.close()

    stats = report.stats()
    history.finish(runid, status,
                   scanned=stats["scanned"], detected=stats["detected"],
                   critical=stats["critical"], errors=stats["errors"])
    meta["status"] = status

    console.print()
    console.print(report.summary())
    console.print()
    console.print(report.global_recap())

    html_path = htmlreport.generate(csv_path, html_path, meta, stats)
    console.print(f"\n[green]HTML report:[/green] [blue]{html_path}[/blue]")
    open_in_browser(html_path)


# ---------------------------------------------------------------------------- #
# Resume / report / history commands
# ---------------------------------------------------------------------------- #
def cfg_from_meta(meta: dict) -> dict:
    return {
        "runid": meta["runid"],
        "targets_file": meta["targets_file"],
        "probes": meta["probes"],
        "check_auth": meta.get("check_auth", False),
        "workers": meta.get("workers", 30),
        "timeout": meta.get("timeout", 6.0),
        "vnc_ports": meta.get("vnc_ports"),
        "rdp_ports": meta.get("rdp_ports"),
        "ssh_ports": meta.get("ssh_ports"),
        "vnc_passwords": meta.get("vnc_passwords") or [],
    }


def do_resume(runid: str) -> None:
    meta = Checkpoint.meta_for(RESULTS_DIR, runid)
    if not meta:
        console.print(f"[red]No saved state for run {runid!r}.[/red]")
        return
    console.print(f"[cyan]Resuming {runid}…[/cyan]")
    execute_run(cfg_from_meta(meta), resume=True)


def do_report(runid: str) -> None:
    meta = Checkpoint.meta_for(RESULTS_DIR, runid) or History(RESULTS_DIR).get(runid)
    if not meta:
        console.print(f"[red]Unknown run {runid!r}.[/red]")
        return
    csv_path = RESULTS_DIR / f"{runid}.csv"
    html_path = RESULTS_DIR / f"{runid}.html"
    rec = History(RESULTS_DIR).get(runid) or {}
    stats = {
        "scanned": rec.get("scanned", 0), "total": meta.get("total", 0),
        "detected": rec.get("detected", 0), "critical": rec.get("critical", 0),
        "errors": rec.get("errors", 0), "elapsed": rec.get("elapsed", 0),
        "rate": rec.get("rate", 0), "by_service": {},
    }
    html_path = htmlreport.generate(csv_path, html_path, meta, stats)
    console.print(f"[green]Report:[/green] [blue]{html_path}[/blue]")
    open_in_browser(html_path)


def show_history() -> list[dict]:
    runs = History(RESULTS_DIR).all()
    if not runs:
        console.print("[dim]No scans recorded yet.[/dim]")
        return runs
    t = Table(title="Scan History", box=box.ROUNDED, show_lines=False)
    t.add_column("#", style="dim", justify="right")
    t.add_column("Run ID", style="cyan")
    t.add_column("Started")
    t.add_column("Status")
    t.add_column("Targets", justify="right")
    t.add_column("Found", justify="right", style="green")
    t.add_column("Crit", justify="right", style="bold red")
    for i, r in enumerate(runs, 1):
        st = r.get("status", "")
        st_col = {"completed": "[green]completed[/green]",
                  "running": "[yellow]running[/yellow]",
                  "interrupted": "[red]interrupted[/red]"}.get(st, st)
        t.add_row(str(i), r.get("runid", ""), r.get("started", ""), st_col,
                  str(r.get("targets_count", "")), str(r.get("detected", "")),
                  str(r.get("critical", "")))
    console.print(t)
    return runs


# ---------------------------------------------------------------------------- #
# Interactive menu
# ---------------------------------------------------------------------------- #
def wizard_new_scan() -> dict | None:
    tf = Prompt.ask("Targets file", default="targets.txt")
    tpath = Path(tf)
    if not tpath.is_absolute():
        tpath = ROOT / tf
    targets = targets_mod.load(tpath)
    if not targets:
        console.print(f"[red]No valid targets in {tpath}.[/red]")
        return None
    console.print(f"[dim]  {len(targets)} target(s) loaded.[/dim]")

    console.print("\n[bold]Probes[/bold] — available:")
    console.print(f"  [cyan]all[/cyan]  •  [cyan]web[/cyan] ({', '.join(WEB_NAMES)})")
    console.print("  [cyan]vnc[/cyan]  •  [cyan]rdp[/cyan]  •  [cyan]ssh[/cyan]")
    console.print("  [dim]or a custom list e.g. 'ilo,sato,vnc'[/dim]")
    spec = Prompt.ask("Select", default="all")
    try:
        probes = resolve_selection(spec)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return None
    console.print(f"[dim]  → {', '.join(probes)}[/dim]")

    check_auth = Confirm.ask("Test default credentials when a service is found?", default=True)
    workers = IntPrompt.ask("Parallel workers", default=30)

    vnc_ports = rdp_ports = ssh_ports = None
    vnc_passwords = None
    if "VNC" in probes:
        vp = Prompt.ask("VNC ports", default="5900")
        vnc_ports = targets_mod.parse_ports(vp) or [5900]
        if check_auth:
            vnc_passwords = load_vnc_passwords(DEFAULT_VNC_CREDS, None)
            console.print(f"[dim]  {len(vnc_passwords)} VNC password(s) from {DEFAULT_VNC_CREDS.name}[/dim]")
    if "RDP" in probes:
        rdp_ports = targets_mod.parse_ports(Prompt.ask("RDP ports", default="3389")) or [3389]
    if "SSH" in probes:
        ssh_ports = targets_mod.parse_ports(Prompt.ask("SSH ports", default="22")) or [22]

    return {
        "runid": new_runid(),
        "targets_file": str(tpath),
        "probes": probes,
        "check_auth": check_auth,
        "workers": workers,
        "timeout": 6.0,
        "vnc_ports": vnc_ports,
        "rdp_ports": rdp_ports,
        "ssh_ports": ssh_ports,
        "vnc_passwords": vnc_passwords,
    }


def menu() -> None:
    banner()

    # Offer to resume an unfinished run on entry.
    resumable = History(RESULTS_DIR).resumable()
    if resumable:
        last = resumable[0]
        console.print(f"[yellow]An unfinished scan was found:[/yellow] "
                      f"[cyan]{last['runid']}[/cyan] ({last.get('status')})")
        if Confirm.ask("Resume it now?", default=True):
            do_resume(last["runid"])
            return

    while True:
        console.print("\n[bold]Menu[/bold]")
        console.print("  [cyan]1[/cyan]) New scan")
        console.print("  [cyan]2[/cyan]) Scan history")
        console.print("  [cyan]3[/cyan]) Resume a scan")
        console.print("  [cyan]4[/cyan]) Open / regenerate a report")
        console.print("  [cyan]5[/cyan]) Quit")
        choice = Prompt.ask("Choose", choices=["1", "2", "3", "4", "5"], default="1")

        if choice == "1":
            cfg = wizard_new_scan()
            if cfg:
                execute_run(cfg)
        elif choice == "2":
            show_history()
        elif choice == "3":
            runs = show_history()
            if runs:
                rid = Prompt.ask("Run ID to resume (blank to cancel)", default="")
                if rid:
                    do_resume(rid)
        elif choice == "4":
            runs = show_history()
            if runs:
                rid = Prompt.ask("Run ID to open (blank to cancel)", default="")
                if rid:
                    do_report(rid)
        else:
            console.print("[dim]Bye.[/dim]")
            return


# ---------------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nooby",
        description="Unified scanner: web services + VNC + RDP + SSH, with resume, "
                    "history and HTML report. Run with no arguments for the menu.",
    )
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Run a scan")
    s.add_argument("targets", help="Targets file — one IP / CIDR / range per line")
    s.add_argument("--probes", default="all",
                   help=f"Comma list or group. Names: {', '.join(ALL_NAMES)} | groups: all,web,extra")
    s.add_argument("--check-auth", action="store_true", help="Test default credentials when found")
    s.add_argument("--workers", type=int, default=30, help="Parallel workers (default 30)")
    s.add_argument("--timeout", type=float, default=6.0, help="Per-connection timeout (default 6s)")
    s.add_argument("--vnc-ports", default="5900", help="VNC ports (default 5900)")
    s.add_argument("--rdp-ports", default="3389", help="RDP ports (default 3389)")
    s.add_argument("--ssh-ports", default="22", help="SSH ports (default 22)")
    s.add_argument("--vnc-creds", default=str(DEFAULT_VNC_CREDS), help="VNC password list file")
    s.add_argument("--vnc-pass", dest="vnc_pass", action="append", default=[],
                   help="Inline VNC password (repeatable); overrides --vnc-creds")

    sub.add_parser("history", help="List past scans")

    r = sub.add_parser("resume", help="Resume an interrupted scan")
    r.add_argument("runid", nargs="?", help="Run ID (omit with --last)")
    r.add_argument("--last", action="store_true", help="Resume the most recent unfinished scan")

    rp = sub.add_parser("report", help="Regenerate and open a run's HTML report")
    rp.add_argument("runid")

    sub.add_parser("menu", help="Interactive menu (default when no command)")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd in (None, "menu"):
        try:
            menu()
        except KeyboardInterrupt:
            console.print("\n[dim]Bye.[/dim]")
        return

    if args.cmd == "history":
        show_history()
        return

    if args.cmd == "resume":
        if args.last or not args.runid:
            resumable = History(RESULTS_DIR).resumable()
            if not resumable:
                console.print("[dim]No unfinished scans to resume.[/dim]")
                return
            do_resume(resumable[0]["runid"])
        else:
            do_resume(args.runid)
        return

    if args.cmd == "report":
        do_report(args.runid)
        return

    if args.cmd == "scan":
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s  %(message)s")
        try:
            probes = resolve_selection(args.probes)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

        tpath = Path(args.targets)
        if not tpath.is_absolute():
            tpath = ROOT / args.targets

        vnc_passwords = None
        if "VNC" in probes and args.check_auth:
            vnc_passwords = load_vnc_passwords(Path(args.vnc_creds), args.vnc_pass)

        cfg = {
            "runid": new_runid(),
            "targets_file": str(tpath),
            "probes": probes,
            "check_auth": args.check_auth,
            "workers": args.workers,
            "timeout": args.timeout,
            "vnc_ports": targets_mod.parse_ports(args.vnc_ports) or [5900],
            "rdp_ports": targets_mod.parse_ports(args.rdp_ports) or [3389],
            "ssh_ports": targets_mod.parse_ports(args.ssh_ports) or [22],
            "vnc_passwords": vnc_passwords,
        }
        banner()
        execute_run(cfg)
        return


if __name__ == "__main__":
    main()
