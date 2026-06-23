# Nooby Scanner v2

One tool that **fuses** the web-service scanner and the VNC scanner, and adds
**RDP/SSH** port checks, **crash-safe resume**, **scan history**, a **global
recap**, and a self-contained **HTML report** — all behind an easy interactive
menu (or a scriptable CLI).

> ⚠ **Authorized testing only.** Run this against systems you own or are
> explicitly permitted to test.

Approach is unchanged from the originals: **fingerprint first, targeted auth
second** — no brute force. Web/VNC services that expose default credentials are
flagged; RDP/SSH are *port + security-layer* checks only (no auth attempts).

## What it scans

| Probe | What it does |
|---|---|
| `iLO`, `InfoPrint`, `XPort`, `SATO`, `Zebra`, `ThousandEyes`, `CiscoVoIP`, `PATLITE`, `Crestron`, `Schneider` | Detect the embedded web UI and test vendor-default credentials (`--check-auth`) |
| `VNC` | RFB handshake → detect, identify security (`none`/`vncauth`), test passwords |
| `RDP` | Is 3389 open? Negotiates X.224 to report the security layer (NLA/TLS/RDP) |
| `SSH` | Is 22 open? Reads the SSH banner to confirm + identify the server |

Groups for `--probes`: `all` (default), `web`, `extra` (VNC+RDP+SSH), or any
comma list of names (`ilo,sato,vnc`).

## Install

```powershell
pip install -r requirements.txt

# Copy the credential examples to real files (vendor defaults, not secrets)
foreach ($f in Get-ChildItem data\*.creds.example.json) {
    Copy-Item $f.FullName ($f.FullName -replace '\.example\.json$','.json')
}
```

`creds/vnc.txt` holds the VNC passwords to try (one per line).

## Easiest way — the menu

```powershell
python nooby.py
```

You get a menu: **new scan** (a guided wizard asks for the targets file, which
probes, whether to test creds, ports, workers), **scan history**, **resume**,
and **open/regenerate a report**. If a previous scan was interrupted, it offers
to resume it on startup.

## CLI

```powershell
# Full scan, test default creds, all probes
python nooby.py scan targets.txt --check-auth

# Only VNC + RDP + SSH, extra VNC ports
python nooby.py scan targets.txt --probes vnc,rdp,ssh --vnc-ports 5900-5905 --check-auth

# Pick services
python nooby.py scan targets.txt --probes ilo,sato,vnc --check-auth

python nooby.py history                 # list past scans
python nooby.py resume <runid>          # resume an interrupted scan
python nooby.py resume --last           # resume the most recent unfinished scan
python nooby.py report <runid>          # regenerate + open the HTML report
```

### `scan` options

| Flag | Default | Effect |
|---|---|---|
| `--probes` | `all` | Probes/group to run |
| `--check-auth` | off | Test default creds / VNC passwords when a service is found |
| `--workers` | 30 | Parallel workers |
| `--timeout` | 6.0 | Per-connection timeout (s) — applies to VNC/RDP/SSH |
| `--vnc-ports` / `--rdp-ports` / `--ssh-ports` | 5900 / 3389 / 22 | Ports to probe |
| `--vnc-creds` | `creds/vnc.txt` | VNC password list |
| `--vnc-pass` | — | Inline VNC password (repeatable; overrides the file) |

## Targets format

```
10.0.0.5                    # single IP
10.0.0.0/24                 # CIDR
10.0.0.1-50                 # short range (same /24)
10.0.0.1-10.0.1.50          # full range
```

## Output (everything lands in `results/`)

- **`<runid>.csv`** — every finding, flushed per hit (interrupt-safe).
- **`<runid>.html`** — self-contained, **Michelin-blue themed** report: summary
  cards, per-service global recap, and a searchable/sortable findings table
  colour-coded by severity. Opens automatically when a scan finishes.

  **Branding / mascot.** The report header shows a mascot. By default it uses
  the bundled original SVG (`core/assets/mascot.svg`, drawn in the Michelin
  palette — *not* the trademarked artwork). To use the **official Bibendum**,
  drop the brand asset from Michelin's internal library into `core/assets/` as
  `bibendum.png` (or `.svg` / `.jpg` / `.webp`) — the report embeds it
  automatically, no code change needed. The image is base64-embedded so the
  report stays a single offline file.
- **`<runid>.meta.json` / `<runid>.done`** — checkpoint state used for resume.
- **`history.json`** — the scan history index.

## Resume & auto-continue

Every completed job is appended to `<runid>.done` and flushed immediately, so a
`Ctrl+C` or a power loss leaves a valid checkpoint. On the next launch the tool
offers to resume; `resume` re-runs only the jobs that hadn't finished and keeps
the earlier hits in the same CSV/report. If the scan **crashes** mid-run it
auto-continues from the checkpoint (a few retries) without losing progress.

## The VNC reliability fix

The old VNC scanner would detect a host on the first run and then report it as
*down* on the next. Cause: it opened a throwaway connection to fingerprint the
host, abandoned it mid-handshake, then opened more connections per password —
which trips VNC servers' "too many security failures" throttle and leaves
half-open sessions reserved. The fused VNC probe now:

- uses **one** connection for detection *and* the first password,
- **`shutdown()`s every socket** so the server frees the session immediately
  (the "session not deconnected" the symptom pointed at),
- **retries connects** with a short back-off so a host briefly cooling down
  isn't misreported as down,
- adds a small cooldown between per-password reconnects.

Verified detecting reliably across repeated back-to-back scans.

## Project layout

```
nooby.py                 # entry point: interactive menu + CLI + orchestration
core/
├── result.py            # the one ScanResult shape every probe emits
├── targets.py           # IP/CIDR/range + port expansion
├── runner.py            # parallel engine + checkpoint-aware job filtering
├── report.py            # live output, CSV, summary, global recap
├── htmlreport.py        # self-contained HTML report generator
├── checkpoint.py        # crash-safe resume state
├── history.py           # scan history index
├── registry.py          # builds the probe set from a selection
├── services/            # the 10 HTTP web-service probes (+ base.py)
└── probes/              # vnc.py (fixed), rdp.py, ssh.py
data/                    # <service>.creds.json (gitignored) + .example.json
creds/vnc.txt            # VNC password list (gitignored)
results/                 # CSV / HTML / checkpoints / history
```

## Adding a web service

Same as before: drop `core/services/<name>.py` with a `Service` subclass
(declare `name`, `creds_filename`, `patterns`, `config_path`, optionally
override `try_login`), add `data/<name>.creds.example.json`, and register the
class in `core/services/__init__.py` (`WEB_SERVICES`). It's then available via
`--probes <name>` and included in `all`.
