"""Generate a self-contained HTML report from a run's hit CSV.

Sober, report-style layout (not a dashboard mock-up): a title block, a summary
band with a severity bar, scan parameters, a per-service breakdown, and the
detailed findings table. Data and any logo are embedded, so the file is a single
offline document.

Logo:
  If a brand asset named ``logo.png`` / ``.svg`` / ``.jpg`` / ``.webp`` (or
  ``bibendum.*``) is placed in ``core/assets/``, it is embedded in the header.
  Otherwise the header is clean and text-only. Nothing is downloaded.
"""

from __future__ import annotations

import base64
import csv
import html
import json
from datetime import datetime
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"
_MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
         "svg": "image/svg+xml", "webp": "image/webp", "gif": "image/gif"}


def _severity(row: dict) -> str:
    auth = (row.get("auth") or "").upper()
    sec = (row.get("security") or "").lower()
    if auth == "SUCCESS" or sec in ("none", "open"):
        return "critical"
    if (row.get("detected") or "").lower() == "yes":
        return "detected"
    if row.get("error"):
        return "error"
    return "info"


def _read_rows(csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        return []
    rows: list[dict] = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            row["severity"] = _severity(row)
            rows.append(row)
    return rows


def _logo_data_uri() -> str:
    for name in ("logo.png", "logo.svg", "logo.webp", "logo.jpg",
                 "bibendum.png", "bibendum.svg", "bibendum.webp", "bibendum.jpg"):
        f = ASSETS / name
        if f.exists():
            ext = name.rsplit(".", 1)[-1].lower()
            b64 = base64.b64encode(f.read_bytes()).decode("ascii")
            return f"data:{_MIME.get(ext, 'image/png')};base64,{b64}"
    return ""


def _fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M")
    except Exception:
        return iso or ""


def generate(csv_path: Path, out_html: Path, meta: dict, stats: dict) -> Path:
    rows = _read_rows(csv_path)

    by_service = stats.get("by_service") or {}
    recap_rows = sorted(by_service.items(), key=lambda kv: -kv[1].get("detected", 0))

    found = stats.get("detected", len(rows))
    crit = stats.get("critical", sum(1 for r in rows if r["severity"] == "critical"))
    detected_only = max(found - crit, 0)
    errors = stats.get("errors", 0)

    # summary band figures
    summary = [
        ("Hosts / jobs scanned", f"{stats.get('scanned', 0)} / {stats.get('total', 0)}"),
        ("Services found", str(found)),
        ("Critical", str(crit)),
        ("Errors", str(errors)),
        ("Duration", f"{stats.get('elapsed', 0)} s"),
        ("Throughput", f"{stats.get('rate', 0)}/s"),
    ]
    summary_html = "".join(
        f'<div class="stat"><span class="num">{html.escape(v)}</span>'
        f'<span class="lab">{html.escape(l)}</span></div>'
        for l, v in summary
    )

    # severity bar widths
    tot = max(crit + detected_only, 1)
    bar_html = (
        f'<span class="seg crit" style="width:{crit / tot * 100:.1f}%"></span>'
        f'<span class="seg det" style="width:{detected_only / tot * 100:.1f}%"></span>'
    )

    recap_html = "".join(
        f"<tr><td>{html.escape(name)}</td>"
        f"<td class='r'>{v.get('detected', 0)}</td>"
        f"<td class='r crit'>{v.get('critical', 0)}</td>"
        f"<td class='r'>{v.get('auth', 0)}</td></tr>"
        for name, v in recap_rows
    ) or "<tr><td colspan='4' class='muted'>No services detected.</td></tr>"

    probes = meta.get("probes", [])
    probes_str = ", ".join(probes) if isinstance(probes, list) else str(probes)
    params = [
        ("Run", meta.get("runid", "")),
        ("Date", _fmt_date(meta.get("started", ""))),
        ("Scope", f'{Path(str(meta.get("targets_file", ""))).name} '
                  f'({meta.get("targets_count", "?")} hosts)'),
        ("Probes", probes_str),
        ("Credential test", "enabled" if meta.get("check_auth") else "disabled"),
        ("Status", meta.get("status", "")),
    ]
    params_html = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in params
    )

    logo = _logo_data_uri()
    logo_html = f'<img class="logo" src="{logo}" alt="">' if logo else ""

    doc = _TEMPLATE
    doc = doc.replace("{{TITLE}}", html.escape(f"Network Service Scan Report - {meta.get('runid', '')}"))
    doc = doc.replace("{{LOGO}}", logo_html)
    doc = doc.replace("{{RUNLINE}}", html.escape(
        f"{meta.get('runid', '')}    {_fmt_date(meta.get('started', ''))}"))
    doc = doc.replace("{{SUMMARY}}", summary_html)
    doc = doc.replace("{{SEVBAR}}", bar_html)
    doc = doc.replace("{{CRIT}}", str(crit))
    doc = doc.replace("{{DET}}", str(detected_only))
    doc = doc.replace("{{PARAMS}}", params_html)
    doc = doc.replace("{{RECAP}}", recap_html)
    doc = doc.replace("{{DATA}}", json.dumps(rows))

    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(doc, encoding="utf-8")
    return out_html


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root{
    --blue:#27509B; --navy:#13284f; --line:#d9dee8; --ink:#1b2333; --muted:#707a8c;
    --paper:#ffffff; --bg:#eef1f6; --crit:#c01632; --det:#2c63c9; --warn:#b8860b;
    --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font-family:"Helvetica Neue",Arial,"Segoe UI",sans-serif;font-size:14px;line-height:1.45}
  .sheet{max-width:1080px;margin:22px auto;background:var(--paper);border:1px solid var(--line)}

  header{border-top:4px solid var(--blue);padding:22px 30px 18px;border-bottom:1px solid var(--line);
         display:flex;align-items:center;gap:18px}
  header .logo{height:46px;width:auto}
  header h1{margin:0;font-size:19px;font-weight:700;letter-spacing:.2px;color:var(--navy)}
  header .runline{margin-top:3px;font-family:var(--mono);font-size:12px;color:var(--muted)}

  .summary{display:flex;flex-wrap:wrap;gap:0;border-bottom:1px solid var(--line)}
  .summary .stat{flex:1 1 140px;padding:16px 22px;border-right:1px solid var(--line)}
  .summary .stat:last-child{border-right:none}
  .summary .num{display:block;font-size:24px;font-weight:700;color:var(--navy)}
  .summary .lab{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:3px}

  .sevwrap{padding:16px 30px;border-bottom:1px solid var(--line)}
  .sevbar{height:12px;background:#eef1f6;border:1px solid var(--line);display:flex;overflow:hidden;border-radius:2px}
  .sevbar .seg{height:100%} .sevbar .seg.crit{background:var(--crit)} .sevbar .seg.det{background:var(--det)}
  .sevlegend{margin-top:8px;font-size:12px;color:var(--muted)}
  .sevlegend b{color:var(--ink)} .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin:0 5px 0 14px;vertical-align:middle}
  .dot.crit{background:var(--crit)} .dot.det{background:var(--det)}

  main{display:grid;grid-template-columns:1fr 320px;gap:0}
  @media(max-width:860px){main{grid-template-columns:1fr}}
  section{padding:20px 30px}
  aside{border-left:1px solid var(--line)}
  @media(max-width:860px){aside{border-left:none;border-top:1px solid var(--line)}}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--blue);margin:0 0 12px;font-weight:700}

  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
  thead th{font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);
           border-bottom:2px solid var(--navy);cursor:pointer;user-select:none;white-space:nowrap}
  td.mono,.mono{font-family:var(--mono)}
  td.r,th.r{text-align:right}
  .crit{color:var(--crit);font-weight:700}
  .muted{color:var(--muted)}
  tbody tr.critical td:first-child{border-left:3px solid var(--crit)}
  tbody tr.detected td:first-child{border-left:3px solid var(--det)}
  tbody tr:hover{background:#f5f7fb}

  .params th{width:44%;color:var(--muted);font-weight:600;text-transform:none;letter-spacing:0;
             font-size:13px;border-bottom:1px solid var(--line)}
  .params td{font-family:var(--mono);font-size:12px;word-break:break-all}

  .toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
  .toolbar input{border:1px solid var(--line);padding:7px 10px;font-size:13px;min-width:230px}
  .filt{font-size:12px;color:var(--muted);border:1px solid var(--line);padding:6px 11px;cursor:pointer;background:#fff}
  .filt.on{background:var(--navy);color:#fff;border-color:var(--navy)}
  code{font-family:var(--mono);font-size:12px;background:#f1f3f8;border:1px solid var(--line);padding:0 4px}
  a{color:var(--blue);text-decoration:none} a:hover{text-decoration:underline}
  footer{padding:14px 30px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}
</style>
</head>
<body>
<div class="sheet">
  <header>
    {{LOGO}}
    <div>
      <h1>Network Service Scan Report</h1>
      <div class="runline">{{RUNLINE}}</div>
    </div>
  </header>

  <div class="summary">{{SUMMARY}}</div>

  <div class="sevwrap">
    <div class="sevbar">{{SEVBAR}}</div>
    <div class="sevlegend">
      <span class="dot crit"></span><b>{{CRIT}}</b> critical (default creds / open)
      <span class="dot det"></span><b>{{DET}}</b> detected, not cracked
    </div>
  </div>

  <main>
    <section>
      <h2>Findings</h2>
      <div class="toolbar">
        <input id="q" placeholder="filter ip / service / url" oninput="render()">
        <span class="filt on" data-s="all" onclick="setF(this)">all</span>
        <span class="filt" data-s="critical" onclick="setF(this)">critical</span>
        <span class="filt" data-s="detected" onclick="setF(this)">detected</span>
        <span class="filt" data-s="error" onclick="setF(this)">errors</span>
      </div>
      <table id="tbl">
        <thead><tr>
          <th onclick="sortBy('ip')">Host</th>
          <th onclick="sortBy('port')">Port</th>
          <th onclick="sortBy('service')">Service</th>
          <th onclick="sortBy('security')">Security</th>
          <th onclick="sortBy('auth')">Auth</th>
          <th>Credentials</th>
          <th>Notes</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </section>
    <aside>
      <section>
        <h2>Scan parameters</h2>
        <table class="params">{{PARAMS}}</table>
      </section>
      <section>
        <h2>By service</h2>
        <table>
          <thead><tr><th>Service</th><th class="r">Found</th><th class="r">Crit</th><th class="r">Auth</th></tr></thead>
          <tbody>{{RECAP}}</tbody>
        </table>
      </section>
    </aside>
  </main>

  <footer>Confidential. Internal use only, for authorized security testing.</footer>
</div>
<script>
const DATA = {{DATA}};
let filter="all", key="ip", dir=1;
function setF(el){document.querySelectorAll('.filt').forEach(c=>c.classList.remove('on'));el.classList.add('on');filter=el.dataset.s;render();}
function sortBy(k){if(key===k)dir*=-1;else{key=k;dir=1;}render();}
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML;}
function render(){
  const q=document.getElementById('q').value.toLowerCase();
  let rows=DATA.filter(r=>{
    if(filter!=='all'&&r.severity!==filter)return false;
    if(!q)return true;
    return (r.ip+' '+r.service+' '+(r.url||'')+' '+(r.info||'')).toLowerCase().includes(q);
  });
  rows.sort((a,b)=>{const x=(a[key]||''),y=(b[key]||'');return (x>y?1:x<y?-1:0)*dir;});
  const authCell=r=>r.auth==='SUCCESS'?'<span class="crit">SUCCESS</span>'
                 :r.security==='none'?'<span class="crit">OPEN</span>'
                 :esc(r.auth||'-');
  const creds=r=>{
    if(r.auth!=='SUCCESS'&&r.security!=='none')return '<span class="muted">-</span>';
    const u=r.username?esc(r.username)+' / ':'';
    const p=r.password?esc(r.password):(r.security==='none'?'(no auth)':'<empty>');
    return '<code>'+u+p+'</code>';
  };
  const host=r=>'<span class="mono">'+esc(r.ip)+(r.url?'':'')+'</span>';
  document.getElementById('rows').innerHTML=rows.map(r=>
    `<tr class="${r.severity}">
       <td>${r.url?`<a href="${esc(r.url)}" class="mono">${esc(r.ip)}</a>`:`<span class="mono">${esc(r.ip)}</span>`}</td>
       <td class="mono">${esc(r.port)||'-'}</td>
       <td>${esc(r.service)}</td>
       <td>${esc(r.security)||'-'}${r.proto?` <span class="muted">(${esc(r.proto)})</span>`:''}</td>
       <td>${authCell(r)}</td>
       <td>${creds(r)}</td>
       <td class="muted">${esc(r.info||r.error||'')}</td>
     </tr>`).join('')||'<tr><td colspan="7" class="muted">No matching findings.</td></tr>';
}
render();
</script>
</body>
</html>"""
