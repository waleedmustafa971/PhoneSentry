"""Builds the HTML + JSON report and the recommendation list."""
import base64
import html
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from . import APP_NAME, APP_VERSION, paths
from .models import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, ScanResult

E = html.escape
SEV_LABEL = {CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low"}
CAT_LABEL = {"spyware": "Mercenary spyware", "stalkerware": "Stalkerware", "malware": "Malware / trojan",
             "suspicious-app": "Suspicious app", "profile": "Configuration profile", "forensic": "Forensic alert"}
STATUS_LABEL = {"found": "Not removed", "kept": "Kept by user", "removed": "Removed",
                "failed": "Removal failed", "needs-user-action": "Needs action on phone"}


def mask(serial: str) -> str:
    return serial if len(serial) <= 4 else "•" * (len(serial) - 4) + serial[-4:]


def verdict(r: ScanResult):
    active = [f for f in r.findings if f.status != "removed"]
    if any(f.severity == CRITICAL for f in r.findings):
        return "danger", "Threats detected", "Known spyware or malware indicators were found on this device."
    if any(f.severity == HIGH for f in active):
        return "danger", "Malware likely", "Apps with strong malware behaviour were found."
    if any(f.severity == HIGH for f in r.findings):
        return "warn", "Threats removed", "Malicious apps were found and removed. Follow the recommendations below."
    if any(f.severity in (MEDIUM, LOW) for f in active):
        return "warn", "Review recommended", "No known threats, but some items deserve a look."
    return "ok", "No threats found", "No known spyware, stalkerware or malware was detected."


def recommendations(r: ScanResult) -> list[tuple[str, str]]:
    recs, cats = [], {f.category for f in r.findings}
    removed = [f for f in r.findings if f.status == "removed"]
    ios = r.device.platform == "ios"
    if "spyware" in cats:
        recs.append(("urgent", "Mercenary spyware indicators were found. Before wiping the phone, contact "
                     "Amnesty International's Security Lab (securitylab.amnesty.org/get-help) or Access Now's "
                     "Digital Security Helpline (accessnow.org/help). They help for free, can confirm the "
                     "infection and preserve evidence. Meanwhile use a different device for sensitive conversations."))
        recs.append(("urgent", "Update the phone to the latest OS version and restart it daily: several spyware "
                     "families do not survive a reboot." + (" Turn on Lockdown Mode." if ios else "")))
    if "stalkerware" in cats:
        recs.append(("urgent", "Stalkerware was found. Someone with access to the phone likely installed it, and "
                     "removing it may alert them. If you feel unsafe, contact a support service first "
                     "(stopstalkerware.org lists helplines by country). Change your phone passcode and "
                     "the passwords of your Google/Apple, email and social accounts from a safe device."))
    if removed or "malware" in cats:
        recs.append(("high", "Malware had access to this phone: change passwords for email, banking and social "
                     "accounts, turn on two-factor authentication, and check bank statements for unknown charges."))
    if any(f.status in ("failed", "needs-user-action") for f in r.findings):
        recs.append(("high", "Some threats could not be removed automatically. Follow the note next to each one. "
                     "If an app cannot be removed, back up photos and contacts and do a factory reset."))
    for c in r.checks:
        if c.status == FAIL and c.advice:
            recs.append(("high", f"{c.name}: {c.advice}"))
    for c in r.checks:
        if c.status == WARN and c.advice:
            recs.append(("medium", f"{c.name}: {c.advice}"))
    if any(f.category == "suspicious-app" and f.status != "removed" for f in r.findings):
        recs.append(("medium", "Review the suspicious apps listed above. Remove any you don't recognise or no longer use."))
    if not r.deep_scan or not r.forensic.get("ran"):
        recs.append(("low", "Run a Deep scan for full forensic coverage of advanced spyware such as Pegasus."))
    if not r.cloud.get("ran") and r.device.platform == "android":
        recs.append(("low", "Add a free VirusTotal API key in Settings so every sideloaded app is checked against 70+ antivirus engines."))
    recs.append(("low", "Install apps only from the official store, keep automatic updates on, and re-scan monthly."))
    return recs


def _logo_b64() -> str:
    try:
        return base64.b64encode(paths.resource("assets", "logo-96.png").read_bytes()).decode()
    except OSError:
        return ""


CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#0f172a;--muted:#5b6475;--line:#e3e7ef;--ok:#059669;--warn:#d97706;--bad:#dc2626;--accent:#2563eb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;align-items:center;gap:14px;margin-bottom:18px}header img{width:52px;height:52px}
header h1{margin:0;font-size:22px}header .sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:14px 0}
h2{font-size:17px;margin:0 0 12px}
.verdict{border-left:6px solid var(--ok)}.verdict.warn{border-color:var(--warn)}.verdict.danger{border-color:var(--bad)}
.verdict .big{font-size:24px;font-weight:700}.verdict.ok .big{color:var(--ok)}.verdict.warn .big{color:var(--warn)}.verdict.danger .big{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px 22px}
.kv .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.kv .v{font-weight:600;word-break:break-word}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:var(--bg);border-radius:10px;padding:10px 12px}.stat b{display:block;font-size:22px}.stat span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}.medium{background:#fef3c7;color:#92400e}.low{background:#e0e7ff;color:#3730a3}
.pass{background:#d1fae5;color:#065f46}.warn{background:#fef3c7;color:#92400e}.fail{background:#fee2e2;color:#991b1b}.unknown{background:#eef0f4;color:#475569}
.removed{background:#d1fae5;color:#065f46}.failed,.needs-user-action{background:#fee2e2;color:#991b1b}.found,.kept{background:#eef0f4;color:#475569}
ul.reasons{margin:4px 0 0;padding-left:18px;color:var(--muted)}code{font:12px Consolas,monospace;background:var(--bg);padding:1px 4px;border-radius:4px;word-break:break-all}
ol.recs li{margin:6px 0}.tag{font-size:11px;font-weight:700;text-transform:uppercase;margin-right:6px}
.tag.urgent{color:var(--bad)}.tag.high{color:#c2410c}.tag.medium{color:var(--warn)}.tag.low{color:var(--accent)}
details summary{cursor:pointer;color:var(--accent)}.muted{color:var(--muted)}.small{font-size:13px}
footer{color:var(--muted);font-size:12px;margin-top:24px}
@media print{body{background:#fff}.card{break-inside:avoid}details{display:block}}
"""


def build(r: ScanResult, out_dir: Path | None = None) -> Path:
    d = r.device
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", d.display).strip("-") or "device"
    out = out_dir or paths.REPORTS_DIR / f"{slug}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    r.report_dir = str(out)

    # Keep MVT's machine-readable output with the report; drop the raw dump unless asked.
    if r.forensic.get("output_dir") and Path(r.forensic["output_dir"]).exists():
        dest = out / "forensics"
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(r.forensic["output_dir"], dest)
        r.forensic["output_dir"] = str(dest)

    cls, title, sub = verdict(r)
    threats = [f for f in r.findings if f.severity in (CRITICAL, HIGH)]
    susp = [f for f in r.findings if f.severity in (MEDIUM, LOW)]
    removed = [f for f in r.findings if f.status == "removed"]

    dev_rows = [("Brand", d.brand), ("Model", d.model), ("Model code", d.model_code),
                ("Operating system", f"{d.os_name} {d.os_version}".strip()),
                ("Interface", d.extra.get("skin", "")), ("Build", d.build),
                ("Security patch", d.security_patch), ("Manufacturer", d.manufacturer if d.manufacturer != d.brand else ""),
                ("Model number", d.extra.get("model_number", "")), ("Device name", d.extra.get("name", "")),
                ("Serial number", mask(d.serial)), ("Storage", d.extra.get("storage", "")),
                ("Battery", d.extra.get("battery", "")), ("Hardware", d.extra.get("hardware", ""))]
    dev_html = "".join(f'<div class="kv"><div class="k">{E(k)}</div><div class="v">{E(str(v))}</div></div>'
                       for k, v in dev_rows if v)

    def finding_rows(items):
        if not items:
            return '<p class="muted">None.</p>'
        rows = []
        for f in items:
            det = f.details or {}
            extra = []
            if det.get("store"):
                extra.append(f"Source: {E(det['store'])}")
            if det.get("version"):
                extra.append(f"Version {E(det['version'])}")
            if det.get("installed"):
                extra.append(f"Installed {E(det['installed'])}")
            if det.get("sha256"):
                extra.append(f"SHA-256 <code>{E(det['sha256'])}</code>")
            note = f'<div class="small muted">{E(f.status_note)}</div>' if f.status_note else ""
            rows.append(
                f'<tr><td><span class="pill {f.severity}">{SEV_LABEL.get(f.severity, f.severity)}</span></td>'
                f'<td><b>{E(f.title)}</b><div class="small muted">{CAT_LABEL.get(f.category, f.category)}</div>'
                f'<ul class="reasons">{"".join(f"<li>{E(x)}</li>" for x in f.reasons[:8])}</ul>'
                f'<div class="small muted">{" · ".join(extra)}</div></td>'
                f'<td><span class="pill {f.status}">{STATUS_LABEL.get(f.status, f.status)}</span>{note}</td></tr>')
        return f'<table><tr><th>Severity</th><th>Item</th><th>Status</th></tr>{"".join(rows)}</table>'

    checks_html = "".join(
        f'<tr><td>{E(c.name)}</td><td><span class="pill {c.status}">{c.status.upper()}</span></td>'
        f'<td>{E(c.value)}{f"<div class=small muted>{E(c.advice)}</div>" if c.advice and c.status != PASS else ""}</td></tr>'
        for c in r.checks)

    fz = r.forensic
    if fz.get("ran"):
        cnt = fz["counts"]
        notes = "".join(f"<li><b>{E(n['level'])}</b> · {E(n['module'])}: {E(n['message'])}</li>" for n in fz.get("notes", []))
        forensic_html = (
            f'<p>Source: {E(fz.get("source", ""))}. Analysed with the Mobile Verification Toolkit (MVT) forensic '
            f'modules against every indicator below.</p><div class="stats">'
            f'<div class="stat"><b>{len(fz["ioc_hits"])}</b><span>Indicator matches</span></div>'
            f'<div class="stat"><b>{cnt.get("CRITICAL", 0) + cnt.get("HIGH", 0)}</b><span>High/critical alerts</span></div>'
            f'<div class="stat"><b>{cnt.get("MEDIUM", 0)}</b><span>Medium alerts</span></div>'
            f'<div class="stat"><b>{cnt.get("LOW", 0)}</b><span>Low alerts</span></div></div>'
            + (f'<details><summary>{fz["notes_total"]} heuristic warnings (usually benign; for expert review)</summary>'
               f'<ul class="small">{notes}</ul></details>' if notes else "")
            + '<p class="small muted">Full MVT output (JSON, timeline) is in the <code>forensics</code> folder next to this report.</p>')
    else:
        forensic_html = '<p class="muted">Not run. Use <b>Deep scan</b> to analyse a full bug report / backup with MVT.</p>'

    recs = "".join(f'<li><span class="tag {lvl}">{lvl}</span>{E(t)}</li>' for lvl, t in recommendations(r))
    actions = [f"Removed {f.title}" for f in removed] + r.actions
    actions_html = "".join(f"<li>{E(a)}</li>" for a in actions) or '<li class="muted">No changes were made to the device.</li>'
    errors_html = "".join(f"<li>{E(e)}</li>" for e in r.errors)
    sets = sorted({s for s in r.ioc_sets if s})
    sets_html = ", ".join(E(s) for s in sets)

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{APP_NAME} report · {E(d.display)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><img src="data:image/png;base64,{_logo_b64()}" alt=""><div><h1>{APP_NAME} security report</h1>
<div class="sub">{E(d.display)} · {E(r.finished or r.started).replace("T", " ")} · {"Deep scan" if r.deep_scan else "Quick scan"}</div></div></header>
{'<div class="card" style="background:#eef2ff;border-color:#c7d2fe"><b>Sample report.</b> Demo data generated by PhoneSentry&#39;s demo mode to show the report format. It does not describe a real device or real apps.</div>' if r.sample else ""}
<div class="card verdict {cls}"><div class="big">{title}</div><div>{sub}</div></div>
<div class="card"><h2>Device</h2><div class="grid">{dev_html}</div></div>
<div class="card"><h2>Summary</h2><div class="stats">
<div class="stat"><b>{len(threats)}</b><span>Threats</span></div>
<div class="stat"><b>{len(susp)}</b><span>Items to review</span></div>
<div class="stat"><b>{len(removed)}</b><span>Removed</span></div>
<div class="stat"><b>{r.apps_scanned}</b><span>User apps scanned</span></div>
<div class="stat"><b>{r.system_apps}</b><span>System apps checked</span></div>
<div class="stat"><b>{r.ioc_total:,}</b><span>Threat indicators</span></div></div></div>
<div class="card"><h2>Threats</h2>{finding_rows(threats)}</div>
<div class="card"><h2>Items to review</h2>{finding_rows(susp)}</div>
{f'<div class="card"><h2>Security checks</h2><table><tr><th>Check</th><th>Result</th><th>Details</th></tr>{checks_html}</table></div>' if checks_html else ""}
<div class="card"><h2>Advanced spyware forensics</h2>{forensic_html}</div>
<div class="card"><h2>Actions taken</h2><ul>{actions_html}</ul>{f"<h2>Scan notes</h2><ul>{errors_html}</ul>" if errors_html else ""}</div>
<div class="card"><h2>Recommendations</h2><ol class="recs">{recs}</ol></div>
<div class="card small"><h2>What was checked</h2>
<p>Spyware & stalkerware families covered ({len(sets)}): {sets_html}.</p>
<p>Malware engine: package/hash/process/property indicator matching, behavioural analysis of every user app
(sideloading, accessibility & device-admin abuse, SMS and notification access, overlays, hidden icons, system-app impersonation){
", and cloud hash reputation for " + str(r.cloud.get("checked", 0)) + " apps" if r.cloud.get("ran") else ""}.</p>
<p class="muted">Limitations: a clean result lowers the likelihood of known threats but cannot prove a device is uncompromised.
New or unknown spyware may leave no trace that any tool can see. If you have strong reasons to believe you are targeted,
seek expert help (see recommendations).</p></div>
<footer>Generated by {APP_NAME} {APP_VERSION} · spyware detection powered by the Mobile Verification Toolkit (MVT) and its public indicator feeds.
This report may contain personal data (app list, forensic records): share it only with people you trust.</footer>
</div></body></html>"""
    html_path = out / "report.html"
    html_path.write_text(page, encoding="utf-8")
    r.report_html = str(html_path)
    data = r.to_dict()
    data["device"]["serial"] = mask(d.serial)
    data["device"]["extra"].pop("udid", None)
    (out / "report.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return html_path
