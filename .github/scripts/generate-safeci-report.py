#!/usr/bin/env python3
"""Generate the SafeCI full findings report.

The PDF is the deliverable: it carries every finding from every stage plus a
map of where each scanner's raw assessment lives. The Markdown output is only a
compact run summary for the GitHub Actions step summary panel.

    python generate-safeci-report.py \\
      --results results.json \\
      --artifacts-dir artifacts \\
      --pdf safeci-full-report.pdf \\
      --html safeci-full-report.html \\
      --out safeci-summary.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

# Severity rank: lower sorts first (most severe at the top of every table).
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 5,
}

SEVERITY_COLOR = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#c2410c",
    "low": "#a16207",
    "info": "#525252",
    "informational": "#525252",
    "unknown": "#525252",
}

STATUS_COLOR = {
    "success": "#15803d",
    "failure": "#b91c1c",
    "cancelled": "#a16207",
    "skipped": "#525252",
    "unknown": "#525252",
}

PROJECT_KEY = "sudhakar-dotcom_leaky-repo"
SONAR_BASE = "https://sonarcloud.io"

STAGES = [
    {
        "id": "gitleaks",
        "num": "1",
        "title": "Gitleaks",
        "kind": "Secrets (SCA of credentials)",
        "scope": "Working tree + full git history",
        "artifact": "safeci-gitleaks",
        "files": "gitleaks-report.json, gitleaks-history-report.json, stage-meta.json",
        "where": (
            "Workflow run &rarr; Artifacts &rarr; <b>safeci-gitleaks</b> &rarr; "
            "<code>gitleaks-report.json</code> (working tree) and "
            "<code>gitleaks-history-report.json</code> (git history)"
        ),
        "dashboard": None,
        "note": (
            "leaky-repo is a secrets benchmark: every hit is a planted fixture, so the stage "
            "soft-fails and the pipeline still publishes this report. Secret values are redacted below."
        ),
        "headers": ["Severity", "Rule", "File", "Line", "Commit", "Secret (redacted)"],
        "widths": ["8%", "20%", "34%", "6%", "12%", "20%"],
    },
    {
        "id": "checkov",
        "num": "2",
        "title": "Checkov",
        "kind": "IaC / configuration",
        "scope": "Terraform, Dockerfiles, K8s, CI config under the repo root",
        "artifact": "safeci-checkov",
        "files": "results_json.json, stage-meta.json",
        "where": (
            "Workflow run &rarr; Artifacts &rarr; <b>safeci-checkov</b> &rarr; "
            "<code>results_json.json</code> (key <code>results.failed_checks</code>)"
        ),
        "dashboard": None,
        "note": "soft_fail=true — failed checks are reported without breaking the build.",
        "headers": ["Severity", "Check ID", "Check", "Resource", "File:line"],
        "widths": ["9%", "14%", "32%", "22%", "23%"],
    },
    {
        "id": "sonarcloud",
        "num": "3",
        "title": "SonarCloud",
        "kind": "SAST + security hotspots",
        "scope": "All source under sonar.sources (.git and .leaky-meta excluded)",
        "artifact": "safeci-sonarcloud",
        "files": "stage-meta.json (scan metadata only — findings live on SonarCloud)",
        "where": (
            f"<b>{SONAR_BASE}/project/issues?id={PROJECT_KEY}&amp;resolved=false</b> (Issues tab) and "
            f"<b>{SONAR_BASE}/project/security_hotspots?id={PROJECT_KEY}</b> (Security Hotspots tab)"
        ),
        "dashboard": f"{SONAR_BASE}/project/overview?id={PROJECT_KEY}",
        "note": (
            "The scanner uploads results to SonarCloud rather than writing a local report file, "
            "so this stage has no offline findings table — use the links above."
        ),
        "headers": ["Field", "Value"],
        "widths": ["22%", "78%"],
        "linkonly": True,
    },
    {
        "id": "snyk",
        "num": "4",
        "title": "Snyk",
        "kind": "Dependency vulnerabilities",
        "scope": "Package manifests discovered by --all-projects",
        "artifact": "safeci-snyk",
        "files": "snyk-report.json, stage-meta.json",
        "where": (
            "Workflow run &rarr; Artifacts &rarr; <b>safeci-snyk</b> &rarr; "
            "<code>snyk-report.json</code>, plus the live dashboard at <b>https://app.snyk.io</b>"
        ),
        "dashboard": "https://app.snyk.io",
        "note": (
            "Threshold is --severity-threshold=high. leaky-repo ships no real package manifests, "
            "so an empty result here is the expected outcome, not a failure."
        ),
        "headers": ["Severity", "ID / CVE", "Title", "Package", "Fixed in"],
        "widths": ["9%", "18%", "33%", "24%", "16%"],
    },
    {
        "id": "zap",
        "num": "5",
        "title": "OWASP ZAP",
        "kind": "DAST (baseline, passive)",
        "scope": "The live target URL — not repository files",
        "artifact": "safeci-zap",
        "files": "report_html.html, report_json.json, report_md.md, stage-meta.json",
        "where": (
            "Workflow run &rarr; Artifacts &rarr; <b>safeci-zap</b> &rarr; "
            "<code>report_html.html</code> (best for reading) or <code>report_json.json</code> (machine readable)"
        ),
        "dashboard": None,
        "note": "Baseline scan is passive only — it does not attack the target. fail_action=false.",
        "headers": ["Risk", "Alert", "CWE", "Instances", "Example URL"],
        "widths": ["9%", "34%", "8%", "10%", "39%"],
    },
]

STAGE_BY_ID = {s["id"]: s for s in STAGES}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def norm_severity(value: str | None) -> str:
    v = (value or "unknown").strip().lower()
    for key in SEVERITY_ORDER:
        if v.startswith(key):
            return "medium" if key == "moderate" else ("info" if key == "informational" else key)
    return "unknown"


def sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 5)


def clip(value, limit: int = 160) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def redact(secret: str | None) -> str:
    if not secret:
        return ""
    s = " ".join(str(secret).split())
    if len(s) <= 8:
        return s[0] + "*" * (len(s) - 1) if s else ""
    return f"{s[:4]}{'*' * 8}{s[-4:]} ({len(s)} chars)"


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def load_results(path: Path | None) -> dict:
    if path and path.exists():
        data = read_json(path)
        if isinstance(data, dict):
            return data
    raw = os.environ.get("SAFECI_RESULTS_JSON", "").strip()
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return {}


def stage_dir(artifacts_root: Path, sid: str) -> Path | None:
    """Artifacts land in <root>/safeci-<id>/ but tolerate flatter layouts."""
    for candidate in (artifacts_root / f"safeci-{sid}", artifacts_root / sid):
        if candidate.is_dir():
            return candidate
    if artifacts_root.is_dir():
        for child in artifacts_root.iterdir():
            if child.is_dir() and sid in child.name.lower():
                return child
    return None


def find(directory: Path | None, *names: str) -> list[Path]:
    if directory is None or not directory.is_dir():
        return []
    hits: list[Path] = []
    for name in names:
        hits.extend(p for p in directory.rglob(name) if p.is_file())
    seen, out = set(), []
    for p in hits:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def load_stage_meta(directory: Path | None) -> dict:
    for p in find(directory, "stage-meta.json"):
        data = read_json(p)
        if isinstance(data, dict):
            return data
    return {}


# --------------------------------------------------------------------------
# per-scanner parsers -> list of rows (first cell is severity where relevant)
# --------------------------------------------------------------------------

def parse_gitleaks(directory: Path | None) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    notes: list[str] = []
    for path in sorted(find(directory, "gitleaks*.json")):
        if path.name == "stage-meta.json":
            continue
        data = read_json(path)
        if data is None:
            notes.append(f"{path.name}: could not be parsed as JSON")
            continue
        items = data if isinstance(data, list) else (data.get("findings") or data.get("Findings") or [])
        source = "history" if "history" in path.name else "working tree"
        notes.append(f"{path.name} ({source}): {len(items)} finding(s)")
        for f in items:
            if not isinstance(f, dict):
                continue
            rule = f.get("RuleID") or f.get("rule_id") or f.get("Rule") or "?"
            rows.append([
                "high",
                clip(f.get("Description") or rule, 70),
                clip(f.get("File") or f.get("file") or "?", 90),
                str(f.get("StartLine") or f.get("start_line") or ""),
                clip(f.get("Commit") or "working tree", 12),
                redact(f.get("Secret") or f.get("Match")),
            ])
    return rows, notes


def parse_checkov(directory: Path | None) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    notes: list[str] = []
    for path in sorted(find(directory, "results_json.json", "checkov*.json")):
        data = read_json(path)
        if data is None:
            notes.append(f"{path.name}: could not be parsed as JSON")
            continue
        blocks = data if isinstance(data, list) else [data]
        failed_total = 0
        for block in blocks:
            results = (block or {}).get("results") or {}
            failed = results.get("failed_checks") or []
            failed_total += len(failed)
            for c in failed:
                line_range = c.get("file_line_range") or []
                line = f"{line_range[0]}-{line_range[-1]}" if line_range else ""
                location = f"{clip(c.get('file_path') or '?', 70)}:{line}" if line else clip(c.get("file_path") or "?", 70)
                rows.append([
                    norm_severity(c.get("severity")),
                    clip(c.get("check_id") or "?", 30),
                    clip(c.get("check_name") or "", 90),
                    clip(c.get("resource") or "", 60),
                    location,
                ])
            passed = len(results.get("passed_checks") or [])
            if passed:
                notes.append(f"{(block or {}).get('check_type', 'checkov')}: {passed} check(s) passed")
        notes.append(f"{path.name}: {failed_total} failed check(s)")
    return rows, notes


def parse_snyk(directory: Path | None) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    notes: list[str] = []
    for path in sorted(find(directory, "snyk*.json")):
        data = read_json(path)
        if data is None:
            notes.append(f"{path.name}: could not be parsed as JSON")
            continue
        for proj in (data if isinstance(data, list) else [data]):
            vulns = (proj or {}).get("vulnerabilities") or []
            notes.append(f"{(proj or {}).get('displayTargetFile') or path.name}: {len(vulns)} vulnerability(ies)")
            for v in vulns:
                cves = ", ".join((v.get("identifiers") or {}).get("CVE") or []) or v.get("id") or "?"
                pkg = f"{v.get('packageName') or v.get('package') or '?'}@{v.get('version') or '?'}"
                fixed = ", ".join(v.get("fixedIn") or []) or "no fix"
                rows.append([
                    norm_severity(v.get("severity")),
                    clip(cves, 40),
                    clip(v.get("title") or "", 90),
                    clip(pkg, 55),
                    clip(fixed, 30),
                ])
    return rows, notes


def parse_zap(directory: Path | None) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    notes: list[str] = []
    for path in sorted(find(directory, "report_json.json", "zap*.json")):
        if path.name == "stage-meta.json":
            continue
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        for site in data.get("site") or []:
            alerts = site.get("alerts") or []
            notes.append(f"{site.get('@name', 'target')}: {len(alerts)} alert type(s)")
            for a in alerts:
                instances = a.get("instances") or []
                example = instances[0].get("uri") if instances else ""
                rows.append([
                    norm_severity((a.get("riskdesc") or a.get("risk") or "unknown").split(" ")[0]),
                    clip(a.get("alert") or a.get("name") or "?", 90),
                    str(a.get("cweid") or ""),
                    str(a.get("count") or len(instances) or ""),
                    clip(example, 90),
                ])
    if not rows:
        for path in sorted(find(directory, "report_md.md", "report_html.html")):
            notes.append(f"{path.name} present ({path.stat().st_size:,} bytes) — no parsable JSON alerts")
    return rows, notes


def parse_sonarcloud(directory: Path | None) -> tuple[list[list[str]], list[str]]:
    meta = load_stage_meta(directory)
    rows = [
        ["Project key", PROJECT_KEY],
        ["Open issues", f"{SONAR_BASE}/project/issues?id={PROJECT_KEY}&resolved=false"],
        ["Security hotspots", f"{SONAR_BASE}/project/security_hotspots?id={PROJECT_KEY}"],
        ["Project overview", f"{SONAR_BASE}/project/overview?id={PROJECT_KEY}"],
    ]
    if meta.get("note"):
        rows.append(["Stage note", clip(meta["note"], 200)])
    return rows, ["Findings are stored server-side by SonarCloud; open the Issues tab for the full list."]


PARSERS = {
    "gitleaks": parse_gitleaks,
    "checkov": parse_checkov,
    "sonarcloud": parse_sonarcloud,
    "snyk": parse_snyk,
    "zap": parse_zap,
}


def collect(artifacts_dir: Path) -> dict:
    data = {}
    for stage in STAGES:
        sid = stage["id"]
        directory = stage_dir(artifacts_dir, sid)
        rows, notes = PARSERS[sid](directory)
        counts: dict[str, int] = {}
        if not stage.get("linkonly"):
            # most severe first, then alphabetical for stable ordering
            rows.sort(key=lambda r: (sev_rank(r[0]), r[1]))
            for r in rows:
                counts[r[0]] = counts.get(r[0], 0) + 1
        data[sid] = {
            "dir": directory,
            "rows": rows,
            "notes": notes,
            "counts": counts,
            "meta": load_stage_meta(directory),
            "files": sorted(
                (p for p in directory.rglob("*") if p.is_file()),
                key=lambda p: p.name,
            ) if directory and directory.is_dir() else [],
        }
    return data


# --------------------------------------------------------------------------
# HTML rendering (xhtml2pdf-compatible subset)
# --------------------------------------------------------------------------

CSS = """
@page { size: A4 landscape; margin: 1.2cm 1.1cm 1.5cm 1.1cm;
        @frame footer { -pdf-frame-content: footer; bottom: 0.7cm; left: 1.1cm; right: 1.1cm; height: 0.8cm; } }
body { font-family: Helvetica, Arial, sans-serif; font-size: 8.5pt; color: #18181b; }
h1 { font-size: 20pt; margin: 0 0 2px 0; color: #0f172a; }
h2 { font-size: 13pt; margin: 16px 0 6px 0; color: #0f172a;
     border-bottom: 1.5px solid #0f172a; padding-bottom: 3px; }
h3 { font-size: 10.5pt; margin: 12px 0 4px 0; color: #1e293b; }
p  { margin: 3px 0; }
.sub { color: #52525b; font-size: 9pt; margin-bottom: 10px; }
.meta { background: #f4f4f5; border: 1px solid #d4d4d8; padding: 7px 9px; margin: 8px 0 12px 0; }
.meta td { border: none; padding: 1px 6px 1px 0; font-size: 8.5pt; }
table { border-collapse: collapse; width: 100%; margin: 5px 0 12px 0; }
th { background: #1e293b; color: #ffffff; text-align: left; font-size: 8pt;
     padding: 4px 5px; border: 0.6px solid #334155; }
td { border: 0.6px solid #cbd5e1; padding: 3px 5px; font-size: 7.8pt; vertical-align: top;
     word-wrap: break-word; }
tr.alt td { background: #f8fafc; }
code { font-family: Courier, monospace; font-size: 7.5pt; }
.badge { color: #ffffff; padding: 1px 5px; font-size: 7pt; font-weight: bold; }
.note { background: #fffbeb; border-left: 3px solid #d97706; padding: 5px 8px; margin: 6px 0 10px 0;
        font-size: 8pt; color: #451a03; }
.empty { background: #f0fdf4; border-left: 3px solid #16a34a; padding: 5px 8px; margin: 6px 0 10px 0;
         font-size: 8pt; color: #052e16; }
.pagebreak { page-break-before: always; }
#footer { color: #71717a; font-size: 7pt; text-align: center; }
"""


def badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{escape(str(text).upper())}</span>'


def table(headers: list[str], widths: list[str], rows: list[list[str]], sev_col: int | None = 0) -> str:
    out = ["<table>", "<tr>"]
    for h, w in zip(headers, widths):
        out.append(f'<th style="width:{w}">{escape(h)}</th>')
    out.append("</tr>")
    for i, row in enumerate(rows):
        cells = list(row) + [""] * (len(headers) - len(row))
        out.append(f'<tr class="{"alt" if i % 2 else ""}">')
        for j, cell in enumerate(cells[: len(headers)]):
            if j == sev_col and str(cell).lower() in SEVERITY_COLOR:
                sev = str(cell).lower()
                out.append(f"<td>{badge(sev, SEVERITY_COLOR[sev])}</td>")
            else:
                out.append(f"<td>{escape(str(cell))}</td>")
        out.append("</tr>")
    out.append("</table>")
    return "\n".join(out)


def severity_summary(data: dict) -> dict[str, int]:
    totals: dict[str, int] = {}
    for sid, d in data.items():
        if STAGE_BY_ID[sid].get("linkonly"):
            continue
        for sev, n in d["counts"].items():
            totals[sev] = totals.get(sev, 0) + n
    return totals


def build_html(results: dict, data: dict, meta: dict, max_rows: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    totals = severity_summary(data)
    grand_total = sum(totals.values())

    h: list[str] = [f"<style>{CSS}</style>", '<div id="footer">SafeCI full findings report — '
                    f'{escape(meta.get("repository", ""))} — page <pdf:pagenumber> of <pdf:pagecount></div>']

    # ---- cover / run metadata
    h.append("<h1>SafeCI Pipeline &mdash; Full Findings Report</h1>")
    h.append(f'<p class="sub">Every finding from all five scan stages, with the location of each '
             f'scanner&rsquo;s raw assessment. Generated {escape(now)}.</p>')
    h.append('<table class="meta">')
    for label, value in [
        ("Repository", meta.get("repository", "")),
        ("Commit", (meta.get("sha") or "")[:12]),
        ("Workflow run", meta.get("run_url", "")),
        ("DAST target", meta.get("target_url", "")),
        ("Total findings", f"{grand_total} across 4 offline scanners (SonarCloud reports server-side)"),
    ]:
        if value:
            h.append(f"<tr><td><b>{escape(label)}</b></td><td>{escape(str(value))}</td></tr>")
    h.append("</table>")

    # ---- section 1: scoreboard
    h.append("<h2>1 &middot; Stage scoreboard</h2>")
    rows = []
    for s in STAGES:
        d = data[s["id"]]
        status = str(results.get(s["id"], "unknown")).lower()
        linkonly = s.get("linkonly")
        breakdown = ", ".join(
            f"{n} {sev}" for sev, n in sorted(d["counts"].items(), key=lambda kv: sev_rank(kv[0]))
        ) or "—"
        rows.append([
            f'{s["num"]} · {s["title"]}',
            s["kind"],
            status,
            "on SonarCloud" if linkonly else str(len(d["rows"])),
            "—" if linkonly else breakdown,
        ])
    out = ["<table>", "<tr>"]
    for hdr, w in zip(["Stage", "Scan type", "Job status", "Findings", "Severity breakdown"],
                      ["16%", "24%", "12%", "10%", "38%"]):
        out.append(f'<th style="width:{w}">{hdr}</th>')
    out.append("</tr>")
    for i, r in enumerate(rows):
        out.append(f'<tr class="{"alt" if i % 2 else ""}">')
        out.append(f"<td>{escape(r[0])}</td><td>{escape(r[1])}</td>")
        out.append(f"<td>{badge(r[2], STATUS_COLOR.get(r[2], '#525252'))}</td>")
        out.append(f"<td>{escape(r[3])}</td><td>{escape(r[4])}</td></tr>")
    out.append("</table>")
    h.append("\n".join(out))

    if totals:
        h.append("<h3>Severity rollup (all offline scanners)</h3>")
        h.append(table(
            ["Severity", "Findings", ""],
            ["14%", "14%", "72%"],
            [[sev, str(n), ""] for sev, n in sorted(totals.items(), key=lambda kv: sev_rank(kv[0]))],
        ))

    # ---- section 2: where to find everything
    h.append("<h2>2 &middot; Where to find each scan&rsquo;s assessment</h2>")
    h.append('<p class="sub">Download artifacts from the workflow run page &rarr; <b>Artifacts</b> section '
             '(bottom of the summary). Each stage uploads one zip.</p>')
    out = ["<table>", "<tr>"]
    for hdr, w in zip(["Stage", "Artifact zip", "Files inside", "Where the findings are"],
                      ["14%", "14%", "24%", "48%"]):
        out.append(f'<th style="width:{w}">{hdr}</th>')
    out.append("</tr>")
    for i, s in enumerate(STAGES):
        where = s["where"]
        if s.get("dashboard"):
            where += f'<br/><b>Dashboard:</b> {escape(s["dashboard"])}'
        out.append(f'<tr class="{"alt" if i % 2 else ""}">')
        out.append(f'<td>{s["num"]} · {escape(s["title"])}</td>')
        out.append(f'<td><code>{escape(s["artifact"])}</code></td>')
        out.append(f'<td>{escape(s["files"])}</td>')
        out.append(f"<td>{where}</td></tr>")
    out.append("</table>")
    h.append("\n".join(out))

    # ---- sections 3+: per-stage detail
    for s in STAGES:
        sid = s["id"]
        d = data[sid]
        status = str(results.get(sid, "unknown")).lower()
        linkonly = s.get("linkonly")
        h.append('<div class="pagebreak"></div>')
        h.append(f'<h2>{s["num"]} &middot; {escape(s["title"])} &mdash; {escape(s["kind"])}</h2>')
        h.append('<table class="meta">')
        count_text = "reported on SonarCloud" if linkonly else str(len(d["rows"]))
        h.append(f'<tr><td><b>Job status</b></td><td>{badge(status, STATUS_COLOR.get(status, "#525252"))}'
                 f'&nbsp;&nbsp;<b>Findings:</b> {count_text}</td></tr>')
        h.append(f'<tr><td><b>Scope</b></td><td>{escape(s["scope"])}</td></tr>')
        h.append(f'<tr><td><b>Raw assessment</b></td><td>{s["where"]}</td></tr>')
        if s.get("dashboard"):
            h.append(f'<tr><td><b>Dashboard</b></td><td>{escape(s["dashboard"])}</td></tr>')
        h.append("</table>")
        h.append(f'<div class="note">{escape(s["note"])}</div>')

        if d["meta"].get("note") and d["meta"]["note"] != s["note"]:
            h.append(f'<p><b>Stage reported:</b> {escape(str(d["meta"]["note"]))}</p>')
        for note in d["notes"]:
            h.append(f"<p>&bull; {escape(note)}</p>")

        rows = d["rows"]
        if not rows:
            h.append('<div class="empty">No findings recorded for this stage in this run. '
                     'If that is unexpected, check the stage job log and confirm its artifact uploaded.</div>')
            continue
        shown = rows[:max_rows]
        if linkonly:
            h.append("<h3>Where to read the findings</h3>")
            h.append(table(s["headers"], s["widths"], shown, sev_col=None))
            continue
        h.append(f'<h3>Findings ({len(shown)} of {len(rows)} shown, most severe first)</h3>')
        h.append(table(s["headers"], s["widths"], shown))
        if len(rows) > len(shown):
            h.append(f'<div class="note">{len(rows) - len(shown)} further finding(s) omitted to keep the '
                     f'PDF readable &mdash; the complete set is in the <code>{s["artifact"]}</code> artifact.</div>')

    # ---- appendix: artifact inventory
    h.append('<div class="pagebreak"></div>')
    h.append("<h2>Appendix &middot; Artifact file inventory</h2>")
    inv = []
    for s in STAGES:
        for p in data[s["id"]]["files"]:
            try:
                size = f"{p.stat().st_size:,} bytes"
            except OSError:
                size = "?"
            inv.append([s["artifact"], p.name, size])
    if inv:
        h.append(table(["Artifact zip", "File", "Size"], ["24%", "56%", "20%"], inv, sev_col=None))
    else:
        h.append('<div class="note">No stage artifacts were downloaded. The report job downloads artifacts '
                 'matching <code>safeci-*</code>; if this is empty, the stage jobs did not upload.</div>')

    h.append("<h3>How to reproduce locally</h3>")
    h.append("<p>1. <code>python safeci.py scan</code> &mdash; run the local scan set.<br/>"
             "2. <code>python safeci.py benchmark</code> &mdash; score secrets coverage against "
             "<code>.leaky-meta/secrets.csv</code>.<br/>"
             "3. Re-run any single stage from Actions &rarr; the numbered workflow (1&ndash;5) &rarr; Run workflow.</p>")

    return "<div>" + "\n".join(h) + "</div>"


# --------------------------------------------------------------------------
# compact Markdown (step summary only — the PDF is the real report)
# --------------------------------------------------------------------------

def build_summary_md(results: dict, data: dict, meta: dict) -> str:
    totals = severity_summary(data)
    lines = [
        "## SafeCI pipeline results",
        "",
        f"**Full detail: download the `safeci-full-report` artifact → `safeci-full-report.pdf`.**",
        "",
        "| Stage | Type | Status | Findings | Where the raw assessment lives |",
        "|---|---|---|---|---|",
    ]
    for s in STAGES:
        d = data[s["id"]]
        status = results.get(s["id"], "unknown")
        found = "on SonarCloud" if s.get("linkonly") else str(len(d["rows"]))
        lines.append(f"| {s['num']} · {s['title']} | {s['kind']} | `{status}` | {found} | "
                     f"artifact `{s['artifact']}` |")
    lines += ["", "**Severity rollup:** " + (
        ", ".join(f"{n} {sev}" for sev, n in sorted(totals.items(), key=lambda kv: sev_rank(kv[0])))
        or "no findings"), ""]
    for s in STAGES:
        d = data[s["id"]]
        if s.get("linkonly") or not d["rows"]:
            continue
        lines += [f"<details><summary>{s['num']} · {s['title']} — top 10 of {len(d['rows'])}</summary>", "",
                  "| " + " | ".join(s["headers"]) + " |",
                  "|" + "---|" * len(s["headers"])]
        for r in d["rows"][:10]:
            cells = [str(c).replace("|", "\\|") for c in (list(r) + [""] * len(s["headers"]))[: len(s["headers"])]]
            lines.append("| " + " | ".join(cells) + " |")
        lines += ["", "</details>", ""]
    lines += [
        "",
        f"SonarCloud issues: {SONAR_BASE}/project/issues?id={PROJECT_KEY}&resolved=false",
        "",
        "> leaky-repo is a secrets benchmark — Gitleaks findings are planted fixtures and are soft-failed by design.",
        "",
    ]
    return "\n".join(lines)


def write_pdf(html_doc: str, pdf_path: Path) -> None:
    try:
        from xhtml2pdf import pisa  # type: ignore
    except ImportError as exc:
        raise SystemExit("xhtml2pdf is required for PDF output: pip install xhtml2pdf") from exc
    with pdf_path.open("wb") as fh:
        result = pisa.CreatePDF(html_doc, dest=fh, encoding="utf-8")
    if result.err:
        raise SystemExit(f"PDF generation failed with {result.err} error(s)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, help="JSON map of stage id -> job conclusion")
    ap.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    ap.add_argument("--pdf", type=Path, default=Path("safeci-full-report.pdf"))
    ap.add_argument("--html", type=Path, default=Path("safeci-full-report.html"))
    ap.add_argument("--out", type=Path, help="optional compact Markdown summary path")
    ap.add_argument("--max-rows", type=int, default=400, help="max findings rows per stage in the PDF")
    ap.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--run-url", default="")
    ap.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    ap.add_argument("--target-url", default=os.environ.get("SAFECI_TARGET_URL", ""))
    args = ap.parse_args()

    results = load_results(args.results)
    meta = {
        "repository": args.repository,
        "run_url": args.run_url,
        "sha": args.sha,
        "target_url": args.target_url,
    }

    data = collect(args.artifacts_dir)
    for sid, d in data.items():
        print(f"{sid}: dir={d['dir']} findings={len(d['rows'])} files={len(d['files'])}")

    html_doc = build_html(results, data, meta, args.max_rows)
    args.html.write_text(html_doc, encoding="utf-8")
    print(f"Wrote {args.html} ({len(html_doc):,} chars)")

    write_pdf(html_doc, args.pdf)
    print(f"Wrote {args.pdf} ({args.pdf.stat().st_size:,} bytes)")

    summary_md = build_summary_md(results, data, meta)
    if args.out:
        args.out.write_text(summary_md, encoding="utf-8")
        print(f"Wrote {args.out}")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        # GitHub caps the step summary at 1 MiB — the PDF holds the full detail.
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md[:900_000])
        print("Appended summary to GITHUB_STEP_SUMMARY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
