#!/usr/bin/env python3
"""Generate SafeCI full scan report (Markdown + HTML + PDF).

    python generate-safeci-report.py \\
      --results results.json \\
      --artifacts-dir artifacts \\
      --out safeci-full-report.md
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape


STAGES = [
    {
        "id": "gitleaks",
        "title": "1 · Gitleaks",
        "kind": "Secrets",
        "scope": "Repository history & working tree",
        "dashboard": None,
        "artifact_name": "safeci-gitleaks",
        "where": "Actions → Artifacts → safeci-gitleaks → gitleaks-report.json (also in this PDF)",
        "expected": "Many findings expected — leaky-repo is a secrets benchmark (soft-fail).",
        "artifact_hints": ["gitleaks*.json", "gitleaks*.sarif", "*.json"],
    },
    {
        "id": "checkov",
        "title": "2 · Checkov",
        "kind": "IaC",
        "scope": "IaC / config under repo root",
        "dashboard": None,
        "artifact_name": "safeci-checkov",
        "where": "Actions → Artifacts → safeci-checkov → results_json.json",
        "expected": "Soft-fail enabled; review failed checks in the report.",
        "artifact_hints": ["results_json.json", "checkov*.json", "*.json"],
    },
    {
        "id": "sonarcloud",
        "title": "3 · SonarCloud",
        "kind": "SAST",
        "scope": "Source code quality & security hotspots",
        "dashboard": "https://sonarcloud.io/project/overview?id=sudhakar-dotcom_leaky-repo",
        "artifact_name": "safeci-sonarcloud",
        "where": "https://sonarcloud.io/project/issues?id=sudhakar-dotcom_leaky-repo — Issues / Security Hotspots tabs",
        "expected": "Full issue list lives on SonarCloud (linked below).",
        "artifact_hints": ["sonar*.json", "stage-meta.json", "*.json"],
    },
    {
        "id": "snyk",
        "title": "4 · Snyk",
        "kind": "Dependencies",
        "scope": "Dependency manifests",
        "dashboard": "https://app.snyk.io",
        "artifact_name": "safeci-snyk",
        "where": "Actions → Artifacts → safeci-snyk → snyk-report.json AND https://app.snyk.io",
        "expected": "Limited on leaky-repo (no real package manifests).",
        "artifact_hints": ["snyk*.json", "*.json"],
    },
    {
        "id": "zap",
        "title": "5 · ZAP",
        "kind": "DAST",
        "scope": "Live target_url (not repo files)",
        "dashboard": None,
        "artifact_name": "safeci-zap",
        "where": "Actions → Artifacts → safeci-zap → report_html.html / report_md.md",
        "expected": "WARN findings on the demo DAST target are expected.",
        "artifact_hints": ["report_html.html", "report_md.md", "report_json.json", "zap*.html", "*.html", "*.md", "*.json"],
    },
]


def load_results(path: Path | None) -> dict:
    if path and path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    raw = os.environ.get("SAFECI_RESULTS_JSON", "").strip()
    if raw:
        return json.loads(raw)
    return {}


def find_files(root: Path, patterns: list[str]) -> list[Path]:
    if not root.exists():
        return []
    found: list[Path] = []
    for pat in patterns:
        found.extend(root.rglob(pat))
    seen = set()
    out = []
    for p in found:
        if p.is_file() and p.resolve() not in seen:
            seen.add(p.resolve())
            out.append(p)
    return out


def stage_files(stage: dict, artifacts_root: Path) -> list[Path]:
    sid = stage["id"]
    stage_dir = artifacts_root / f"safeci-{sid}"
    files = find_files(stage_dir, stage["artifact_hints"]) if stage_dir.exists() else []
    if not files:
        preferred = [
            p for p in find_files(artifacts_root, stage["artifact_hints"])
            if f"safeci-{sid}" in str(p).replace("\\", "/")
        ]
        files = preferred or find_files(artifacts_root / sid, stage["artifact_hints"])
    if not files and stage_dir.exists():
        files = [p for p in stage_dir.rglob("*") if p.is_file()]
    # Prefer findings over meta when summarizing
    files = sorted(files, key=lambda p: (0 if "meta" in p.name else 1, p.name), reverse=True)
    return files


def extract_findings_rows(path: Path, limit: int = 200) -> tuple[str, list[list[str]]]:
    """Return (title, rows) for a findings table."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            return f"{path.name} (parse error)", [[str(exc), "", ""]]

        # Gitleaks list format
        if isinstance(data, list):
            rows = []
            for f in data[:limit]:
                if not isinstance(f, dict):
                    continue
                rows.append([
                    str(f.get("RuleID") or f.get("Rule") or f.get("Description") or "?")[:80],
                    str(f.get("File") or f.get("FilePath") or "?")[:120],
                    str(f.get("StartLine") or f.get("Line") or f.get("Entropy") or ""),
                ])
            return f"Gitleaks findings ({len(data)} total, showing {len(rows)})", rows

        if isinstance(data, dict):
            if "findings" in data and isinstance(data["findings"], list):
                findings = data["findings"]
                rows = []
                for f in findings[:limit]:
                    rows.append([
                        str(f.get("RuleID") or f.get("rule_id") or "?")[:80],
                        str(f.get("File") or f.get("file") or "?")[:120],
                        str(f.get("StartLine") or f.get("start_line") or ""),
                    ])
                return f"Gitleaks findings ({len(findings)} total)", rows

            if "results" in data and isinstance(data["results"], dict):
                failed = data["results"].get("failed_checks") or []
                rows = []
                for c in failed[:limit]:
                    rows.append([
                        str(c.get("check_id", "?"))[:40],
                        str(c.get("check_name", ""))[:80],
                        str(c.get("resource") or c.get("file_path") or "")[:100],
                    ])
                return f"Checkov failed checks ({len(failed)} total)", rows

            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                vulns = data["vulnerabilities"]
                rows = []
                for v in vulns[:limit]:
                    rows.append([
                        str(v.get("severity", "?")),
                        str(v.get("id") or v.get("title") or "?")[:80],
                        str(v.get("packageName") or v.get("package") or "?")[:80],
                    ])
                return f"Snyk vulnerabilities ({len(vulns)} total)", rows

            if data.get("stage"):
                rows = [[k, str(v), ""] for k, v in data.items()]
                return f"Stage meta ({path.name})", rows

        return path.name, [["(unrecognized JSON shape)", "", ""]]

    if suffix in {".html", ".htm", ".md"}:
        text = path.read_text(encoding="utf-8", errors="replace")
        rows = []
        for line in text.splitlines():
            u = line.upper()
            if any(k in u for k in ("FAIL-NEW", "WARN-NEW", "PASS:", "ALERT", "RISK", "WARN-")):
                rows.append([line.strip()[:200], "", ""])
                if len(rows) >= limit:
                    break
        if not rows:
            rows = [[f"See artifact file {path.name} ({len(text):,} bytes)", "", ""]]
        return f"ZAP / text report highlights ({path.name})", rows

    return path.name, [[f"{path.stat().st_size:,} bytes", "", ""]]


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for r in rows:
        cells = [(c or "").replace("|", "\\|").replace("\n", " ") for c in r]
        while len(cells) < len(headers):
            cells.append("")
        lines.append("| " + " | ".join(cells[: len(headers)]) + " |")
    return "\n".join(lines)


def build_markdown(results: dict, artifacts_dir: Path, meta: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    repo = meta.get("repository", "")
    run_url = meta.get("run_url", "")
    sha = (meta.get("sha") or "")[:12]
    target = meta.get("target_url", "")

    out: list[str] = [
        "# SafeCI Pipeline — Full Findings Report",
        "",
        f"- **Generated:** {now}",
        f"- **Repository:** `{repo}`",
        f"- **Commit:** `{sha}`",
    ]
    if target:
        out.append(f"- **DAST target:** {target}")
    if run_url:
        out.append(f"- **Workflow run:** {run_url}")

    out += [
        "",
        "## Where to find each scan’s assessments",
        "",
        "| Stage | Artifact / dashboard | What you get |",
        "|-------|----------------------|--------------|",
    ]
    for s in STAGES:
        out.append(f"| {s['title']} | {s['where']} | {s['kind']} findings |")
        if s.get("dashboard"):
            out.append(f"| ↳ dashboard | {s['dashboard']} | Live UI |")

    out += [
        "",
        "## Executive summary",
        "",
        "| Stage | Type | Job status |",
        "|-------|------|------------|",
    ]
    for s in STAGES:
        out.append(f"| {s['title']} | {s['kind']} | `{results.get(s['id'], 'unknown')}` |")

    out += [
        "",
        "> **leaky-repo note:** planted fake secrets are fixtures. Gitleaks findings are expected "
        "and soft-failed so the Pipeline can still publish this report.",
        "",
        "---",
        "",
    ]

    for s in STAGES:
        sid = s["id"]
        status = results.get(sid, "unknown")
        out += [
            f"## {s['title']}",
            "",
            f"- **Status:** `{status}`",
            f"- **Type:** {s['kind']}",
            f"- **Scope:** {s['scope']}",
            f"- **Where to review:** {s['where']}",
            f"- **Notes:** {s['expected']}",
            "",
        ]
        files = stage_files(s, artifacts_dir)
        # skip pure meta if we have better files
        detail_files = [f for f in files if f.name != "stage-meta.json"] or files
        if not detail_files:
            out.append("_No artifact detail uploaded for this stage._\n")
        for f in detail_files[:6]:
            if f.name == "stage-meta.json" and len(detail_files) > 1:
                continue
            title, rows = extract_findings_rows(f, limit=250)
            if not rows:
                continue
            # choose headers by stage
            if sid == "gitleaks":
                headers = ["Rule", "File", "Line"]
            elif sid == "checkov":
                headers = ["Check ID", "Name", "Resource"]
            elif sid == "snyk":
                headers = ["Severity", "ID / Title", "Package"]
            else:
                headers = ["Detail", "", ""]
            out.append(f"### {title}")
            out.append("")
            out.append(md_table(headers, rows))
            out.append("")
        out.append("---\n")

    out += [
        "## Next steps",
        "",
        "1. Download **safeci-full-report.pdf** from the workflow Artifacts.",
        "2. Download per-stage `safeci-*` zips for raw JSON/HTML.",
        "3. Open SonarCloud / Snyk dashboards for interactive triage.",
        "4. Score secrets coverage with `python safeci.py benchmark` vs `.leaky-meta/secrets.csv`.",
        "",
    ]
    return "\n".join(out)


def markdown_to_simple_html(md: str) -> str:
    """Minimal Markdown→HTML good enough for PDF (tables, headings, lists, code)."""
    lines = md.splitlines()
    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'/>",
        "<style>",
        "body{font-family:Helvetica,Arial,sans-serif;font-size:11pt;color:#111;margin:24px;}",
        "h1{font-size:20pt;border-bottom:2px solid #333;padding-bottom:6px;}",
        "h2{font-size:14pt;margin-top:22px;color:#222;}",
        "h3{font-size:12pt;margin-top:14px;}",
        "table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:9pt;}",
        "th,td{border:1px solid #999;padding:4px 6px;vertical-align:top;word-wrap:break-word;}",
        "th{background:#eee;text-align:left;}",
        "code{font-family:Consolas,monospace;font-size:9pt;}",
        "blockquote{border-left:3px solid #888;margin:8px 0;padding:4px 10px;color:#333;}",
        "a{color:#0645ad;}",
        "</style></head><body>",
    ]
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("| ") and i + 1 < len(lines) and re.match(r"^\|\s*-+", lines[i + 1]):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                if re.match(r"^\|\s*-+", lines[i]):
                    i += 1
                    continue
                cells = [c.strip() for c in lines[i].strip("|").split("|")]
                rows.append(cells)
                i += 1
            if rows:
                html_parts.append("<table>")
                html_parts.append("<tr>" + "".join(f"<th>{xml_escape(c)}</th>" for c in rows[0]) + "</tr>")
                for r in rows[1:]:
                    html_parts.append("<tr>" + "".join(f"<td>{xml_escape(c)}</td>" for c in r) + "</tr>")
                html_parts.append("</table>")
            continue
        if line.startswith("# "):
            html_parts.append(f"<h1>{xml_escape(line[2:])}</h1>")
        elif line.startswith("## "):
            html_parts.append(f"<h2>{xml_escape(line[3:])}</h2>")
        elif line.startswith("### "):
            html_parts.append(f"<h3>{xml_escape(line[4:])}</h3>")
        elif line.startswith("> "):
            html_parts.append(f"<blockquote>{xml_escape(line[2:])}</blockquote>")
        elif line.startswith("- "):
            html_parts.append("<ul>")
            while i < len(lines) and lines[i].startswith("- "):
                item = lines[i][2:]
                item = re.sub(r"`([^`]+)`", lambda m: f"<code>{xml_escape(m.group(1))}</code>", item)
                item = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", item)
                # escape leftover
                # already partially escaped via code; escape plain carefully
                html_parts.append(f"<li>{item}</li>")
                i += 1
            html_parts.append("</ul>")
            continue
        elif line.strip() == "---":
            html_parts.append("<hr/>")
        elif line.strip() == "":
            html_parts.append("<br/>")
        else:
            text = xml_escape(line)
            text = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", text)
            text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
            html_parts.append(f"<p>{text}</p>")
        i += 1
    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def write_pdf(html_doc: str, pdf_path: Path) -> None:
    try:
        from xhtml2pdf import pisa  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "xhtml2pdf is required for PDF output. Install with: pip install xhtml2pdf"
        ) from exc

    with pdf_path.open("wb") as fh:
        result = pisa.CreatePDF(html_doc, dest=fh, encoding="utf-8")
    if result.err:
        raise SystemExit(f"PDF generation failed with {result.err} error(s)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, help="JSON map of stage id -> conclusion")
    ap.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    ap.add_argument("--out", type=Path, default=Path("safeci-full-report.md"))
    ap.add_argument("--pdf", type=Path, default=Path("safeci-full-report.pdf"))
    ap.add_argument("--html", type=Path, default=Path("safeci-full-report.html"))
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
    report_md = build_markdown(results, args.artifacts_dir, meta)
    args.out.write_text(report_md, encoding="utf-8")
    print(f"Wrote {args.out} ({len(report_md):,} chars)")

    html_doc = markdown_to_simple_html(report_md)
    args.html.write_text(html_doc, encoding="utf-8")
    print(f"Wrote {args.html}")

    write_pdf(html_doc, args.pdf)
    print(f"Wrote {args.pdf} ({args.pdf.stat().st_size:,} bytes)")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report_md)
            fh.write("\n\n_PDF artifact: `safeci-full-report.pdf`_\n")
        print("Appended Markdown report to GITHUB_STEP_SUMMARY")
    return 0


if __name__ == "__main__":
    # silence unused import warning for html in some linters
    _ = html
    sys.exit(main())
