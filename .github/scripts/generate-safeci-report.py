#!/usr/bin/env python3
"""Generate a single SafeCI pipeline report from stage results + optional artifacts.

Used by the Pipeline ``report`` job. Also runnable locally:

    python generate-safeci-report.py \\
      --results results.json \\
      --artifacts-dir artifacts \\
      --out safeci-full-report.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


STAGES = [
    {
        "id": "gitleaks",
        "title": "1 · Gitleaks",
        "kind": "Secrets",
        "scope": "Repository history & working tree",
        "dashboard": None,
        "expected": "Many findings — this repo is a secrets benchmark fixture.",
        "artifact_hints": ["gitleaks*.json", "gitleaks*.sarif", "*.json"],
    },
    {
        "id": "checkov",
        "title": "2 · Checkov",
        "kind": "IaC",
        "scope": "Infrastructure-as-code / config under repo root",
        "dashboard": None,
        "expected": "Soft-fail enabled; findings are informational for this fixture repo.",
        "artifact_hints": ["results_json.json", "checkov*.json", "*.json"],
    },
    {
        "id": "sonarcloud",
        "title": "3 · SonarCloud",
        "kind": "SAST",
        "scope": "Source code quality & security hotspots",
        "dashboard": "https://sonarcloud.io/project/overview?id=sudhakar-dotcom_leaky-repo",
        "expected": "Open the SonarCloud dashboard for issue breakdowns and quality gate.",
        "artifact_hints": ["sonar*.json", "*.json"],
    },
    {
        "id": "snyk",
        "title": "4 · Snyk",
        "kind": "Dependencies",
        "scope": "Manifests (package.json / requirements / etc.)",
        "dashboard": "https://app.snyk.io",
        "expected": "This repo has no real dependency manifests — soft-fail / limited coverage.",
        "artifact_hints": ["snyk*.json", "*.json"],
    },
    {
        "id": "zap",
        "title": "5 · ZAP",
        "kind": "DAST",
        "scope": "Live target_url (not repo files)",
        "dashboard": None,
        "expected": "WARN findings on ginandjuice.shop are expected for a demo DAST target.",
        "artifact_hints": ["report_html.html", "report_md.md", "zap*.html", "*.html", "*.md"],
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
    # de-dupe preserving order
    seen = set()
    out = []
    for p in found:
        if p.is_file() and p.resolve() not in seen:
            seen.add(p.resolve())
            out.append(p)
    return out


def summarize_json(path: Path, limit: int = 40) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return f"_Could not parse JSON ({exc})_\n"

    lines: list[str] = []
    if isinstance(data, dict):
        # Gitleaks-style
        if "findings" in data and isinstance(data["findings"], list):
            findings = data["findings"]
            lines.append(f"- Findings count: **{len(findings)}**")
            for f in findings[:limit]:
                rule = f.get("RuleID") or f.get("rule_id") or f.get("check_id") or "?"
                file_ = f.get("File") or f.get("file") or f.get("filename") or "?"
                lines.append(f"  - `{rule}` @ `{file_}`")
            if len(findings) > limit:
                lines.append(f"  - …and {len(findings) - limit} more")
            return "\n".join(lines) + "\n"

        # Checkov-style
        if "results" in data and isinstance(data["results"], dict):
            failed = data["results"].get("failed_checks") or []
            passed = data["results"].get("passed_checks") or []
            lines.append(f"- Failed checks: **{len(failed)}**")
            lines.append(f"- Passed checks: **{len(passed)}**")
            for c in failed[:limit]:
                cid = c.get("check_id", "?")
                name = c.get("check_name", "")
                resource = c.get("resource") or c.get("file_path") or ""
                lines.append(f"  - `{cid}` {name} — `{resource}`")
            if len(failed) > limit:
                lines.append(f"  - …and {len(failed) - limit} more")
            return "\n".join(lines) + "\n"

        # Snyk-style
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            vulns = data["vulnerabilities"]
            lines.append(f"- Vulnerabilities: **{len(vulns)}**")
            for v in vulns[:limit]:
                lines.append(
                    f"  - [{v.get('severity', '?')}] `{v.get('id', '?')}` "
                    f"{v.get('title', '')} in `{v.get('packageName') or v.get('package', '?')}`"
                )
            if len(vulns) > limit:
                lines.append(f"  - …and {len(vulns) - limit} more")
            return "\n".join(lines) + "\n"

        # Generic meta
        if "stage" in data or "status" in data:
            for k in ("stage", "status", "conclusion", "target_url", "dashboard", "note", "message"):
                if k in data and data[k] not in (None, ""):
                    lines.append(f"- **{k}**: {data[k]}")
            return ("\n".join(lines) + "\n") if lines else "```json\n" + json.dumps(data, indent=2)[:4000] + "\n```\n"

    if isinstance(data, list):
        lines.append(f"- Records: **{len(data)}**")
        for item in data[: min(10, limit)]:
            lines.append(f"  - `{json.dumps(item)[:200]}`")
        return "\n".join(lines) + "\n"

    return "```json\n" + json.dumps(data, indent=2)[:4000] + "\n```\n"


def summarize_html_or_md(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    # Pull ZAP-style summary lines if present
    interesting = []
    for line in text.splitlines():
        u = line.upper()
        if any(k in u for k in ("FAIL-NEW", "WARN-NEW", "PASS:", "ALERTS", "RISK")):
            interesting.append(line.strip())
    if interesting:
        return "\n".join(f"- `{x}`" for x in interesting[:30]) + "\n"
    # Fall back to size note
    return f"- Report file `{path.name}` ({len(text):,} bytes). Download the artifact for full detail.\n"


def stage_section(stage: dict, results: dict, artifacts_root: Path) -> str:
    sid = stage["id"]
    status = results.get(sid, "unknown")
    badge = {
        "success": "PASS",
        "failure": "FAIL",
        "cancelled": "CANCELLED",
        "skipped": "SKIPPED",
    }.get(status, status.upper() if isinstance(status, str) else str(status))

    lines = [
        f"## {stage['title']}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Status | **{badge}** (`{status}`) |",
        f"| Type | {stage['kind']} |",
        f"| Scope | {stage['scope']} |",
        f"| Interpretation | {stage['expected']} |",
    ]
    if stage.get("dashboard"):
        lines.append(f"| Dashboard | {stage['dashboard']} |")
    lines.append("")

    stage_dir = artifacts_root / f"safeci-{sid}"
    # Also accept flat / nested download layouts from actions/download-artifact
    candidates = [stage_dir, artifacts_root / sid, artifacts_root]
    files: list[Path] = []
    for root in candidates:
        files = find_files(root, stage["artifact_hints"])
        # Prefer files under safeci-<id> if present
        if root == stage_dir and files:
            break
        if root.name.startswith("safeci") and files:
            break
    # If multiple roots matched loosely, prefer those under safeci-<id>
    preferred = [p for p in files if f"safeci-{sid}" in str(p).replace("\\", "/")]
    if preferred:
        files = preferred

    if not files:
        # Try any file under safeci-<id>
        if stage_dir.exists():
            files = [p for p in stage_dir.rglob("*") if p.is_file()][:20]

    if files:
        lines.append("### Findings / artifact summary")
        lines.append("")
        for f in files[:8]:
            lines.append(f"**`{f.name}`**")
            if f.suffix.lower() == ".json":
                lines.append(summarize_json(f))
            elif f.suffix.lower() in {".html", ".htm", ".md"}:
                lines.append(summarize_html_or_md(f))
            else:
                size = f.stat().st_size
                lines.append(f"- Attached ({size:,} bytes)\n")
    else:
        lines.append("_No detailed artifact uploaded for this stage (status only)._")
        lines.append("")

    return "\n".join(lines)


def build_report(results: dict, artifacts_dir: Path, meta: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    repo = meta.get("repository", os.environ.get("GITHUB_REPOSITORY", "unknown"))
    run_url = meta.get("run_url", "")
    sha = meta.get("sha", os.environ.get("GITHUB_SHA", ""))[:12]
    target = meta.get("target_url", os.environ.get("SAFECI_TARGET_URL", ""))

    passed = sum(1 for s in STAGES if results.get(s["id"]) == "success")
    failed = sum(1 for s in STAGES if results.get(s["id"]) == "failure")
    skipped = sum(1 for s in STAGES if results.get(s["id"]) == "skipped")
    other = len(STAGES) - passed - failed - skipped

    out: list[str] = [
        "# SafeCI Pipeline — Full Scan Report",
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
        "## Executive summary",
        "",
        "| Stage | Type | Status |",
        "|-------|------|--------|",
    ]
    for s in STAGES:
        st = results.get(s["id"], "unknown")
        out.append(f"| {s['title']} | {s['kind']} | `{st}` |")

    out += [
        "",
        f"**Totals:** {passed} passed · {failed} failed · {skipped} skipped · {other} other",
        "",
        "> **Note:** `leaky-repo` intentionally contains fake secrets. Secret/SAST findings "
        "are expected and should be scored against `.leaky-meta/secrets.csv`, not \"fixed\".",
        "",
        "---",
        "",
    ]

    for s in STAGES:
        out.append(stage_section(s, results, artifacts_dir))
        out.append("---")
        out.append("")

    out += [
        "## Next steps",
        "",
        "1. Download this report + stage artifacts from the workflow run's **Artifacts** section.",
        "2. For secrets coverage scoring, run `python safeci.py benchmark` (see SafeCI skill).",
        "3. Review SonarCloud / Snyk dashboards linked above for trend history.",
        "4. Treat ZAP WARNs on the demo DAST target as target-app issues, not repo secrets.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, help="JSON map of stage id -> conclusion")
    ap.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    ap.add_argument("--out", type=Path, default=Path("safeci-full-report.md"))
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
    report = build_report(results, args.artifacts_dir, meta)
    args.out.write_text(report, encoding="utf-8")
    print(f"Wrote {args.out} ({len(report):,} chars)")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)
            fh.write("\n")
        print("Appended report to GITHUB_STEP_SUMMARY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
