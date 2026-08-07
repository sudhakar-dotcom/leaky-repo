#!/usr/bin/env python3
"""SafeCI pipeline runner.

Parses the machine-readable stage definitions in ``reference/commands.md`` and
runs them locally, or triggers the equivalent GitHub Actions workflow via ``gh``.

The reference markdown is the single source of truth: this script never hardcodes
scanner commands, it reads them from ``reference/commands.md`` so the docs and the
executor can never drift apart.

Usage:
    python safeci.py list                       # list stages parsed from the reference
    python safeci.py run <stage>                # run one local stage (or 'all')
    python safeci.py run all --dry-run          # print commands without executing
    python safeci.py run zap --target-url URL   # override the DAST target
    python safeci.py ci [stage] [--target-url URL]   # trigger the GitHub Actions pipeline
    python safeci.py benchmark                  # score scanners vs .leaky-meta/secrets.csv

Examples:
    python safeci.py run gitleaks
    python safeci.py run all
    python safeci.py ci                         # run ALL stages in Actions
    python safeci.py ci sonarcloud              # run only the SonarCloud stage
    python safeci.py benchmark                  # run .leaky-meta/benchmark.sh
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Ensure em-dashes etc. render on Windows consoles (cp1252 by default).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# reference/commands.md sits next to this script's parent: skills/<name>/reference/
REFERENCE = Path(__file__).resolve().parent.parent / "reference" / "commands.md"

# CI-only stages have no first-class local CLI in this repo.
CI_ONLY: set[str] = set()
# Valid workflow_dispatch toggles on pipeline.yml.
CI_STAGES = {"gitleaks", "checkov", "sonarcloud", "snyk", "zap"}


class Stage:
    def __init__(self, sid, title, meta, command):
        self.id = sid
        self.title = title
        self.type = meta.get("type", "")
        self.requires = [r.strip() for r in meta.get("requires", "").split(",") if r.strip()]
        self.tool = meta.get("tool", "")
        self.command = command

    def __repr__(self):
        return f"<Stage {self.id}>"


def parse_reference(path: Path = REFERENCE) -> "dict[str, Stage]":
    """Parse reference/commands.md into an ordered {id: Stage} mapping."""
    if not path.exists():
        sys.exit(f"error: reference file not found: {path}")
    text = path.read_text(encoding="utf-8")

    # Split into level-3 sections: "### id — title"
    section_re = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)
    stages: "dict[str, Stage]" = {}
    matches = list(section_re.finditer(text))
    for i, m in enumerate(matches):
        heading = m.group(1)
        # "gitleaks — Gitleaks (secrets)"  ->  id="gitleaks", title="Gitleaks (secrets)"
        parts = re.split(r"\s+[—-]\s+", heading, maxsplit=1)
        sid = parts[0].strip()
        title = parts[1].strip() if len(parts) > 1 else sid
        body = text[m.end(): matches[i + 1].start() if i + 1 < len(matches) else len(text)]

        meta = dict(re.findall(r"^-\s*([\w]+):\s*(.+?)\s*$", body, re.MULTILINE))
        fence = re.search(r"```(?:bash|sh)?\n(.*?)```", body, re.DOTALL)
        command = fence.group(1).strip() if fence else ""
        if command:
            stages[sid] = Stage(sid, title, meta, command)
    return stages


def cmd_list(stages: "dict[str, Stage]") -> int:
    print(f"Stages defined in {REFERENCE.name}:\n")
    for s in stages.values():
        reqs = ", ".join(s.requires) or "none"
        print(f"  {s.id:<11} {s.type:<14} requires: {reqs}")
    return 0


def _check_requirements(stage: Stage) -> "list[str]":
    missing = []
    for req in stage.requires:
        if req.isupper():  # env var, e.g. SONAR_TOKEN
            if not os.environ.get(req):
                missing.append(f"env:{req}")
        elif shutil.which(req) is None:
            missing.append(f"bin:{req}")
    return missing


def run_local(stage: Stage, dry_run: bool, target_url: str | None) -> int:
    env = os.environ.copy()
    if target_url:
        env["TARGET_URL"] = target_url

    missing = _check_requirements(stage)
    if missing and not dry_run:
        print(f"! {stage.id}: skipped — missing prerequisites: {', '.join(missing)}")
        print(f"  command was: {stage.command}")
        return 0  # non-fatal: expected on machines without every tool

    print(f"\n=== {stage.id} — {stage.title} ===")
    print(f"$ {stage.command}")
    if dry_run:
        return 0

    # $PWD / ${TARGET_URL} expansion is done by the shell.
    proc = subprocess.run(stage.command, shell=True, env=env)
    print(f"--- {stage.id} exited with code {proc.returncode} "
          f"(findings are EXPECTED on this benchmark repo)")
    return proc.returncode


def cmd_run(args, stages: "dict[str, Stage]") -> int:
    if args.stage == "all":
        selected = list(stages.values())
    elif args.stage in stages:
        selected = [stages[args.stage]]
    elif args.stage in CI_ONLY:
        return sys.exit(f"'{args.stage}' has no local runner — use: python safeci.py ci {args.stage}")
    else:
        valid = ", ".join(list(stages) + ["all"])
        return sys.exit(f"unknown stage '{args.stage}'. Choose from: {valid}")

    rc = 0
    for stage in selected:
        rc = run_local(stage, args.dry_run, args.target_url) or rc
    return 0  # local runs never fail the wrapper; findings are the goal


def find_leaky_meta(start: Path | None = None) -> Path | None:
    """Walk up from cwd to find the repo's .leaky-meta/benchmark.sh.

    Resolved against the working directory (the actual leaky-repo), NOT this
    script's location — when installed as a plugin the script lives elsewhere.
    """
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if (d / ".leaky-meta" / "benchmark.sh").exists():
            return d / ".leaky-meta"
    return None


def cmd_benchmark(args) -> int:
    meta = find_leaky_meta()
    if meta is None:
        sys.exit("error: .leaky-meta/benchmark.sh not found from the current directory. "
                 "Run this from inside the leaky-repo checkout.")
    if shutil.which("bash") is None:
        sys.exit("error: 'bash' not found. The benchmark harness is bash/Linux only "
                 "(use WSL, Git Bash + Linux tooling, or a container). See reference/benchmark.md.")

    print(f"$ (cd {meta}) && bash benchmark.sh")
    print("  note: installs gitleaks/detect-secrets/truffleHog and writes reports to "
          ".leaky-meta/benchmarking/*.md (Linux/pip required).")
    if args.dry_run:
        return 0
    return subprocess.run(["bash", "benchmark.sh"], cwd=str(meta)).returncode


def cmd_ci(args) -> int:
    if shutil.which("gh") is None:
        sys.exit("error: GitHub CLI 'gh' not found. Install it or trigger the workflow from the Actions tab.")

    cmd = ["gh", "workflow", "run", "pipeline.yml"]
    if args.stage and args.stage != "all":
        if args.stage not in CI_STAGES:
            sys.exit(f"unknown CI stage '{args.stage}'. Choose from: {', '.join(sorted(CI_STAGES))}, all")
        cmd += ["-f", "run_all=false", "-f", f"{args.stage}=true"]
    if args.target_url:
        cmd += ["-f", f"target_url={args.target_url}"]

    print("$ " + " ".join(cmd))
    if args.dry_run:
        return 0
    return subprocess.run(cmd).returncode


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="SafeCI pipeline runner (reads reference/commands.md).")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list stages parsed from the reference file")

    pr = sub.add_parser("run", help="run stage(s) locally")
    pr.add_argument("stage", help="stage id or 'all'")
    pr.add_argument("--dry-run", action="store_true", help="print commands without executing")
    pr.add_argument("--target-url", help="DAST target URL override (zap)")

    pc = sub.add_parser("ci", help="trigger the GitHub Actions pipeline via gh")
    pc.add_argument("stage", nargs="?", default="all", help="stage id or 'all' (default: all)")
    pc.add_argument("--dry-run", action="store_true", help="print the gh command without running it")
    pc.add_argument("--target-url", help="DAST target URL override (zap)")

    pb = sub.add_parser("benchmark", help="score scanners vs .leaky-meta/secrets.csv ground truth")
    pb.add_argument("--dry-run", action="store_true", help="print the command without running it")

    args = p.parse_args(argv)

    if args.command == "ci":
        return cmd_ci(args)
    if args.command == "benchmark":
        return cmd_benchmark(args)

    stages = parse_reference()
    if args.command == "list":
        return cmd_list(stages)
    if args.command == "run":
        return cmd_run(args, stages)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
