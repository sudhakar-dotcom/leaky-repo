#!/usr/bin/env python3
"""Verify prerequisites for running the SafeCI pipeline stages.

Reads the required tools/secrets straight from ``reference/commands.md`` (via the
same parser as ``safeci.py``) and reports what is present or missing, so you know
which stages will run locally before you start.

Usage:
    python check_env.py
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safeci import parse_reference  # noqa: E402


def status(ok: bool) -> str:
    return "OK  " if ok else "MISS"


def main() -> int:
    stages = parse_reference()

    # Collect the union of requirements across all stages, plus CI + benchmark tooling.
    bins = {"docker", "npx", "gh", "bash", "pip"}  # bash+pip: .leaky-meta benchmark harness
    envs = {"SONAR_TOKEN", "SNYK_TOKEN"}
    for s in stages.values():
        for req in s.requires:
            (envs if req.isupper() else bins).add(req)

    print("Tools:")
    for b in sorted(bins):
        present = shutil.which(b) is not None
        print(f"  [{status(present)}] {b}")

    print("\nSecrets / env vars:")
    for e in sorted(envs):
        present = bool(os.environ.get(e))
        note = "" if present else "  (set for its stage; SONAR_TOKEN is required for SonarCloud)"
        print(f"  [{status(present)}] {e}{note}")

    def is_missing(req: str) -> bool:
        if req.isupper():
            return not os.environ.get(req)
        return shutil.which(req) is None

    print("\nRunnable local stages:")
    for s in stages.values():
        missing = [r for r in s.requires if is_missing(r)]
        state = "ready" if not missing else f"blocked ({', '.join(missing)})"
        print(f"  {s.id:<11} {state}")

    print("\nBenchmark harness (.leaky-meta):")
    bench_missing = [b for b in ("bash", "pip") if shutil.which(b) is None]
    if bench_missing:
        print(f"  blocked ({', '.join(bench_missing)}) — Linux/bash + pip required; "
              "use WSL or a container. See reference/benchmark.md")
    else:
        print("  ready — python safeci.py benchmark")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
