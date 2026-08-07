# Benchmark scoring (`.leaky-meta/`)

Separate from the CI pipeline, this repo ships the **original leaky-repo
benchmark harness** that scores secret scanners against the planted ground truth.
This is a distinct piece of project functionality — the pipeline *runs* scanners;
the benchmark *scores* them.

## What it does

`.leaky-meta/benchmark.sh` runs two steps:

1. `install-test-tools.sh` — installs `gitleaks` (Linux amd64 binary), plus
   `detect-secrets` and `truffleHog` via `pip`, and downloads the upstream
   `leaky-repo.toml` gitleaks config as `gitleaks-config.toml`.
2. `benchmark.py` — runs each tool over the repo, compares detections against the
   ground truth in `.leaky-meta/secrets.csv`, and writes coverage reports to
   `.leaky-meta/benchmarking/`:
   - `GITLEAKS.md`, `DETECT-SECRETS.md`, `TRUFFLEHOG.md`

Each report shows, per file: **Found/Total** detections, **False Positives**, and
overall **file coverage %** and **find coverage %**.

## Ground truth

`.leaky-meta/secrets.csv` — one row per file: `filename, risk_count,
informative_count`. Expected detections for a file = `risk_count +
informative_count`. `benchmark.py` reads this as the answer key.

## How to run

```bash
# From the repo's .leaky-meta directory (benchmark.py expects cwd='..' i.e. repo root):
cd .leaky-meta && bash benchmark.sh

# Or via the skill helper (locates .leaky-meta from the current repo):
python scripts/safeci.py benchmark
```

## Requirements & caveats

- **Linux/bash environment.** `install-test-tools.sh` downloads a `linux-amd64`
  gitleaks binary and uses `wget`/`curl`; it will not install cleanly on native
  Windows. Use WSL, Git Bash + Linux tooling, or a Linux container.
- Needs `pip` + Python (the script targets py2/py3 compat) for `detect-secrets`
  and `truffleHog`.
- **Tool-version drift:** `benchmark.py` calls `gitleaks` with legacy flags
  (`--repo-path`, `--report`, `--config=`). Modern gitleaks (v8+, the version the
  CI stage uses) changed this CLI. If gitleaks scoring errors out, either pin the
  legacy gitleaks the harness expects or update the command in `benchmark.py`.
- The benchmark is **not** wired into the GitHub Actions pipeline — it is a local
  research/scoring tool. See `interpreting-results.md` for how it relates to the
  live scanners.
