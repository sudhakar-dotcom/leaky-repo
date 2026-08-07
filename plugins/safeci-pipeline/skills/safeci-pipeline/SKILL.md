---
name: safeci-pipeline
description: Run and manage the SafeCI DevSecOps pipeline for the leaky-repo secrets benchmark. Use when asked to execute the security pipeline, run a specific scan stage (Gitleaks, Checkov, SonarCloud, Snyk, ZAP), trigger the GitHub Actions workflow, scan the repo locally, configure required CI secrets, or interpret scan results.
---

# SafeCI Pipeline

A 5-stage DevSecOps pipeline that runs security scanners over this repository.
`leaky-repo` is a **benchmark of intentionally planted, fake secrets**, so
scanners are *expected* to fire. The goal is to run the scanners and report
coverage — **not** to "fix" the secrets (they are test fixtures).

The repo has **two functional layers**:
- **CI pipeline** (`.github/workflows/`) — *runs* scanners. Stages: **1** Gitleaks
  (secrets) → **2** Checkov (IaC) → **3** SonarCloud (SAST) → **4** Snyk (deps) →
  **5** ZAP (DAST). Defined in `pipeline.yml`; each is
  also a standalone reusable workflow.
- **Benchmark harness** (`.leaky-meta/`) — *scores* scanners (gitleaks,
  detect-secrets, truffleHog) against the ground truth in `secrets.csv` and
  writes coverage reports. See `reference/benchmark.md`.

## Quick start

Run the helper scripts (they read stage definitions from `reference/commands.md`,
the single source of truth):

```bash
# From this skill's scripts/ directory:
python scripts/check_env.py            # what's installed / which stages can run
python scripts/safeci.py list          # list stages
python scripts/safeci.py run gitleaks  # run one stage locally (docker)
python scripts/safeci.py run all       # run all local stages
python scripts/safeci.py run all --dry-run   # print commands only
python scripts/safeci.py ci            # trigger ALL stages in GitHub Actions (needs gh)
python scripts/safeci.py ci sonarcloud # trigger a single CI stage
python scripts/safeci.py benchmark     # score scanners vs secrets.csv (Linux/bash)
```

## Reference (read the relevant file for detail)

- `reference/pipeline-stages.md` — the six stages, workflow files, required secrets.
- `reference/github-actions.md` — trigger, watch, and inspect runs with `gh`; secrets setup.
- `reference/local-scanning.md` — human-readable local scan commands per stage.
- `reference/commands.md` — machine-readable stage definitions consumed by the scripts.
- `reference/interpreting-results.md` — findings are expected; ground truth in `.leaky-meta/`.
- `reference/benchmark.md` — the `.leaky-meta/` scoring harness (gitleaks / detect-secrets / truffleHog vs `secrets.csv`).

## Key rules

- **Findings are the point.** A clean scan means the tool under-performed. Score
  detections against `.leaky-meta/secrets.csv`.
- **Never remediate** the planted secrets — they are fixtures. Only change them
  if the user explicitly asks.
- **SonarCloud needs `SONAR_TOKEN`** and a matching `sonar.projectKey` /
  `sonar.organization` in `sonar-project.properties`, or stage 3 fails fast.
- **Stages 5–6 are DAST** — they scan a live `target_url`, not the repo source.
