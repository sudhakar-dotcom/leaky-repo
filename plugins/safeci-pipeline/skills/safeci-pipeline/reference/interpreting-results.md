# Interpreting results

## Findings are expected

`leaky-repo` deliberately contains ~40 fake secrets (see the "Secrets" table in
the repo `README.md`). A **good** run *detects* them — a clean run means the
scanner is under-performing, not that the repo is safe.

## Ground truth for benchmarking

- `.leaky-meta/secrets.csv` — canonical list of planted secrets (ground truth).
- `.leaky-meta/benchmarking/` — per-tool writeups (DETECT-SECRETS, GITLEAKS,
  GITROB, TRUFFLEHOG) showing expected coverage.

To score a tool, compare its detections against `secrets.csv`: count true
positives (planted secrets found), false negatives (missed), and false positives
(non-secrets flagged).

## Do not "remediate"

The planted secrets are **test fixtures**. Do not remove, rotate, redact, or
`git filter-branch` them away — doing so destroys the benchmark. Only modify
them if the user explicitly asks to change the fixture set.

## Scan scope notes

- `.git/` and `.leaky-meta/` are excluded from SonarCloud via
  `sonar-project.properties` (`sonar.exclusions`).
- Stage 5 (ZAP) reports on the live `target_url`, so its findings
  describe that web app — they are unrelated to the secrets in this repo.
