# Pipeline stages

The SafeCI pipeline runs six security scanners sequentially. It is defined in
`.github/workflows/pipeline.yml`; each stage is also a standalone reusable
workflow that can run alone via `workflow_dispatch`.

| # | Stage      | Type         | Workflow file          | Required secret                                   |
|---|------------|--------------|------------------------|---------------------------------------------------|
| 1 | Gitleaks   | Secrets      | `gitleaks.yml`         | `GITHUB_TOKEN` (auto)                             |
| 2 | Checkov    | IaC          | `checkov.yml`          | none                                              |
| 3 | SonarCloud | SAST         | `sonarqube_cloud.yml`  | `SONAR_TOKEN` (required — fails fast if missing)  |
| 4 | Snyk       | Dependencies | `snyk.yml`             | `SNYK_TOKEN` (soft-fail; no `package.json` here)  |
| 5 | ZAP        | DAST baseline| `zap_baseline.yml`     | `GITHUB_TOKEN` (auto)                             |
| 6 | Dastardly  | DAST         | `dastardly.yml`        | none                                              |

`pr-quality-gate.yml` is a separate workflow that runs Gitleaks + Snyk +
SonarCloud + Checkov on every pull request and posts a results comment.

## Stage notes

- **Stages 1–4 are SAST/secrets/IaC** — they scan the repository source tree.
  On this benchmark repo they are *expected* to produce findings.
- **Stages 5–6 are DAST** — they scan a **running web target** (`target_url`,
  default `https://ginandjuice.shop`), not the repo files. Overriding
  `target_url` points them at a different live application.

## Execution order and gating

Stages are chained with `needs:` so they run one after another. Most use
`always() && !cancelled()` so a later stage still runs even if an earlier one
reports findings. The `summary` job prints a per-stage results table at the end.

Pinned tool versions live in each stage's own workflow file (bump the `uses:`
ref there). See `github-actions.md` for triggering and `local-scanning.md` for
running the same tools without CI.
