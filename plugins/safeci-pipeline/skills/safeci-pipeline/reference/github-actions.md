# Running via GitHub Actions

The pipeline auto-triggers on push/PR to `main`/`master` and weekly
(cron `0 6 * * 1`, Mondays 06:00 UTC). To trigger it manually use the GitHub
CLI (`gh`).

## Trigger the pipeline

```bash
# Run ALL stages
gh workflow run pipeline.yml

# Run a single stage (turn off run_all, enable the one you want)
gh workflow run pipeline.yml -f run_all=false -f gitleaks=true

# DAST target override (ZAP / Dastardly)
gh workflow run pipeline.yml -f run_all=false -f zap=true -f target_url=https://ginandjuice.shop
```

Dispatch input flags: `run_all` (default `true`), `gitleaks`, `checkov`,
`sonarcloud`, `snyk`, `zap`, `dastardly`, and `target_url`.

## Watch and inspect runs

```bash
# Watch the most recent pipeline run
gh run watch "$(gh run list --workflow=pipeline.yml --limit 1 --json databaseId -q '.[0].databaseId')"

# View full logs of the latest run
gh run view --log

# List recent runs
gh run list --workflow=pipeline.yml --limit 5
```

## Required repository secrets

Set once under **Settings → Secrets and variables → Actions**, or via CLI:

```bash
gh secret set SONAR_TOKEN   # required — SonarCloud stage fails fast without it
gh secret set SNYK_TOKEN    # optional — Snyk stage soft-fails without it
```

- `GITHUB_TOKEN` is provided automatically by Actions (used by Gitleaks and ZAP).
- SonarCloud project config lives in `sonar-project.properties`. Its
  `sonar.projectKey` and `sonar.organization` **must match your SonarCloud
  project**, or stage 3 will fail.
