# Commands (machine-readable)

This file is the single source of truth consumed by `scripts/safeci.py`. Each
stage is a level-3 heading whose text is `<id> — <title>`, followed by metadata
bullets and a single fenced code block holding the local command to run.

The parser reads, per stage:
- `id`   — the slug in the heading before the em dash (e.g. `gitleaks`)
- `title`, `type`, `requires`, `tool` — from the `- key: value` bullets
- `command` — the first fenced code block under the heading

Keep the human-readable narrative in `local-scanning.md`; keep this file
strictly structured so the parser stays simple.

### gitleaks — Gitleaks (secrets)
- type: SAST/secrets
- requires: docker
- tool: zricethezav/gitleaks

```bash
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --source=/repo -v
```

### checkov — Checkov (IaC)
- type: IaC
- requires: docker
- tool: bridgecrew/checkov

```bash
docker run --rm -v "$PWD:/repo" bridgecrew/checkov -d /repo --compact
```

### sonarcloud — SonarCloud (SAST)
- type: SAST
- requires: docker,SONAR_TOKEN
- tool: sonarsource/sonar-scanner-cli

```bash
docker run --rm -e SONAR_TOKEN -e SONAR_HOST_URL=https://sonarcloud.io -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli
```

### snyk — Snyk (dependencies)
- type: dependencies
- requires: npx
- tool: snyk

```bash
npx snyk test --all-projects --severity-threshold=high
```

### zap — ZAP baseline (DAST)
- type: DAST
- requires: docker
- tool: ghcr.io/zaproxy/zaproxy

```bash
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t ${TARGET_URL:-https://ginandjuice.shop}
```
