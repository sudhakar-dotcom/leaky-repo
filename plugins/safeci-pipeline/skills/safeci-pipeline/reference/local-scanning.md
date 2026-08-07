# Running scanners locally (no CI)

These commands reproduce each stage on the working tree without pushing to
GitHub. The canonical, machine-readable copy of these commands lives in
`commands.md` (parsed by `scripts/safeci.py`). Keep the two in sync.

Prerequisites: Docker for stages 1, 2, 3, 5; `npx`/Node for stage 4; `gh` for
CI triggering. Run `scripts/check_env.py` to verify what is installed.

## Stage 1 — Gitleaks (secrets)

Expect **many** findings — that is the entire point of this benchmark repo.

```bash
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --source=/repo -v
```

## Stage 2 — Checkov (IaC)

```bash
docker run --rm -v "$PWD:/repo" bridgecrew/checkov -d /repo --compact
```

## Stage 3 — SonarCloud (SAST)

Needs `SONAR_TOKEN` in the environment plus network access to sonarcloud.io.

```bash
docker run --rm -e SONAR_TOKEN -e SONAR_HOST_URL=https://sonarcloud.io -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli
```

## Stage 4 — Snyk (dependencies)

No `package.json` exists in this repo, so this is effectively a no-op here.

```bash
npx snyk test --all-projects --severity-threshold=high
```

## Stage 5 — ZAP baseline (DAST)

Scans a **live URL**, not the repo. Change the target as needed.

```bash
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://ginandjuice.shop
```

## Stage 6 — Dastardly (DAST)

Dastardly runs as a GitHub Action (`PortSwigger/dastardly-github-action`) and has
no first-class local CLI; trigger it via the pipeline instead. See
`github-actions.md`.
