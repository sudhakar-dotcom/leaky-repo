# SafeCI full report

After every Pipeline run, the **SafeCI full report** job:

1. Downloads `safeci-*` artifacts from each stage
2. Builds one Markdown report (`safeci-full-report.md`)
3. Writes it to the job **Summary** tab
4. Uploads artifact **`safeci-full-report`**

## Where to find it

1. Open the Pipeline run → job **SafeCI full report**
2. Open the **Summary** tab for the rendered report
3. Or **Artifacts** → download `safeci-full-report`

Per-stage raw outputs are also uploaded as:
`safeci-gitleaks`, `safeci-checkov`, `safeci-sonarcloud`, `safeci-snyk`, `safeci-zap`.

## Local regeneration

```bash
python .github/scripts/generate-safeci-report.py \
  --results results.json \
  --artifacts-dir artifacts \
  --out safeci-full-report.md
```

`results.json` shape:

```json
{
  "gitleaks": "failure",
  "checkov": "success",
  "sonarcloud": "success",
  "snyk": "success",
  "zap": "success"
}
```

## How to interpret (leaky-repo)

| Stage | Good outcome for this benchmark |
|-------|----------------------------------|
| Gitleaks | Findings / job fail is **expected** (planted secrets) |
| Checkov | Soft-fail; review IaC findings as informational |
| SonarCloud | Use the linked dashboard for hotspots/bugs |
| Snyk | Limited — no real manifests in this fixture repo |
| ZAP | WARNs on demo `target_url` are about that live app |

Score secret scanners against `.leaky-meta/secrets.csv` via `python safeci.py benchmark`.
