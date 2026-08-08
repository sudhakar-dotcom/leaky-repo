# SafeCI full report (PDF)

After every Pipeline run, the **SafeCI full report** job builds:

- `safeci-full-report.pdf` — **primary deliverable** (all stage findings)
- `safeci-full-report.html` — same content in HTML
- `safeci-full-report.md` — source markdown (optional)

## Where to download

1. Actions → latest **Pipeline** run  
2. **Artifacts** → `safeci-full-report` → download zip → open **`safeci-full-report.pdf`**  
3. Or open job **SafeCI full report** → Summary tab (markdown preview)

## Where to find each scan’s vulnerability / findings assessments

| Stage | In GitHub Actions | External dashboard |
|-------|-------------------|--------------------|
| **1 Gitleaks** (secrets) | Artifact `safeci-gitleaks` → `gitleaks-report.json` + PDF section 1 | — |
| **2 Checkov** (IaC) | Artifact `safeci-checkov` → `results_json.json` + PDF section 2 | — |
| **3 SonarCloud** (SAST) | Artifact `safeci-sonarcloud` (meta) + **full issues UI** | [SonarCloud Issues](https://sonarcloud.io/project/issues?id=sudhakar-dotcom_leaky-repo) · [Hotspots](https://sonarcloud.io/project/security_hotspots?id=sudhakar-dotcom_leaky-repo) · [Overview](https://sonarcloud.io/project/overview?id=sudhakar-dotcom_leaky-repo) |
| **4 Snyk** (deps) | Artifact `safeci-snyk` → `snyk-report.json` + PDF section 4 | [Snyk Projects](https://app.snyk.io) — project `leaky-repo-snyk-demo` after `snyk monitor` (needs root `package.json`) |
| **5 ZAP** (DAST) | Artifact `safeci-zap` → `report_html.html` / `report_md.md` + PDF section 5 | Live scan of `target_url` only |

## Gitleaks “failure” on this repo

`leaky-repo` is a **secrets benchmark**. Gitleaks *will* detect planted secrets.
The stage is **soft-failed** (job succeeds) so the Pipeline can still publish the PDF.
Treat Gitleaks findings as expected detections to score against `.leaky-meta/secrets.csv`,
not as production defects to remediate.

## Local regeneration

```bash
pip install xhtml2pdf
python .github/scripts/generate-safeci-report.py \
  --results results.json \
  --artifacts-dir artifacts \
  --out safeci-full-report.md \
  --html safeci-full-report.html \
  --pdf safeci-full-report.pdf
```
