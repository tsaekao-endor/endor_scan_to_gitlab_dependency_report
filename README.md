# Endor Labs Scan Results → GitLab Dependency Scanning Converter

This is a Python script that converts Endor's Scan results to GitLab Dependency Scanner format:

1) runs an **Endor Labs** dependency scan in CI (`endorctl scan`), then  
2) converts the JSON results to a **GitLab Dependency Scanning** report so findings appear in:
   - **Pipeline → Security** tab
   - **Secure → Vulnerability report** (on the default branch)

The converter also adds Endor-specific context to the **Evidence** section (Call paths, Reachability, Dependency path).

---

## What’s included

- `endor_to_gitlab_dep_scan.py` – converter script
- Example `.gitlab-ci.yml`
- Outputs:
  - `gl-dependency-scanning-report.json` (GitLab DS **v15.0.7**)
  - `endor-findings.csv` *(optional; for triage/export)*

---

## Requirements

- GitLab CI runner with Docker
- Python **3.8+** (CI example uses `python:3.11-slim`)
- Endor Labs credentials stored as CI variables:
  - `ENDOR_API_CREDENTIALS_KEY`
  - `ENDOR_API_CREDENTIALS_SECRET`
  - `ENDOR_NAMESPACE` (e.g., `endor-solutions-yourname`)

---

## Script Parameters & Examples

The converter turns Endor’s `endor-results.json` into a GitLab Dependency Scanning **v15** report.

## Quick start

```bash
# 1) Run your Endor scan to produce endor-results.json
endorctl scan --output-type json --output-file endor-results.json

# 2) Convert to GitLab format (and optionally write a CSV for triage)
python3 endor_to_gitlab_dep_scan.py \
  --input endor-results.json \
  --output gl-dependency-scanning-report.json \
  --csv endor-findings.csv [OPTIONAL]

# Output:
# [OK] Wrote gl-dependency-scanning-report.json and endor-findings.csv



