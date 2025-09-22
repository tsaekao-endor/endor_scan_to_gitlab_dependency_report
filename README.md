# Endor Labs → GitLab Dependency Scanning Converter

This repo ships a tiny Python tool and a sample GitLab CI pipeline that:

1) runs an **Endor Labs** dependency scan in CI (`endorctl scan`), then  
2) converts the JSON results to a **GitLab Dependency Scanning v15** report so findings appear in:
   - **Pipeline → Security** tab
   - **Secure → Vulnerability report** (on the default branch)

The converter also adds Endor-specific context to the **Evidence** section (Call paths, Reachability, Dependency path) and intentionally **omits any Links section** to keep the UI clean.

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
- Endor Labs credentials stored as masked CI variables:
  - `ENDOR_API_CREDENTIALS_KEY`
  - `ENDOR_API_CREDENTIALS_SECRET`
  - `ENDOR_NAMESPACE` (e.g., `endor-solutions-yourname`)

> **Note**  
> If you pass a namespace + valid credentials to `endorctl`, results are also uploaded to the Endor platform.  
> For local-only tests, omit credentials.

---

## Quick start (GitLab CI)

1. **Add CI variables** in *Settings → CI/CD → Variables*  
   `ENDOR_API_CREDENTIALS_KEY`, `ENDOR_API_CREDENTIALS_SECRET`, `ENDOR_NAMESPACE`

2. **Commit** `endor_to_gitlab_dep_scan.py` at the **repo root**.

3. **Add** `.gitlab-ci.yml`:

```yaml
stages: [scan, convert]

endor_dependency_scan:
  stage: scan
  image: maven:3.8-openjdk-11          # change to your toolchain if needed
  variables:
    ENDOR_NAMESPACE: "endor-solutions-yourname"   # <-- set your namespace
    ENDOR_PROJECT_DIR: "."
    ENDOR_ARGS: >
      --path=${ENDOR_PROJECT_DIR}
      --exit-on-policy-warning
      --dependencies --secrets --git-logs
  before_script:
    - mvn -B -DskipTests clean install  # resolve deps for Java; adjust/remove for your stack
    - curl -fsSL https://api.endorlabs.com/download/latest/endorctl_linux_amd64 -o endorctl
    - echo "$(curl -fsSL https://api.endorlabs.com/sha/latest/endorctl_linux_amd64)  endorctl" | sha256sum -c -
    - chmod +x ./endorctl
  script:
    - >
      ./endorctl scan ${ENDOR_ARGS}
      --namespace "$ENDOR_NAMESPACE"
      --api-key "$ENDOR_API_CREDENTIALS_KEY"
      --api-secret "$ENDOR_API_CREDENTIALS_SECRET"
      --output-type json | tee endor-results.json
  artifacts:
    when: always
    paths:
      - endor-results.json

convert_endor_to_gitlab:
  stage: convert
  image: python:3.11-slim
  needs: ["endor_dependency_scan"]
  script:
    - python endor_to_gitlab_dep_scan.py --input endor-results.json --output gl-dependency-scanning-report.json --csv endor-findings.csv
  artifacts:
    when: always
    expire_in: 14 days
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - gl-dependency-scanning-report.json
      - endor-findings.csv
  rules:
    # Ensure ingestion into the project Vulnerability report
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      when: on_success
