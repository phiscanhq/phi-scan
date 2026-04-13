# CI/CD Integration

PhiScan integrates with all major CI/CD platforms. Templates for all 7 platforms are
below — copy, paste, and adapt.

**Core principle:** All scanning runs inside your pipeline runner. No PHI or PII is
transmitted to any external service.

---

## Quick Reference

| Platform | Native format | Inline annotations |
|---|---|---|
| GitHub Actions | SARIF | GitHub Code Scanning |
| GitLab CI | `codequality` + `gitlab-sast` | MR inline annotations |
| Jenkins | SARIF (Warnings NG) | Warnings NG plugin |
| Azure DevOps | SARIF | Advanced Security |
| CircleCI | JUnit XML | Test Summary |
| Bitbucket Pipelines | SARIF | Code Insights |
| AWS CodeBuild | SARIF | Security Hub (ASFF) |

---

## Git Hook Integration

Before CI/CD, block PHI at commit time on developer machines.

### Method 1 — Native Git Hook (individuals)

```bash
phi-scan install-hook
```

Writes a pre-commit hook to `.git/hooks/pre-commit`. Runs `phi-scan scan --diff HEAD`
on every commit — only changed files are scanned.

```bash
phi-scan uninstall-hook    # remove when no longer needed
```

### Method 2 — Pre-commit Framework (teams)

The [pre-commit framework](https://pre-commit.com) manages hooks as versioned,
committed configuration shared across the whole team.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/joeyessak/phi-scan
    rev: v0.5.0
    hooks:
      - id: phi-scan
```

Install:

```bash
pip install pre-commit
pre-commit install
```

Run manually:

```bash
pre-commit run phi-scan --all-files
```

With options:

```yaml
repos:
  - repo: https://github.com/joeyessak/phi-scan
    rev: v0.5.0
    hooks:
      - id: phi-scan
        args:
          - '--severity-threshold'
          - 'medium'
          - '--baseline'
          - '--output'
          - 'sarif'
          - '--report-path'
          - 'phi-scan-results.sarif'
```

Update to the latest release:

```bash
pre-commit autoupdate
```

---

## 1. GitHub Actions

### Basic — scan changed files, fail PR on findings

```yaml
# .github/workflows/phi-scan.yml
name: PHI Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  phi-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2   # needed for --diff HEAD~1

      - name: Install PhiScan
        run: pipx install phi-scan

      - name: Scan for PHI
        run: phi-scan scan --diff HEAD~1
```

### With SARIF upload to GitHub Code Scanning

```yaml
name: PHI Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  phi-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required for SARIF upload
      contents: read

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Install PhiScan
        run: pipx install phi-scan

      - name: Scan for PHI
        run: |
          phi-scan scan --diff HEAD~1 \
            --output sarif \
            --report-path phi-scan.sarif
        # continue-on-error: true   # uncomment to upload SARIF even when findings exist

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: phi-scan.sarif
          category: phi-scan
```

### Full repository scan with baseline

```yaml
name: PHI Scan (full)

on:
  schedule:
    - cron: '0 2 * * 1'   # weekly on Monday at 02:00 UTC
  workflow_dispatch:

jobs:
  phi-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Install PhiScan
        run: pipx install phi-scan

      - name: Scan entire repository
        run: |
          phi-scan scan . \
            --baseline \
            --output sarif \
            --report-path phi-scan.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: phi-scan.sarif
```

**Exit codes:**
- `0` → no findings → job passes
- `1` → PHI detected → job fails (blocks merge)
- `2` → configuration error → job fails

---

## 2. GitLab CI

### Code Quality report (MR inline annotations)

```yaml
# .gitlab-ci.yml
phi-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install phi-scan
  script:
    - phi-scan scan --diff HEAD~1
        --output codequality
        --report-path phi-scan-codequality.json
  artifacts:
    reports:
      codequality: phi-scan-codequality.json
    when: always
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitLab SAST report (Security dashboard)

```yaml
phi-scan-sast:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install phi-scan
  script:
    - phi-scan scan .
        --output gitlab-sast
        --report-path phi-scan-sast.json
  artifacts:
    reports:
      sast: phi-scan-sast.json
    when: always
    expire_in: 1 week
```

### Combined (Code Quality + SAST in one job)

```yaml
phi-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install phi-scan
  script:
    - |
      phi-scan scan --diff HEAD~1 \
        --output codequality \
        --report-path phi-scan-codequality.json
    - |
      phi-scan scan . \
        --output gitlab-sast \
        --report-path phi-scan-sast.json
  artifacts:
    reports:
      codequality: phi-scan-codequality.json
      sast: phi-scan-sast.json
    when: always
    expire_in: 1 week
```

---

## 3. Jenkins

Requires the [Warnings Next Generation plugin](https://plugins.jenkins.io/warnings-ng/).

### Declarative pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('PHI Scan') {
            steps {
                sh 'pip install phi-scan'
                sh '''
                    phi-scan scan --diff HEAD~1 \
                        --output sarif \
                        --report-path phi-scan.sarif \
                        || true
                '''
            }
            post {
                always {
                    recordIssues(
                        tool: sarif(pattern: 'phi-scan.sarif', id: 'phi-scan', name: 'PHI Scan'),
                        qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]]
                    )
                }
            }
        }
    }
}
```

### Scripted pipeline

```groovy
node {
    stage('PHI Scan') {
        sh 'pip install phi-scan'
        def exitCode = sh(
            script: 'phi-scan scan --diff HEAD~1 --output sarif --report-path phi-scan.sarif',
            returnStatus: true
        )
        recordIssues(tool: sarif(pattern: 'phi-scan.sarif', id: 'phi-scan', name: 'PHI Scan'))
        if (exitCode == 1) {
            error('PHI/PII detected — build failed')
        } else if (exitCode == 2) {
            error('phi-scan configuration error')
        }
    }
}
```

---

## 4. Azure DevOps

### Azure Pipelines (YAML)

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - 'feature/*'

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: pip install phi-scan
    displayName: 'Install PhiScan'

  - script: |
      phi-scan scan --diff HEAD~1 \
        --output sarif \
        --report-path $(Build.ArtifactStagingDirectory)/phi-scan.sarif
    displayName: 'Scan for PHI'
    continueOnError: true

  - task: PublishBuildArtifacts@1
    displayName: 'Publish SARIF report'
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/phi-scan.sarif'
      ArtifactName: 'phi-scan-results'
    condition: always()
```

> **Azure DevOps Advanced Security:** Upload the SARIF artifact to Advanced Security
> using the `AdvancedSecurity-Publish` task if your organisation has it enabled.

---

## 5. CircleCI

JUnit XML format integrates with CircleCI's Test Summary view.

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  phi-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install PhiScan
          command: pip install phi-scan
      - run:
          name: Scan for PHI
          command: |
            mkdir -p test-results/phi-scan
            phi-scan scan --diff HEAD~1 \
              --output junit \
              --report-path test-results/phi-scan/results.xml
      - store_test_results:
          path: test-results
      - store_artifacts:
          path: test-results/phi-scan/results.xml

workflows:
  main:
    jobs:
      - phi-scan
```

---

## 6. Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: python:3.12-slim

pipelines:
  pull-requests:
    '**':
      - step:
          name: PHI Scan
          script:
            - pip install phi-scan
            - phi-scan scan --diff HEAD~1
                --output sarif
                --report-path phi-scan.sarif
          after-script:
            - pipe: atlassian/bitbucket-upload-file:0.3.2
              variables:
                BITBUCKET_USERNAME: $BITBUCKET_USERNAME
                BITBUCKET_APP_PASSWORD: $BITBUCKET_APP_PASSWORD
                FILENAME: 'phi-scan.sarif'
```

> **Bitbucket Code Insights:** Use the Bitbucket REST API to post SARIF findings as
> Code Insights annotations on pull requests. The `phi-scan.sarif` artifact produced
> above can be parsed and submitted to the
> `reports/{reportKey}/annotations` endpoint.

---

## 7. AWS CodeBuild

```yaml
# buildspec.yml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install phi-scan

  build:
    commands:
      - phi-scan scan --diff HEAD~1
          --output sarif
          --report-path phi-scan.sarif
          || true

  post_build:
    commands:
      - aws s3 cp phi-scan.sarif s3://${ARTIFACT_BUCKET}/phi-scan/phi-scan.sarif

reports:
  phi-scan-report:
    files:
      - 'phi-scan.sarif'
    file-format: SARIF
```

> **AWS Security Hub:** Convert the SARIF output to Amazon Security Finding Format
> (ASFF) and import via `aws securityhub batch-import-findings` to surface results
> in the Security Hub dashboard.

---

## Environment Variable Auto-Detection

PhiScan auto-detects the CI/CD platform from environment variables and selects the
correct integration automatically:

| Environment variable | Platform |
|---|---|
| `GITHUB_ACTIONS=true` | GitHub Actions |
| `GITLAB_CI=true` | GitLab CI |
| `JENKINS_URL` | Jenkins |
| `SYSTEM_TEAMFOUNDATIONCOLLECTIONURI` | Azure DevOps |
| `CIRCLECI=true` | CircleCI |
| `BITBUCKET_BUILD_NUMBER` | Bitbucket Pipelines |
| `CODEBUILD_BUILD_ID` | AWS CodeBuild |

When auto-detected, PhiScan adjusts console output accordingly (e.g. suppresses Rich
formatting in environments that do not support ANSI codes).

---

## Exit Codes

All integrations rely on the standard exit codes:

| Code | Meaning | CI behaviour |
|---|---|---|
| `0` | No findings (or all covered by baseline) | Job passes |
| `1` | PHI/PII detected | Job fails — blocks merge |
| `2` | Configuration error or invalid CLI argument | Job fails |
