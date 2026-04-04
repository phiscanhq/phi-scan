# phi-scan CI/CD Templates

Drop-in configuration templates for integrating phi-scan into all major CI/CD platforms.

## Supported Platforms

| Platform             | Template file                                          | Diff mode | PR comments | SARIF upload |
|----------------------|--------------------------------------------------------|-----------|-------------|--------------|
| GitHub Actions       | `github-actions/phi-scan.yml`                          | ✅        | ✅          | ✅           |
| GitLab CI            | `gitlab-ci/phi-scan.gitlab-ci.yml`                     | ✅        | ✅          | ✅           |
| Jenkins              | `jenkins/Jenkinsfile` + `jenkins/vars/phiScan.groovy`  | ✅        | ✅          | ✅           |
| Azure DevOps         | `azure-devops/azure-pipelines.yml`                     | ✅        | ✅          | ✅           |
| CircleCI             | `circleci/config.yml`                                  | ✅        | ✅          | ✅           |
| Bitbucket Pipelines  | `bitbucket-pipelines/bitbucket-pipelines.yml`          | ✅        | ✅          | ✅           |
| AWS CodeBuild        | `aws-codebuild/buildspec.yml`                          | ✅        | ✅          | ✅           |

## Quick Start

### GitHub Actions

Copy `github-actions/phi-scan.yml` to `.github/workflows/phi-scan.yml` in your repo.
No additional secrets are required — `GITHUB_TOKEN` is provided automatically.

### GitLab CI

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/your-org/phi-scan/main/ci-templates/gitlab-ci/phi-scan.gitlab-ci.yml'
```

Or copy the file locally and use `include: - local: 'ci-templates/phi-scan.gitlab-ci.yml'`.

### Jenkins

Copy `jenkins/Jenkinsfile` to your repository root. For org-wide reuse, add
`jenkins/vars/phiScan.groovy` to your shared library and call it as:

```groovy
@Library('your-shared-lib') _
phiScan()
```

### Azure DevOps

Copy `azure-devops/azure-pipelines.yml` to your repository root and create the
pipeline in Azure DevOps. `System.AccessToken` is automatically available for
Azure Repos PR comment posting.

### CircleCI

Merge `circleci/config.yml` into your `.circleci/config.yml`. Or use the
reusable orb (once published):

```yaml
orbs:
  phi-scan: phi-scan/phi-scan@1
```

### Bitbucket Pipelines

Copy `bitbucket-pipelines/bitbucket-pipelines.yml` to your repository root.
Set `BITBUCKET_TOKEN` as a repository variable with `pullrequest:write` scope.

### AWS CodeBuild

Copy `aws-codebuild/buildspec.yml` to your repository root and reference it
in your CodeBuild project. Store `GITHUB_TOKEN` or `BITBUCKET_TOKEN` in
AWS Secrets Manager and configure parameter-store references in the buildspec.

## Common Options

All templates support these phi-scan flags:

| Flag                  | Description                                        |
|-----------------------|----------------------------------------------------|
| `--diff <ref>`        | Scan only files changed relative to `<ref>`        |
| `--output sarif`      | SARIF output for inline annotations                |
| `--output json`       | Machine-readable JSON summary                      |
| `--output codequality`| GitLab Code Quality format                         |
| `--output gitlab-sast`| GitLab SAST Security Dashboard format              |
| `--output junit`      | JUnit XML for CircleCI / Jenkins test summary      |
| `--post-comment`      | Post findings as PR/MR comment (auto-detect platform)|
| `--set-status`        | Set commit status PASS/FAIL                        |
| `--severity-threshold`| Minimum severity level to report (LOW/MEDIUM/HIGH) |

## Exit Codes

| Code | Meaning                         |
|------|---------------------------------|
| `0`  | Scan clean — no violations      |
| `1`  | PHI/PII violations found        |
| `2`  | Scanner error (config, I/O etc) |

All templates propagate the phi-scan exit code so the CI pipeline fails
automatically when violations are found.
