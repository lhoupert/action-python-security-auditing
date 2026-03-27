# python-security-auditing

A reusable GitHub Action that runs **[bandit](https://bandit.readthedocs.io/)** (static code analysis) and **[pip-audit](https://pypi.org/project/pip-audit/)** (dependency vulnerability scanning) on any Python repository, then consolidates the results into a single PR comment, a workflow step summary, and a downloadable artifact.

## Why this action instead of using bandit or pip-audit directly?

| | `lhoupert/bandit-action` alone | `pypa/gh-action-pip-audit` alone | **this action** |
|---|---|---|---|
| Static code analysis (bandit) | ✅ | — | ✅ |
| Dependency vulnerability scan (pip-audit) | — | ✅ | ✅ |
| Unified PR comment | — | — | ✅ |
| Configurable blocking thresholds | partial | partial | ✅ |
| Multi-package-manager support | — | ✅ | ✅ |
| Workflow step summary | — | — | ✅ |
| Downloadable audit artifact | — | — | ✅ |

The core value is the **reporting layer**: instead of two separate actions producing separate outputs you have to check individually, you get one PR comment that is created on first run and updated in place on every subsequent run.

## What the PR comment looks like

When issues are found, the comment posted to the PR looks like this:

```
# Security Audit Report

## Bandit — Static Security Analysis

| Severity | Confidence | File | Line | Issue |
|---|---|---|---|---|
| 🔴 HIGH | HIGH | `src/app.py` | 2 | [B404] Consider possible security implications associated with subprocess module. |
| 🟡 MEDIUM | MEDIUM | `src/app.py` | 5 | [B602] subprocess call with shell=True identified, security issue. |

_2 issue(s) found, 1 at or above HIGH threshold._

## pip-audit — Dependency Vulnerabilities

| Package | Version | ID | Fix Versions | Description |
|---|---|---|---|---|
| requests | 2.25.0 | GHSA-j8r2-6x86-q33q | 2.31.0 | Unintended leak of Proxy-Authorization header ... |

_1 vulnerability/vulnerabilities found (1 fixable) across 1 package(s)._

---
**Result: ❌ Blocking issues found — see details above.**
```

When everything is clean:

```
## Bandit — Static Security Analysis
✅ No issues found.

## pip-audit — Dependency Vulnerabilities
✅ No vulnerabilities found.

---
**Result: ✅ No blocking issues found.**
```

The comment is idempotent — it is created once and updated in place on every push, so the PR thread stays clean.

## Quickstart

Add this to your workflow (e.g. `.github/workflows/security.yml`):

```yaml
name: Security Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: developmentseed/python-security-auditing@v1
```

This runs both bandit and pip-audit with sensible defaults: blocks the job on HIGH-severity code issues and on dependency vulnerabilities that have a fix available.

## Usage examples

### uv project

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    package_manager: uv
    bandit_scan_dirs: 'src/'
```

### Poetry project with stricter thresholds

Block on any bandit finding at MEDIUM or above, and on all known vulnerabilities regardless of whether a fix exists:

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    package_manager: poetry
    bandit_severity_threshold: medium
    pip_audit_block_on: all
```

### Bandit only (skip dependency audit)

Useful when you manage dependencies externally or run pip-audit in a separate job:

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    tools: bandit
    bandit_scan_dirs: 'src/'
```

### Project in a subdirectory (monorepo)

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    working_directory: services/api
    package_manager: uv
    bandit_scan_dirs: 'services/api/src/'
```

### Audit-only mode (never block the job)

Run the audit and post the comment for visibility, but don't fail CI:

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    bandit_severity_threshold: low   # report everything
    pip_audit_block_on: none         # never block
```

## How blocking works

The job fails (non-zero exit) when **either** tool finds issues above its configured threshold.

**Bandit threshold** (`bandit_severity_threshold`): findings at or above the threshold block the job.

| `bandit_severity_threshold` | Blocks on |
|---|---|
| `high` (default) | 🔴 HIGH only |
| `medium` | 🟡 MEDIUM and 🔴 HIGH |
| `low` | 🟢 LOW, 🟡 MEDIUM, and 🔴 HIGH |

**pip-audit threshold** (`pip_audit_block_on`):

| `pip_audit_block_on` | Blocks on |
|---|---|
| `fixable` (default) | Vulnerabilities with a fix available — you can act on these immediately |
| `all` | All known vulnerabilities, including those with no fix yet |
| `none` | Never blocks — audit runs but CI stays green |

## Inputs

| Input | Default | Description |
|---|---|---|
| `tools` | `bandit,pip-audit` | Comma-separated tools to run |
| `bandit_scan_dirs` | `.` | Comma-separated directories for bandit to scan |
| `bandit_severity_threshold` | `high` | Minimum severity that blocks the job: `high`, `medium`, or `low` |
| `pip_audit_block_on` | `fixable` | When pip-audit findings block the job: `fixable`, `all`, or `none` |
| `package_manager` | `requirements` | How to resolve deps for pip-audit: `uv`, `pip`, `poetry`, `pipenv`, `requirements` |
| `requirements_file` | `requirements.txt` | Path to requirements file when `package_manager=requirements` |
| `working_directory` | `.` | Directory to run the audit from (useful for monorepos) |
| `post_pr_comment` | `true` | Post/update a PR comment with scan results |
| `github_token` | `${{ github.token }}` | Token used for posting PR comments |

## Outputs

- **PR comment** — created on first run, updated in place on every subsequent run (keyed on a hidden `<!-- security-scan-results -->` marker).
- **Step summary** — the same report is written to the workflow run summary, visible under the "Summary" tab.
- **Artifact** — `pip-audit-report.json` uploaded as `security-audit-reports` for download or downstream steps.
- **Exit code** — non-zero when blocking issues are found, so the job fails and branch protections can enforce it.

## Development

```bash
pip install -e ".[dev]"
pytest
pre-commit run --all-files
```
