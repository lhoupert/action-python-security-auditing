"""Orchestrator: load settings → run tools → report → comment → exit."""

from __future__ import annotations

import sys
from typing import Any

from .pr_comment import upsert_pr_comment
from .report import build_markdown, check_thresholds, write_step_summary
from .runners import generate_requirements, run_bandit, run_pip_audit
from .settings import Settings


def main() -> None:
    settings = Settings()

    bandit_report: dict[str, Any] = {}
    pip_audit_report: list[dict[str, Any]] = []

    if "bandit" in settings.enabled_tools:
        bandit_report = run_bandit(settings.scan_directories)

    if "pip-audit" in settings.enabled_tools:
        requirements_path = generate_requirements(settings)
        pip_audit_report = run_pip_audit(requirements_path)

    markdown = build_markdown(bandit_report, pip_audit_report, settings)
    write_step_summary(markdown, settings)

    if settings.post_pr_comment and settings.github_token:
        upsert_pr_comment(markdown, settings)

    if check_thresholds(bandit_report, pip_audit_report, settings):
        sys.exit(1)


if __name__ == "__main__":
    main()
