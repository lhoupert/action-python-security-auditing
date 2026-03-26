"""Tests for settings.py — env var parsing and computed properties."""

import pytest

from python_security_auditing.settings import Settings


def test_defaults():
    s = Settings()
    assert s.tools == "bandit,pip-audit"
    assert s.bandit_scan_dirs == "."
    assert s.bandit_severity_threshold == "HIGH"
    assert s.pip_audit_block_on == "fixable"
    assert s.package_manager == "requirements"
    assert s.requirements_file == "requirements.txt"
    assert s.post_pr_comment is True
    assert s.github_token == ""


def test_enabled_tools_default():
    s = Settings()
    assert s.enabled_tools == ["bandit", "pip-audit"]


def test_enabled_tools_single(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TOOLS", "bandit")
    s = Settings()
    assert s.enabled_tools == ["bandit"]


def test_enabled_tools_custom(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TOOLS", "pip-audit")
    s = Settings()
    assert s.enabled_tools == ["pip-audit"]


def test_enabled_tools_whitespace(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TOOLS", " bandit , pip-audit ")
    s = Settings()
    assert s.enabled_tools == ["bandit", "pip-audit"]


def test_scan_directories_default():
    s = Settings()
    assert s.scan_directories == ["."]


def test_scan_directories_multiple(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BANDIT_SCAN_DIRS", "src/,scripts/")
    s = Settings()
    assert s.scan_directories == ["src/", "scripts/"]


def test_blocking_severities_high():
    s = Settings()
    assert s.blocking_severities == ["HIGH"]


def test_blocking_severities_medium(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "MEDIUM")
    s = Settings()
    assert s.blocking_severities == ["MEDIUM", "HIGH"]


def test_blocking_severities_low(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "LOW")
    s = Settings()
    assert s.blocking_severities == ["LOW", "MEDIUM", "HIGH"]


def test_pr_number_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PR_NUMBER", "42")
    s = Settings()
    assert s.pr_number == 42


def test_post_pr_comment_false(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("POST_PR_COMMENT", "false")
    s = Settings()
    assert s.post_pr_comment is False


def test_github_context(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/my-branch")
    s = Settings()
    assert s.github_repository == "org/repo"
    assert s.github_run_id == "12345"
    assert s.github_event_name == "pull_request"
    assert s.github_head_ref == "feature/my-branch"
