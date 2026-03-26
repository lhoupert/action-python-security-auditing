"""Tests for runners.py — tool invocation and package manager adapter."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from python_security_auditing.runners import generate_requirements, run_bandit, run_pip_audit
from python_security_auditing.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# generate_requirements
# ---------------------------------------------------------------------------


def test_requirements_mode_returns_configured_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "requirements")
    monkeypatch.setenv("REQUIREMENTS_FILE", "custom-requirements.txt")
    s = Settings()
    assert generate_requirements(s) == Path("custom-requirements.txt")


def test_uv_mode_calls_uv_export(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    s = Settings()

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "uv"
    assert "export" in cmd
    assert "--format" in cmd
    assert "requirements-txt" in cmd
    assert str(result).endswith("-requirements.txt")


def test_pip_mode_calls_pip_freeze(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pip")
    s = Settings()

    freeze_output = "requests==2.31.0\n"
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=freeze_output)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd == ["pip", "freeze"]
    assert result.read_text() == freeze_output


def test_poetry_mode_calls_poetry_export(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "poetry")
    s = Settings()

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "poetry"
    assert "export" in cmd
    assert str(result).endswith("-requirements.txt")


def test_pipenv_mode_calls_pipenv_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    s = Settings()

    pipenv_output = "requests==2.31.0\n"
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=pipenv_output)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd == ["pipenv", "requirements"]
    assert result.read_text() == pipenv_output


# ---------------------------------------------------------------------------
# run_bandit
# ---------------------------------------------------------------------------


def test_run_bandit_parses_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    fixture = json.loads((FIXTURES / "bandit_issues.json").read_text())

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="")
        # Simulate bandit writing the output file
        (tmp_path / "bandit-report.json").write_text(json.dumps(fixture))
        report = run_bandit(["src"])

    assert len(report["results"]) == 2
    assert report["results"][0]["issue_severity"] == "HIGH"


def test_run_bandit_returns_empty_on_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        report = run_bandit(["."])

    assert report["results"] == []


def test_run_bandit_passes_dirs_to_cmd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bandit-report.json").write_text('{"results": [], "errors": []}')

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        run_bandit(["src/", "scripts/"])

    cmd = mock_run.call_args[0][0]
    assert "src/" in cmd
    assert "scripts/" in cmd
    assert "-f" in cmd
    assert "json" in cmd


# ---------------------------------------------------------------------------
# run_pip_audit
# ---------------------------------------------------------------------------


def test_run_pip_audit_parses_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    fixture_text = (FIXTURES / "pip_audit_fixable.json").read_text()

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="", stdout=fixture_text)
        report = run_pip_audit(Path("requirements.txt"))

    assert len(report) == 2
    assert report[0]["name"] == "requests"
    assert (tmp_path / "pip-audit-report.json").exists()


def test_run_pip_audit_returns_empty_on_no_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        report = run_pip_audit(Path("requirements.txt"))

    assert report == []


def test_run_pip_audit_uses_requirements_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    req_path = tmp_path / "custom-reqs.txt"

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="[]")
        run_pip_audit(req_path)

    cmd = mock_run.call_args[0][0]
    assert str(req_path) in cmd
    assert "-f" in cmd
    assert "json" in cmd
