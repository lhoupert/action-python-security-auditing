"""Tool invocation and package manager adapter."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .settings import Settings


def generate_requirements(settings: Settings) -> Path:
    """Return a requirements.txt Path suitable for pip-audit.

    For package managers that don't produce a file directly (pip, pipenv),
    captures stdout into a temp file. For 'requirements', returns the
    configured path unchanged.
    """
    pm = settings.package_manager

    if pm == "requirements":
        return Path(settings.requirements_file)

    tmp = tempfile.NamedTemporaryFile(suffix="-requirements.txt", delete=False, mode="w")
    tmp.close()
    out_path = Path(tmp.name)

    if pm == "uv":
        subprocess.run(
            ["uv", "export", "--format", "requirements-txt", "--no-hashes", "-o", str(out_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    elif pm == "pip":
        result = subprocess.run(["pip", "freeze"], capture_output=True, text=True, check=True)
        out_path.write_text(result.stdout)
    elif pm == "poetry":
        subprocess.run(
            [
                "poetry",
                "export",
                "--format",
                "requirements.txt",
                "--without-hashes",
                "-o",
                str(out_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    elif pm == "pipenv":
        result = subprocess.run(
            ["pipenv", "requirements"], capture_output=True, text=True, check=True
        )
        out_path.write_text(result.stdout)

    return out_path


def run_bandit(scan_dirs: list[str]) -> dict[str, Any]:
    """Run bandit, write bandit-report.json, return parsed report."""
    output_file = Path("bandit-report.json")
    cmd = ["bandit", "-r", *scan_dirs, "-f", "json", "-o", str(output_file)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    # bandit exits 1 when issues are found — that is expected, not an error
    if result.returncode not in (0, 1):
        print(
            f"bandit exited with unexpected code {result.returncode}:\n{result.stderr}",
            file=sys.stderr,
        )

    if output_file.exists():
        return dict(json.loads(output_file.read_text()))  # type: ignore[arg-type]
    return {"results": [], "errors": []}


def run_pip_audit(requirements_path: Path) -> list[dict[str, Any]]:
    """Run pip-audit, write pip-audit-report.json, return parsed report."""
    output_file = Path("pip-audit-report.json")
    cmd = ["pip-audit", "-r", str(requirements_path), "-f", "json"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    # pip-audit exits 1 when vulnerabilities are found — that is expected
    if result.returncode not in (0, 1):
        print(
            f"pip-audit exited with unexpected code {result.returncode}:\n{result.stderr}",
            file=sys.stderr,
        )

    raw = result.stdout.strip()
    if raw:
        parsed: list[dict[str, Any]] = json.loads(raw)
        output_file.write_text(raw)
        return parsed
    return []
