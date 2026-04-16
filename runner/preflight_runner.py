# ABOUTME: Pre-flight gate that runs make check before LLM reviewers
# ABOUTME: Exit code based pass/fail, no JSON parsing, keeps it simple

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PreflightResult:
    passed: bool
    exit_code: int
    output: str
    was_skipped: bool

    @classmethod
    def skipped(cls, reason: str) -> PreflightResult:
        return cls(passed=True, exit_code=0, output=reason, was_skipped=True)


def detect_check_target(project_root: Path) -> bool:
    """Check if the project has a 'make check' target.

    Uses `make -n check` which dry-runs the target. Exit codes:
      0 or 1 = target exists (1 means commands would fail, but target is real)
      2 = "No rule to make target 'check'" (target missing or no Makefile)
    """
    try:
        proc = subprocess.run(
            ["make", "-n", "check"],
            cwd=str(project_root),
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode < 2
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_preflight(project_root: Path, timeout: int = 120) -> PreflightResult:
    """Run make check and return pass/fail with raw output."""
    try:
        proc = subprocess.run(
            ["make", "check"],
            cwd=str(project_root),
            capture_output=True, text=True, timeout=timeout,
        )
        output = (proc.stdout + proc.stderr).strip()
        return PreflightResult(
            passed=proc.returncode == 0,
            exit_code=proc.returncode,
            output=output,
            was_skipped=False,
        )
    except subprocess.TimeoutExpired:
        return PreflightResult(
            passed=False, exit_code=-1,
            output=f"make check: timeout after {timeout}s",
            was_skipped=False,
        )
    except FileNotFoundError:
        return PreflightResult(
            passed=False, exit_code=-1,
            output="make: not found",
            was_skipped=False,
        )
