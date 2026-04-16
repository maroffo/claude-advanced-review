# ABOUTME: Unit tests for runner/preflight_runner.py make-check gate
# ABOUTME: Mocks subprocess; real make check covered by E2E with fixture Makefile

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch


from runner import preflight_runner as PF


# ---------- detect_check_target tests ----------

class TestDetectCheckTarget:
    @patch("subprocess.run")
    def test_returns_true_when_target_exists(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert PF.detect_check_target(Path("/fake/repo")) is True

    @patch("subprocess.run")
    def test_returns_true_on_exit_1(self, mock_run):
        # make -n exits 1 if the commands would fail, but target exists
        mock_run.return_value = MagicMock(returncode=1)
        assert PF.detect_check_target(Path("/fake/repo")) is True

    @patch("subprocess.run")
    def test_returns_false_on_exit_2(self, mock_run):
        # make -n exits 2 when "No rule to make target 'check'"
        mock_run.return_value = MagicMock(returncode=2)
        assert PF.detect_check_target(Path("/fake/repo")) is False

    @patch("subprocess.run")
    def test_returns_false_when_no_makefile(self, mock_run):
        mock_run.return_value = MagicMock(returncode=2,
                                          stderr="No targets specified and no makefile found")
        assert PF.detect_check_target(Path("/fake/repo")) is False

    @patch("subprocess.run")
    def test_returns_false_on_exception(self, mock_run):
        mock_run.side_effect = FileNotFoundError("make not found")
        assert PF.detect_check_target(Path("/fake/repo")) is False


# ---------- run_preflight tests ----------

class TestRunPreflight:
    @patch("subprocess.run")
    def test_pass_on_exit_0(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="all checks passed\n", stderr="")
        result = PF.run_preflight(Path("/fake/repo"))
        assert result.passed is True
        assert result.exit_code == 0

    @patch("subprocess.run")
    def test_fail_on_exit_1(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="golangci-lint: found 3 issues\n")
        result = PF.run_preflight(Path("/fake/repo"))
        assert result.passed is False
        assert result.exit_code == 1
        assert "3 issues" in result.output

    @patch("subprocess.run")
    def test_fail_on_exit_2(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=2, stdout="", stderr="make: *** Error 2")
        result = PF.run_preflight(Path("/fake/repo"))
        assert result.passed is False
        assert result.exit_code == 2

    @patch("subprocess.run")
    def test_timeout_returns_failure(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="make", timeout=120)
        result = PF.run_preflight(Path("/fake/repo"))
        assert result.passed is False
        assert "timeout" in result.output.lower()

    @patch("subprocess.run")
    def test_output_combines_stdout_and_stderr(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="running lint...\n", stderr="error: bad code\n")
        result = PF.run_preflight(Path("/fake/repo"))
        assert "running lint" in result.output
        assert "bad code" in result.output

    @patch("subprocess.run")
    def test_make_not_found_returns_failure(self, mock_run):
        mock_run.side_effect = FileNotFoundError("make not found")
        result = PF.run_preflight(Path("/fake/repo"))
        assert result.passed is False
        assert "not found" in result.output.lower()


# ---------- PreflightResult tests ----------

class TestPreflightResult:
    def test_skipped_result(self):
        result = PF.PreflightResult.skipped("no make check target")
        assert result.passed is True
        assert result.was_skipped is True
        assert "no make check" in result.output

    def test_passed_result(self):
        result = PF.PreflightResult(passed=True, exit_code=0,
                                    output="ok", was_skipped=False)
        assert result.passed is True
        assert result.was_skipped is False

    def test_failed_result(self):
        result = PF.PreflightResult(passed=False, exit_code=1,
                                    output="lint errors", was_skipped=False)
        assert result.passed is False
