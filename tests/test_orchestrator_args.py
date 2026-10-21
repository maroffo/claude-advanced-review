# ABOUTME: Unit tests for orchestrator CLI argument parsing
# ABOUTME: Covers diff-mode resolution and the opt-in SonarQube flag

import pytest

from orchestrator import _parse_args


class TestSonarQubeOptIn:
    def test_sonarqube_off_by_default(self):
        args = _parse_args([])
        assert args.sonarqube is False

    def test_sonarqube_enabled_with_flag(self):
        args = _parse_args(["--sonarqube"])
        assert args.sonarqube is True

    def test_old_no_sonarqube_flag_is_gone(self):
        with pytest.raises(SystemExit):
            _parse_args(["--no-sonarqube"])


class TestDiffModeResolution:
    def test_default_is_staged(self):
        args = _parse_args([])
        assert args.diff_mode == "staged"
        assert args.base == "main"

    def test_all_flag(self):
        args = _parse_args(["--all"])
        assert args.diff_mode == "all"

    def test_branch_sets_mode_and_base(self):
        args = _parse_args(["--branch", "dev"])
        assert args.diff_mode == "branch"
        assert args.base == "dev"

    def test_repo_mode(self):
        args = _parse_args(["--repo"])
        assert args.repo == "."
        args = _parse_args(["--repo", "src/"])
        assert args.repo == "src/"
