# ABOUTME: Unit tests for runner/test_runner.py
# ABOUTME: Toolchain detection + extension mapping + test status classification

from __future__ import annotations

from pathlib import Path

import pytest

from runner import test_runner as R


# ---------- Toolchain detection ----------

class TestDetectToolchain:
    def test_python_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        assert R.detect_toolchain(tmp_path).language == "python"

    def test_python_setup_py(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\n")
        assert R.detect_toolchain(tmp_path).language == "python"

    def test_javascript_npm(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"name":"x"}')
        (tmp_path / "package-lock.json").write_text("{}")
        tc = R.detect_toolchain(tmp_path)
        assert tc.language == "javascript"
        assert tc.runner_cmd[:2] == ["npm", "test"]

    def test_javascript_yarn(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"name":"x"}')
        (tmp_path / "yarn.lock").write_text("")
        tc = R.detect_toolchain(tmp_path)
        assert tc.runner_cmd[0] == "yarn"

    def test_javascript_pnpm(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"name":"x"}')
        (tmp_path / "pnpm-lock.yaml").write_text("")
        tc = R.detect_toolchain(tmp_path)
        assert tc.runner_cmd[0] == "pnpm"

    def test_go(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module x\n")
        assert R.detect_toolchain(tmp_path).language == "go"

    def test_rust(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
        assert R.detect_toolchain(tmp_path).language == "rust"

    def test_ruby(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
        assert R.detect_toolchain(tmp_path).language == "ruby"

    def test_none_detected(self, tmp_path: Path):
        assert R.detect_toolchain(tmp_path) is None


# ---------- File extension mapping ----------

class TestExtensionFor:
    @pytest.mark.parametrize("lang,ext", [
        ("python", ".py"),
        ("javascript", ".test.js"),
        ("typescript", ".test.ts"),
        ("go", "_test.go"),
        ("ruby", "_spec.rb"),
        ("rust", ".rs"),
        ("java", "Test.java"),
        ("kotlin", "Test.kt"),
        ("swift", "Tests.swift"),
    ])
    def test_maps_known_language(self, lang, ext):
        assert R.extension_for(lang) == ext

    def test_unknown_falls_back(self):
        assert R.extension_for("brainfuck") == ".txt"


# ---------- Test status classification ----------

class TestClassify:
    def test_exit_nonzero_is_fail(self):
        assert R.classify_test_result(exit_code=1, stderr="") == "failed"

    def test_exit_zero_is_pass(self):
        assert R.classify_test_result(exit_code=0, stderr="") == "passed"

    def test_import_error_is_errored(self):
        stderr = "ImportError: No module named 'missing_dep'"
        assert R.classify_test_result(exit_code=2, stderr=stderr) == "errored"

    def test_collection_error_is_errored(self):
        stderr = "ERROR tests/test_foo.py - ModuleNotFoundError: foo"
        assert R.classify_test_result(exit_code=2, stderr=stderr) == "errored"

    def test_syntax_error_is_errored(self):
        stderr = "SyntaxError: invalid syntax"
        assert R.classify_test_result(exit_code=2, stderr=stderr) == "errored"


# ---------- Disposition logic ----------

class TestDisposeBugFinding:
    def _finding(self, **ev):
        return {
            "id": "f1",
            "category": "bug",
            "severity": "WARNING",
            "validator_status": "passed",
            "evidence": {
                "test_language": "python",
                "test_target_file": "tests/test_x.py",
                "test_modifies_existing": False,
                "test": "def test_fails():\n    assert False\n",
                **ev,
            },
        }

    def test_passes_finding_when_test_fails(self):
        """Test failing on current code = bug confirmed = keep finding."""
        out = R.apply_disposition(self._finding(), test_status="failed",
                                  test_path="review-tests/f1.py")
        assert out["runner_status"] == "confirmed"
        assert out["test_path"] == "review-tests/f1.py"

    def test_drops_finding_when_test_passes(self):
        """Test passing on current code = claim not demonstrated = drop."""
        out = R.apply_disposition(self._finding(), test_status="passed",
                                  test_path="review-tests/f1.py")
        assert out["runner_status"] == "unproven"

    def test_keeps_finding_when_test_errors(self):
        """Test errored (import, setup) = ambiguous = keep with flag."""
        out = R.apply_disposition(self._finding(), test_status="errored",
                                  test_path="review-tests/f1.py")
        assert out["runner_status"] == "errored"
        # Don't silently drop a finding the runner couldn't evaluate.
        assert "errored" in out["runner_status"]

    def test_non_bug_finding_passes_through(self):
        sec = {
            "id": "f2", "category": "security", "severity": "CRITICAL",
            "validator_status": "passed", "evidence": {},
        }
        out = R.apply_disposition(sec, test_status=None, test_path=None)
        assert out.get("runner_status") == "not_applicable"
