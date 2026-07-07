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

    def test_sandbox_unavailable_survives_with_reason(self):
        """Sandbox couldn't judge = keep finding, record why (like skipped)."""
        out = R.apply_disposition(self._finding(),
                                  test_status="sandbox_unavailable",
                                  test_path="review-tests/f1.py",
                                  reason="docker not installed on host")
        assert out["runner_status"] == "sandbox_unavailable"
        assert out["runner_reason"] == "docker not installed on host"
        # Must NOT be "unproven": orchestrator only drops unproven findings.
        assert out["runner_status"] != "unproven"


# ---------- Sandbox image map ----------

class TestSandboxImages:
    @pytest.mark.parametrize("lang,image", [
        ("python", "python:3.12-slim"),
        ("javascript", "node:22-slim"),
        ("typescript", "node:22-slim"),
        ("go", "golang:1.23"),
        ("rust", "rust:1-slim"),
        ("ruby", "ruby:3-slim"),
    ])
    def test_image_for_toolchain(self, lang, image):
        assert R.SANDBOX_IMAGES[lang] == image

    def test_unknown_language_has_no_image(self):
        assert R.SANDBOX_IMAGES.get("brainfuck") is None


# ---------- Docker argv construction ----------

class TestBuildSandboxCmd:
    def _cmd(self, tmp_path: Path):
        test_file = tmp_path / "review-tests" / "test_review_f1.py"
        return R.build_sandbox_cmd(
            image="python:3.12-slim",
            project_root=tmp_path,
            host_test_path=test_file,
            container_test_path="/review/test_review_f1.py",
            script="python /review/test_review_f1.py",
            timeout=120,
        )

    def test_runs_docker(self, tmp_path: Path):
        assert self._cmd(tmp_path)[:3] == ["docker", "run", "--rm"]

    def test_has_isolation_flags(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
        assert "--read-only" in cmd
        assert "--pids-limit" in cmd
        assert cmd[cmd.index("--pids-limit") + 1] == "256"
        assert "--memory" in cmd
        assert cmd[cmd.index("--memory") + 1] == "1g"

    def test_has_writable_tmpfs_for_scratch(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        assert "--tmpfs" in cmd
        assert cmd[cmd.index("--tmpfs") + 1] == "/tmp"

    def test_mounts_project_read_only(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
        proj = next(m for m in mounts if m.endswith(":/workspace:ro"))
        assert proj.endswith(":ro")

    def test_mounts_test_file_read_only(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
        tf = next(m for m in mounts if "/review/test_review_f1.py" in m)
        assert tf.endswith(":ro")

    def test_workdir_is_workspace(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        assert "-w" in cmd and cmd[cmd.index("-w") + 1] == "/workspace"

    def test_enforces_wall_clock_timeout_in_container(self, tmp_path: Path):
        cmd = self._cmd(tmp_path)
        assert "timeout" in cmd
        assert cmd[cmd.index("timeout") + 1] == "120"


# ---------- In-container script + -k fix ----------

class TestContainerScript:
    def test_python_uses_pytest_when_available_else_python(self):
        tc = R.Toolchain(language="python", runner_cmd=[])
        script = R.build_container_script(tc, "/review/t.py", None)
        assert "python -m pytest" in script
        assert "python /review/t.py" in script  # fallback branch

    def test_python_k_filter_is_two_tokens(self):
        """Regression: `-k name` must be two argv tokens, not `-k name` glued."""
        tc = R.Toolchain(language="python", runner_cmd=[])
        script = R.build_container_script(tc, "/review/t.py", "test_bug")
        # The flag and its value are space-separated in the shell script.
        assert "-k test_bug" in script
        assert "-ktest_bug" not in script

    def test_node_runs_test_file(self):
        tc = R.Toolchain(language="javascript", runner_cmd=[])
        assert R.build_container_script(tc, "/review/t.js", None) \
            .startswith("node ")


# ---------- Sandbox result classification ----------

class TestClassifySandboxResult:
    def test_clean_failure_is_bug(self):
        status, reason = R.classify_sandbox_result(1, "AssertionError", "python")
        assert status == "failed"
        assert reason is None

    def test_clean_pass_is_unproven(self):
        status, reason = R.classify_sandbox_result(0, "1 passed", "python")
        assert status == "passed"

    def test_docker_daemon_down_is_unavailable(self):
        out = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        status, reason = R.classify_sandbox_result(125, out, "python")
        assert status == "sandbox_unavailable"
        assert reason

    def test_missing_image_is_unavailable(self):
        out = "Unable to find image 'python:3.12-slim' locally\nmanifest unknown"
        status, _ = R.classify_sandbox_result(125, out, "python")
        assert status == "sandbox_unavailable"

    def test_missing_dep_is_unavailable_not_bug(self):
        out = "ModuleNotFoundError: No module named 'projectlib'"
        status, reason = R.classify_sandbox_result(1, out, "python")
        assert status == "sandbox_unavailable"
        assert reason

    def test_node_missing_test_harness_is_unavailable(self):
        out = "ReferenceError: describe is not defined"
        status, _ = R.classify_sandbox_result(1, out, "javascript")
        assert status == "sandbox_unavailable"

    def test_timeout_exit_is_unavailable(self):
        status, reason = R.classify_sandbox_result(124, "", "python")
        assert status == "sandbox_unavailable"

    def test_pytest_no_tests_collected_is_unavailable(self):
        # pytest exit 5 = no tests collected: cannot conclude a bug.
        status, _ = R.classify_sandbox_result(5, "no tests ran", "python")
        assert status == "sandbox_unavailable"

    def test_pytest_usage_error_is_unavailable(self):
        status, _ = R.classify_sandbox_result(4, "usage error", "python")
        assert status == "sandbox_unavailable"


# ---------- End-to-end run_bug_finding (subprocess mocked) ----------

class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _bug_finding(code="def test_bug():\n    assert False\n"):
    return {
        "id": "f1", "category": "bug", "severity": "WARNING",
        "validator_status": "passed",
        "evidence": {"test_language": "python", "test": code},
    }


class TestRunBugFindingSandboxed:
    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        return tmp_path

    def test_never_invokes_host_toolchain_directly(self, tmp_path, monkeypatch):
        """Every subprocess call MUST be `docker`; never pytest/npm/go on host."""
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return _FakeProc(returncode=1, stdout="AssertionError")

        monkeypatch.setattr(R.subprocess, "run", fake_run)
        tc = R.detect_toolchain(self._project(tmp_path))
        R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                          tmp_path)
        assert calls, "expected the runner to execute a command"
        for cmd in calls:
            assert cmd[0] == "docker", f"host execution leaked: {cmd}"

    def test_failing_test_confirms_bug(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            R.subprocess, "run",
            lambda *a, **k: _FakeProc(returncode=1, stdout="AssertionError"))
        tc = R.detect_toolchain(self._project(tmp_path))
        out = R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                                tmp_path)
        assert out["runner_status"] == "confirmed"
        # Surviving test kept for the human reviewer.
        assert (tmp_path / "review-tests" / "test_review_f1.py").exists()

    def test_passing_test_is_dropped_and_file_removed(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.setattr(
            R.subprocess, "run",
            lambda *a, **k: _FakeProc(returncode=0, stdout="1 passed"))
        tc = R.detect_toolchain(self._project(tmp_path))
        out = R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                                tmp_path)
        assert out["runner_status"] == "unproven"
        assert not (tmp_path / "review-tests" / "test_review_f1.py").exists()

    def test_docker_missing_is_sandbox_unavailable(self, tmp_path, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError("docker")

        monkeypatch.setattr(R.subprocess, "run", boom)
        tc = R.detect_toolchain(self._project(tmp_path))
        out = R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                                tmp_path)
        assert out["runner_status"] == "sandbox_unavailable"
        assert out.get("runner_reason")
        # Finding survives: kept file for the human.
        assert (tmp_path / "review-tests" / "test_review_f1.py").exists()

    def test_timeout_is_sandbox_unavailable(self, tmp_path, monkeypatch):
        def slow(*a, **k):
            raise R.subprocess.TimeoutExpired(cmd="docker", timeout=1)

        monkeypatch.setattr(R.subprocess, "run", slow)
        tc = R.detect_toolchain(self._project(tmp_path))
        out = R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                                tmp_path)
        assert out["runner_status"] == "sandbox_unavailable"

    def test_missing_dep_survives_as_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            R.subprocess, "run",
            lambda *a, **k: _FakeProc(
                returncode=1,
                stdout="ModuleNotFoundError: No module named 'projectlib'"))
        tc = R.detect_toolchain(self._project(tmp_path))
        out = R.run_bug_finding(_bug_finding(), tc, tmp_path / "review-tests",
                                tmp_path)
        assert out["runner_status"] == "sandbox_unavailable"
