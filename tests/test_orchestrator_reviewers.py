# ABOUTME: Security-invariant tests for orchestrator reviewer calls (key redaction, argv hygiene)
# ABOUTME: Mocks subprocess/key reads; locks in that API keys never reach ps-visible argv or logs

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import orchestrator as O


SECRET = "sk-super-secret-key-value-1234567890"


def _completed(returncode: int, stdout: str = "", stderr: str = "",
               args: list[str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=args or ["docker"], returncode=returncode,
        stdout=stdout, stderr=stderr,
    )


@pytest.fixture
def prompt_file(tmp_path: Path) -> Path:
    p = tmp_path / "prompt.txt"
    p.write_text("review this diff")
    return p


def _mounts(cmd: list[str]) -> list[str]:
    """Return every mount spec that follows a `-v` flag in the argv."""
    return [cmd[i + 1] for i, tok in enumerate(cmd)
            if tok == "-v" and i + 1 < len(cmd)]


# ---------- _classify_failure ----------

class TestClassifyFailureRedaction:
    def test_secret_replaced_with_stars(self, capsys):
        proc = _completed(1, stderr=f"boom: leaked {SECRET} here")
        O._classify_failure("gemini", proc, secret=SECRET)
        err = capsys.readouterr().err
        assert "***" in err
        assert SECRET not in err

    def test_no_secret_arg_still_logs_tail(self, capsys):
        proc = _completed(1, stderr="plain error line")
        O._classify_failure("claude", proc)
        err = capsys.readouterr().err
        assert "plain error line" in err


class TestClassifyFailureAuth:
    @pytest.mark.parametrize("blob", [
        "Error: invalid authentication token",
        "HTTP 403 Unauthorized",
        "request failed with 401: auth token rejected",
    ])
    def test_auth_failure_prints_relogin_hint(self, capsys, blob):
        proc = _completed(1, stderr=blob)
        O._classify_failure("gemini", proc)
        err = capsys.readouterr().err
        assert "auth" in err.lower()
        assert "re-login" in err.lower()

    def test_auth_hint_redacts_nothing_but_never_leaks_secret(self, capsys):
        # Even on the auth path, a secret in the blob must not be echoed.
        proc = _completed(1, stderr=f"invalid authentication {SECRET}")
        O._classify_failure("gemini", proc, secret=SECRET)
        err = capsys.readouterr().err
        assert SECRET not in err


class TestClassifyFailureNonAuth:
    def test_empty_output_reports_no_output(self, capsys):
        proc = _completed(7, stdout="", stderr="")
        O._classify_failure("deepseek", proc)
        err = capsys.readouterr().err
        assert "no output" in err
        assert "exit 7" in err

    def test_non_auth_reports_exit_code_and_last_line(self, capsys):
        proc = _completed(2, stderr="first line\nlast meaningful line")
        O._classify_failure("claude", proc)
        err = capsys.readouterr().err
        assert "exit 2" in err
        assert "last meaningful line" in err
        assert "first line" not in err

    def test_prefers_stderr_tail_over_stdout(self, capsys):
        proc = _completed(3, stdout="stdout tail", stderr="stderr tail")
        O._classify_failure("claude", proc)
        err = capsys.readouterr().err
        assert "stderr tail" in err


# ---------- run_gemini / run_deepseek key hygiene ----------

class TestGeminiKeyHygiene:
    def test_key_value_absent_from_argv_name_only_form(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_gemini(prompt_file, Path("/fake/repo"))
        cmd = mrun.call_args[0][0]
        # Secret never appears anywhere in the ps-visible argv.
        assert all(SECRET not in tok for tok in cmd)
        # Name-only env passthrough: `-e GEMINI_API_KEY` with no `=value`
        # (other -e entries, e.g. the egress proxy vars, may precede it).
        assert "GEMINI_API_KEY" in cmd
        assert cmd[cmd.index("GEMINI_API_KEY") - 1] == "-e"
        assert not any(tok.startswith("GEMINI_API_KEY=") for tok in cmd)

    def test_key_value_injected_via_subprocess_env(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_gemini(prompt_file, Path("/fake/repo"))
        env = mrun.call_args.kwargs["env"]
        assert env["GEMINI_API_KEY"] == SECRET


class TestDeepseekKeyHygiene:
    def test_key_value_absent_from_argv_name_only_form(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_deepseek(prompt_file, Path("/fake/repo"))
        cmd = mrun.call_args[0][0]
        assert all(SECRET not in tok for tok in cmd)
        assert "DEEPSEEK_API_KEY" in cmd
        assert cmd[cmd.index("DEEPSEEK_API_KEY") - 1] == "-e"
        assert not any(tok.startswith("DEEPSEEK_API_KEY=") for tok in cmd)

    def test_key_value_injected_via_subprocess_env(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_deepseek(prompt_file, Path("/fake/repo"))
        env = mrun.call_args.kwargs["env"]
        assert env["DEEPSEEK_API_KEY"] == SECRET


# ---------- read-only project mounts ----------

class TestReadOnlyMounts:
    def test_claude_mounts_all_read_only(self, prompt_file):
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_claude(prompt_file, Path("/fake/repo"))
        cmd = mrun.call_args[0][0]
        mounts = _mounts(cmd)
        assert mounts, "expected at least one -v mount"
        assert all(m.endswith(":ro") for m in mounts)

    def test_gemini_mounts_all_read_only(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_gemini(prompt_file, Path("/fake/repo"))
        cmd = mrun.call_args[0][0]
        mounts = _mounts(cmd)
        assert mounts, "expected at least one -v mount"
        assert all(m.endswith(":ro") for m in mounts)

    def test_deepseek_mounts_all_read_only(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as mrun:
            O.run_deepseek(prompt_file, Path("/fake/repo"))
        cmd = mrun.call_args[0][0]
        mounts = _mounts(cmd)
        assert mounts, "expected at least one -v mount"
        assert all(m.endswith(":ro") for m in mounts)


# ---------- failure and timeout handling ----------

class TestFailureHandling:
    def test_claude_nonzero_returns_empty(self, prompt_file, capsys):
        with patch.object(O.subprocess, "run",
                          return_value=_completed(1, stderr="crash")):
            out = O.run_claude(prompt_file, Path("/fake/repo"))
        assert out == ""
        assert "claude: FAILED" in capsys.readouterr().err

    def test_gemini_nonzero_returns_empty_and_redacts(self, prompt_file, monkeypatch, capsys):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(1, stderr=f"boom {SECRET}")):
            out = O.run_gemini(prompt_file, Path("/fake/repo"))
        assert out == ""
        err = capsys.readouterr().err
        assert SECRET not in err

    def test_deepseek_nonzero_returns_empty_and_redacts(self, prompt_file, monkeypatch, capsys):
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(1, stderr=f"boom {SECRET}")):
            out = O.run_deepseek(prompt_file, Path("/fake/repo"))
        assert out == ""
        err = capsys.readouterr().err
        assert SECRET not in err


class TestTimeoutHandling:
    def test_claude_timeout_returns_empty_and_logs(self, prompt_file, capsys):
        with patch.object(O.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=1)):
            out = O.run_claude(prompt_file, Path("/fake/repo"))
        assert out == ""
        assert "timeout" in capsys.readouterr().err.lower()

    def test_gemini_timeout_returns_empty_and_logs(self, prompt_file, monkeypatch, capsys):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=1)):
            out = O.run_gemini(prompt_file, Path("/fake/repo"))
        assert out == ""
        assert "timeout" in capsys.readouterr().err.lower()

    def test_deepseek_timeout_returns_empty_and_logs(self, prompt_file, monkeypatch, capsys):
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=1)):
            out = O.run_deepseek(prompt_file, Path("/fake/repo"))
        assert out == ""
        assert "timeout" in capsys.readouterr().err.lower()


# ---------- gemini output cleaning ----------

class TestGeminiOutputCleaning:
    def test_strips_warn_and_warning_noise_lines(self, prompt_file, monkeypatch):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        raw = (
            "[WARN] Skipping unreadable /workspace/foo\n"
            "real finding one\n"
            "Warning: Could not read /workspace/bar\n"
            "[STARTUP] Phase 'cleanup_ops' was started but never ended.\n"
            "real finding two\n"
        )
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout=raw)):
            out = O.run_gemini(prompt_file, Path("/fake/repo"))
        assert "[WARN] Skipping unreadable" not in out
        assert "Warning: Could not read" not in out
        assert "[STARTUP]" not in out
        assert "real finding one" in out
        assert "real finding two" in out


# ---------- Prompt via stdin (ARG_MAX) ----------

def _run_calls(mock):
    """(cmd, kwargs) for every subprocess.run call on the mock."""
    return [(c.args[0], c.kwargs) for c in mock.call_args_list]


class TestPromptViaStdin:
    """The prompt (up to 4000-line chunks) must reach the container via
    stdin, never as a docker argv element (ARG_MAX)."""

    @pytest.mark.parametrize("runner", ["run_claude", "run_gemini",
                                        "run_deepseek"])
    def test_prompt_absent_from_argv_and_passed_as_input(
            self, prompt_file, monkeypatch, runner):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as m:
            getattr(O, runner)(prompt_file, Path("/fake/repo"))
        cmd, kwargs = _run_calls(m)[0]
        assert all("review this diff" not in tok for tok in cmd)
        assert kwargs.get("input") == "review this diff"
        assert "-i" in cmd


# ---------- Egress guard ----------

class TestEgressGuardArgs:
    """Reviewers consume untrusted diffs while holding live creds; by
    default they must join the internal egress network and speak only
    through the allowlisting proxy."""

    @pytest.mark.parametrize("runner", ["run_claude", "run_gemini",
                                        "run_deepseek"])
    def test_default_attaches_internal_network_and_proxy_env(
            self, prompt_file, monkeypatch, runner):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as m:
            getattr(O, runner)(prompt_file, Path("/fake/repo"))
        cmd, _ = _run_calls(m)[0]
        joined = " ".join(cmd)
        assert f"--network {O.EGRESS_NETWORK}" in joined
        proxy = f"http://{O.EGRESS_PROXY_NAME}:{O.EGRESS_PROXY_PORT}"
        assert f"HTTPS_PROXY={proxy}" in cmd[cmd.index("-e") :]
        assert any(tok == f"HTTP_PROXY={proxy}" for tok in cmd)
        assert any(tok.startswith("NO_PROXY=") for tok in cmd)

    @pytest.mark.parametrize("runner", ["run_claude", "run_gemini",
                                        "run_deepseek"])
    def test_egress_false_leaves_network_open(self, prompt_file,
                                              monkeypatch, runner):
        monkeypatch.setattr(O, "_read_gemini_key", lambda: SECRET)
        monkeypatch.setattr(O, "_read_deepseek_key", lambda: SECRET)
        with patch.object(O.subprocess, "run",
                          return_value=_completed(0, stdout="ok")) as m:
            getattr(O, runner)(prompt_file, Path("/fake/repo"), egress=False)
        cmd, _ = _run_calls(m)[0]
        assert "--network" not in cmd
        assert not any("PROXY" in tok for tok in cmd)


class TestSquidConf:
    def test_allowlist_hosts_and_default_deny(self):
        conf = O._squid_conf()
        for host in O.EGRESS_ALLOWED_HOSTS:
            assert host in conf
        assert "http_access deny all" in conf
        # exact hosts only: a leading-dot dstdomain token is a wildcard and
        # would reopen exfil channels like storage.googleapis.com
        acl_line = next(ln for ln in conf.splitlines()
                        if ln.startswith("acl allowed dstdomain"))
        hosts = acl_line.split()[3:]
        assert hosts and not any(h.startswith(".") for h in hosts)


class TestEnsureEgressGuard:
    def _mock_docker(self, responses):
        """subprocess.run mock keyed on the docker subcommand tuple."""
        def fake_run(cmd, **kwargs):
            for key, rc in responses.items():
                if list(key) == cmd[:len(key)]:
                    return _completed(rc, args=cmd)
            return _completed(0, args=cmd)
        return fake_run

    def test_creates_internal_network_when_missing(self, tmp_path,
                                                   monkeypatch):
        monkeypatch.setattr(O, "EGRESS_CONF_PATH", tmp_path / "squid.conf")
        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:3] == ["docker", "network", "inspect"]:
                return _completed(1, args=cmd)
            if cmd[:2] == ["docker", "inspect"]:
                return _completed(0, stdout="true\n", args=cmd)
            return _completed(0, args=cmd)
        with patch.object(O.subprocess, "run", side_effect=fake_run):
            assert O.ensure_egress_guard() is True
        create = next(c for c in calls
                      if c[:3] == ["docker", "network", "create"])
        assert "--internal" in create
        assert O.EGRESS_NETWORK in create

    def test_returns_false_when_network_create_fails(self, tmp_path,
                                                     monkeypatch):
        monkeypatch.setattr(O, "EGRESS_CONF_PATH", tmp_path / "squid.conf")
        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["docker", "network", "inspect"]:
                return _completed(1, args=cmd)
            if cmd[:3] == ["docker", "network", "create"]:
                return _completed(1, stderr="cannot create", args=cmd)
            return _completed(0, args=cmd)
        with patch.object(O.subprocess, "run", side_effect=fake_run):
            assert O.ensure_egress_guard() is False

    def test_recreates_proxy_when_conf_changed(self, tmp_path, monkeypatch):
        conf_path = tmp_path / "squid.conf"
        conf_path.write_text("stale config")
        monkeypatch.setattr(O, "EGRESS_CONF_PATH", conf_path)
        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["docker", "inspect"]:
                return _completed(0, stdout="true\n", args=cmd)
            return _completed(0, args=cmd)
        with patch.object(O.subprocess, "run", side_effect=fake_run):
            assert O.ensure_egress_guard() is True
        assert any(c[:3] == ["docker", "rm", "-f"] for c in calls)
        assert conf_path.read_text() == O._squid_conf()
