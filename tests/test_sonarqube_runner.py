# ABOUTME: Unit tests for runner/sonarqube_runner.py API parsing and mapping
# ABOUTME: Mocks Docker subprocess and HTTP API calls; real SonarQube covered by E2E

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch


from runner import sonarqube_runner as SQ


# ---------- Sample API response ----------

SONAR_ISSUES_RESPONSE = {
    "paging": {"pageIndex": 1, "pageSize": 500, "total": 3},
    "issues": [
        {
            "key": "AYx-bug-001",
            "rule": "go:S1192",
            "severity": "MAJOR",
            "component": "cli-review:cmd/main.go",
            "project": "cli-review",
            "line": 81,
            "textRange": {
                "startLine": 81, "endLine": 81,
                "startOffset": 4, "endOffset": 28,
            },
            "message": "Define a constant instead of duplicating this literal 3 times.",
            "type": "CODE_SMELL",
            "effort": "10min",
            "tags": ["convention"],
        },
        {
            "key": "AYx-vuln-002",
            "rule": "go:S2077",
            "severity": "CRITICAL",
            "component": "cli-review:api/handler.go",
            "project": "cli-review",
            "line": 42,
            "textRange": {
                "startLine": 42, "endLine": 42,
                "startOffset": 0, "endOffset": 60,
            },
            "message": "Make sure that formatting this SQL query is safe here.",
            "type": "VULNERABILITY",
            "effort": "30min",
            "tags": ["cwe", "sql", "owasp-a1"],
        },
        {
            "key": "AYx-bug-003",
            "rule": "go:S1144",
            "severity": "BLOCKER",
            "component": "cli-review:internal/core.go",
            "project": "cli-review",
            "line": 15,
            "textRange": {
                "startLine": 15, "endLine": 15,
                "startOffset": 0, "endOffset": 40,
            },
            "message": "Remove this unused private method.",
            "type": "BUG",
            "effort": "5min",
            "tags": [],
        },
    ],
    "components": [],
    "rules": [],
}


# ---------- map_result tests ----------

class TestMapResult:
    def test_maps_severity_major_to_warning(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["severity"] == "WARNING"

    def test_maps_severity_critical_to_critical(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][1])
        assert f["severity"] == "CRITICAL"

    def test_maps_severity_blocker_to_critical(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][2])
        assert f["severity"] == "CRITICAL"

    def test_extracts_file_strips_project_prefix(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["file"] == "cmd/main.go"

    def test_extracts_line(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["line"] == 81

    def test_category_vulnerability_to_security(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][1])
        assert f["category"] == "security"

    def test_category_code_smell_to_quality(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["category"] == "quality"

    def test_category_bug_to_bug(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][2])
        assert f["category"] == "bug"

    def test_source_tagged_sonarqube(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["source"] == "sonarqube"

    def test_validator_status_passed(self):
        """SonarQube findings are ground truth, bypass validator."""
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["validator_status"] == "passed"

    def test_evidence_contains_rule_id(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["evidence"]["rule_id"] == "go:S1192"

    def test_evidence_contains_effort(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["evidence"]["effort"] == "10min"

    def test_id_format(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert f["id"].startswith("sonarqube-")
        assert "cmd/main.go" in f["id"]
        assert "81" in f["id"]

    def test_problem_from_message(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert "duplicating this literal" in f["problem"]

    def test_suggestion_references_rule(self):
        f = SQ.map_result(SONAR_ISSUES_RESPONSE["issues"][0])
        assert "go:S1192" in f["suggestion"]

    def test_missing_line_defaults_to_zero(self):
        issue = {**SONAR_ISSUES_RESPONSE["issues"][0]}
        del issue["line"]
        f = SQ.map_result(issue)
        assert f["line"] == 0

    def test_missing_component_uses_empty_file(self):
        issue = {**SONAR_ISSUES_RESPONSE["issues"][0]}
        del issue["component"]
        f = SQ.map_result(issue)
        assert f["file"] == ""


# ---------- parse_output tests ----------

class TestParseOutput:
    def test_converts_all_issues(self):
        out = SQ.parse_output(SONAR_ISSUES_RESPONSE["issues"])
        assert len(out) == 3

    def test_empty_issues_returns_empty(self):
        out = SQ.parse_output([])
        assert out == []

    def test_preserves_order(self):
        out = SQ.parse_output(SONAR_ISSUES_RESPONSE["issues"])
        assert out[0]["file"] == "cmd/main.go"
        assert out[1]["file"] == "api/handler.go"
        assert out[2]["file"] == "internal/core.go"


# ---------- generate_project_key tests ----------

class TestGenerateProjectKey:
    @patch("runner.sonarqube_runner._git_cmd")
    def test_includes_repo_name(self, mock_git):
        mock_git.side_effect = [
            "my-project",     # repo name
            "feat/something", # branch
            "abc1234",        # short sha
        ]
        key = SQ.generate_project_key(Path("/fake/repo"))
        assert "my-project" in key

    @patch("runner.sonarqube_runner._git_cmd")
    def test_includes_branch(self, mock_git):
        mock_git.side_effect = ["repo", "feat/something", "abc1234"]
        key = SQ.generate_project_key(Path("/fake/repo"))
        assert "feat-something" in key  # slashes replaced

    @patch("runner.sonarqube_runner._git_cmd")
    def test_includes_short_sha(self, mock_git):
        mock_git.side_effect = ["repo", "main", "abc1234"]
        key = SQ.generate_project_key(Path("/fake/repo"))
        assert "abc1234" in key

    @patch("runner.sonarqube_runner._git_cmd")
    def test_sanitizes_special_chars(self, mock_git):
        mock_git.side_effect = ["my project!", "feat/bar@baz", "abc1234"]
        key = SQ.generate_project_key(Path("/fake/repo"))
        assert " " not in key
        assert "!" not in key
        assert "@" not in key


# ---------- fetch_issues tests ----------

class TestFetchIssues:
    @patch("runner.sonarqube_runner.requests.get")
    def test_single_page(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SONAR_ISSUES_RESPONSE
        mock_get.return_value = mock_resp

        issues = SQ.fetch_issues("cli-review", "tok-123", "http://localhost:9000")
        assert len(issues) == 3
        mock_get.assert_called_once()

    @patch("runner.sonarqube_runner.requests.get")
    def test_pagination(self, mock_get):
        page1 = {
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 3},
            "issues": SONAR_ISSUES_RESPONSE["issues"][:2],
        }
        page2 = {
            "paging": {"pageIndex": 2, "pageSize": 2, "total": 3},
            "issues": SONAR_ISSUES_RESPONSE["issues"][2:],
        }
        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.json.return_value = page1
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.json.return_value = page2
        mock_get.side_effect = [resp1, resp2]

        issues = SQ.fetch_issues("cli-review", "tok-123", "http://localhost:9000",
                                 page_size=2)
        assert len(issues) == 3

    @patch("runner.sonarqube_runner.requests.get")
    def test_api_error_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.raise_for_status.side_effect = Exception("server error")
        mock_get.return_value = mock_resp

        issues = SQ.fetch_issues("cli-review", "tok-123", "http://localhost:9000")
        assert issues == []


# ---------- ensure_running tests ----------

class TestEnsureRunning:
    @patch("runner.sonarqube_runner._container_running")
    def test_returns_true_when_already_running(self, mock_running):
        mock_running.return_value = True
        with patch("runner.sonarqube_runner._wait_for_ready", return_value=True):
            assert SQ.ensure_running() is True

    @patch("runner.sonarqube_runner._container_running")
    @patch("runner.sonarqube_runner._container_exists")
    @patch("subprocess.run")
    def test_starts_stopped_container(self, mock_run, mock_exists, mock_running):
        mock_running.return_value = False
        mock_exists.return_value = True
        mock_run.return_value = MagicMock(returncode=0)
        with patch("runner.sonarqube_runner._wait_for_ready", return_value=True):
            assert SQ.ensure_running() is True
        # Should have called docker start
        cmd_args = mock_run.call_args[0][0]
        assert "start" in cmd_args

    @patch("runner.sonarqube_runner._container_running")
    @patch("runner.sonarqube_runner._container_exists")
    @patch("subprocess.run")
    def test_creates_container_when_missing(self, mock_run, mock_exists, mock_running):
        mock_running.return_value = False
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=0)
        with patch("runner.sonarqube_runner._wait_for_ready", return_value=True):
            assert SQ.ensure_running() is True
        cmd_args = mock_run.call_args[0][0]
        assert "run" in cmd_args

    @patch("runner.sonarqube_runner._container_running")
    def test_returns_false_when_ready_timeout(self, mock_running):
        mock_running.return_value = True
        with patch("runner.sonarqube_runner._wait_for_ready", return_value=False):
            assert SQ.ensure_running() is False


# ---------- run_scan tests ----------

def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """Create a real repo and a linked worktree of it; return both roots."""
    main = (tmp_path / "main").resolve()
    main.mkdir()
    _git(main, "init", "-q")
    _git(main, "-c", "user.name=t", "-c", "user.email=t@example.com",
         "commit", "-q", "--allow-empty", "-m", "init")
    worktree = tmp_path.resolve() / "wt"
    _git(main, "worktree", "add", "-q", "-b", "wt", str(worktree))
    return main, worktree


def _scanner_cmd(project_root: Path, **kwargs) -> list[str]:
    """Run run_scan with real git but a fake docker; return the docker cmd."""
    real_run = subprocess.run
    docker_calls: list[list[str]] = []

    def fake_run(cmd, *args, **kw):
        if cmd and cmd[0] == "docker":
            docker_calls.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")
        return real_run(cmd, *args, **kw)

    with patch("subprocess.run", side_effect=fake_run):
        SQ.run_scan(project_root, "my-project", "tok-123",
                    "http://localhost:9000", **kwargs)
    assert len(docker_calls) == 1
    return docker_calls[0]


class TestRunScan:
    @patch("subprocess.run")
    def test_calls_scanner_with_correct_args(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        SQ.run_scan(Path("/fake/repo"), "my-project", "tok-123",
                    "http://localhost:9000")
        cmd = mock_run.call_args[0][0]
        assert "sonarsource/sonar-scanner-cli" in " ".join(cmd)
        assert any("sonar.projectKey=my-project" in arg for arg in cmd)
        assert any("sonar.qualitygate.wait=true" in arg for arg in cmd)

    @patch("subprocess.run")
    def test_uses_tmp_working_dir(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        SQ.run_scan(Path("/fake/repo"), "my-project", "tok-123",
                    "http://localhost:9000")
        cmd = " ".join(mock_run.call_args[0][0])
        assert "sonar.working.dir" in cmd or "scannerwork" not in cmd

    @patch("subprocess.run")
    def test_timeout_returns_false(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=300)
        result = SQ.run_scan(Path("/fake/repo"), "my-project", "tok-123",
                             "http://localhost:9000")
        assert result is False

    def test_linked_worktree_keeps_host_paths(self, tmp_path):
        # A linked worktree's .git is a file pointing into the main repo's git
        # dir, and that git dir records the worktree's host path as its work
        # tree. JGit needs both at their host paths: without the git dir the
        # scan exits 3 (RepositoryNotFoundException), and with the worktree
        # only at /usr/src every file is "ignored because of scm ignore
        # settings", so nothing is analyzed.
        main, worktree = _linked_worktree(tmp_path)
        cmd = _scanner_cmd(worktree, sources=["infra/modules"])
        assert f"{main}/.git:{main}/.git:ro" in cmd
        assert f"{worktree}:{worktree}:ro" in cmd
        assert f"-Dsonar.projectBaseDir={worktree}" in cmd
        assert f"-Dsonar.sources={worktree}/infra/modules" in cmd
        assert not any(":/usr/src" in arg for arg in cmd)

    def test_planted_git_file_does_not_mount_another_repo(self, tmp_path):
        # `.git` is repo content. A hand-written gitdir/commondir pair makes
        # git report any repo's git dir as the common dir; mounting it would
        # hand that repo (config included) to the scanner container.
        other = (tmp_path / "other").resolve()
        other.mkdir()
        _git(other, "init", "-q")
        root = (tmp_path / "planted").resolve()
        (root / "g").mkdir(parents=True)
        (root / ".git").write_text("gitdir: ./g\n")
        (root / "g" / "HEAD").write_text("ref: refs/heads/x\n")
        (root / "g" / "commondir").write_text(f"{other}/.git\n")
        cmd = _scanner_cmd(root)
        assert f"{root}:/usr/src:ro" in cmd
        assert not any(str(other) in arg for arg in cmd)

    @patch("runner.sonarqube_runner._git_cmd",
           return_value="--path-format=absolute\n.git")
    def test_unusable_git_output_falls_back_to_usr_src(self, mock_git,
                                                        tmp_path):
        # git < 2.31 echoes the unknown --path-format flag back on stdout.
        root = tmp_path.resolve()
        (root / ".git").write_text("gitdir: /somewhere/.git/worktrees/wt\n")
        cmd = _scanner_cmd(root)
        assert f"{root}:/usr/src:ro" in cmd
        assert not any("sonar.projectBaseDir" in arg for arg in cmd)

    @patch("runner.sonarqube_runner._git_cmd")
    @patch("subprocess.run")
    def test_regular_checkout_mounts_at_usr_src(self, mock_run, mock_git,
                                                tmp_path):
        root = tmp_path.resolve()
        (root / ".git").mkdir()
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        SQ.run_scan(root, "my-project", "tok-123", "http://localhost:9000",
                    sources=["infra/modules"])
        cmd = mock_run.call_args[0][0]
        assert f"{root}:/usr/src:ro" in cmd
        assert "-Dsonar.sources=/usr/src/infra/modules" in cmd
        assert not any("sonar.projectBaseDir" in arg for arg in cmd)
        mock_git.assert_not_called()


# ---------- cleanup_old_projects tests ----------

class TestCleanupOldProjects:
    @patch("runner.sonarqube_runner.requests.get")
    @patch("runner.sonarqube_runner.requests.post")
    def test_deletes_old_projects(self, mock_post, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
            "components": [
                {
                    "key": "old-project_main_abc1234",
                    "lastAnalysisDate": "2020-01-01T00:00:00+0000",
                },
            ],
        }
        mock_get.return_value = mock_resp
        mock_post.return_value = MagicMock(status_code=204)

        SQ.cleanup_old_projects("tok-123", "http://localhost:9000",
                                max_age_hours=24)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "old-project_main_abc1234" in str(call_kwargs)

    @patch("runner.sonarqube_runner.requests.get")
    def test_skips_recent_projects(self, mock_get):
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
            "components": [
                {"key": "recent-project", "lastAnalysisDate": now_iso},
            ],
        }
        mock_get.return_value = mock_resp

        with patch("runner.sonarqube_runner.requests.post") as mock_post:
            SQ.cleanup_old_projects("tok-123", "http://localhost:9000",
                                    max_age_hours=24)
            mock_post.assert_not_called()
