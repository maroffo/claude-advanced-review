# ABOUTME: E2E regression tests for the orchestrator pipeline
# ABOUTME: Stubs Docker/LLM calls with canned responses; runs real validator + merge

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from validator import validator as V
from merge import merger as MG
import orchestrator as O


FIXTURE = Path(__file__).resolve().parent.parent / "fixture-repo"


# ---------- Canned reviewer outputs ----------

CLAUDE_ROUND1_RAW = """Brief reasoning omitted.

```json
{
  "findings": [
    {
      "id": "c1",
      "category": "security",
      "severity": "CRITICAL",
      "file": "app.py",
      "line": 15,
      "problem": "User input is concatenated into a raw SQL string.",
      "suggestion": "Use a parameterized query.",
      "evidence": {
        "cwe_id": "CWE-89",
        "cwe_url": "https://cwe.mitre.org/data/definitions/89.html"
      }
    },
    {
      "id": "c2",
      "category": "bug",
      "severity": "WARNING",
      "file": "app.py",
      "line": 21,
      "problem": "divide() no longer guards against b == 0.",
      "suggestion": "Re-add the ValueError on b == 0.",
      "evidence": {
        "test_language": "python",
        "test_target_file": "tests/test_app.py",
        "test_modifies_existing": false,
        "test": "from app import UserService\\nimport pytest\\n\\ndef test_divide_by_zero_raises():\\n    svc = UserService(None)\\n    with pytest.raises(ValueError):\\n        svc.divide(1, 0)\\n"
      }
    },
    {
      "id": "c3",
      "category": "security",
      "severity": "CRITICAL",
      "file": "app.py",
      "line": 15,
      "problem": "HALLUCINATED claim — wrong CWE id.",
      "suggestion": "N/A",
      "evidence": {
        "cwe_id": "CWE-99999",
        "cwe_url": "https://cwe.mitre.org/data/definitions/99999.html"
      }
    }
  ],
  "summary": "2 real, 1 hallucinated."
}
```
"""

GEMINI_ROUND1_RAW = """```json
{
  "findings": [
    {
      "id": "g1",
      "category": "bug",
      "severity": "WARNING",
      "file": "app.py",
      "line": 21,
      "problem": "Division by zero not handled.",
      "suggestion": "Guard with b != 0.",
      "evidence": {
        "test_language": "python",
        "test_target_file": "tests/test_app.py",
        "test_modifies_existing": false,
        "test": "def test_math():\\n    assert 2 + 2 == 4\\n"
      }
    }
  ],
  "summary": "1 (but the test is unrelated to the diff)."
}
```
"""

CLAUDE_ROUND2_RAW = """```json
{
  "verdicts": [
    {"finding_id": "c1", "verdict": "ACCEPT"},
    {"finding_id": "c2", "verdict": "ACCEPT"}
  ],
  "summary": "2 ACCEPT."
}
```
"""

GEMINI_ROUND2_RAW = """```json
{
  "verdicts": [
    {"finding_id": "c1", "verdict": "ACCEPT"},
    {"finding_id": "c2", "verdict": "MODIFY",
     "modification": {"severity": "CRITICAL", "rationale": "Zero-div crash at runtime."}}
  ],
  "summary": "1 ACCEPT, 1 MODIFY."
}
```
"""

DEEPSEEK_ROUND2_RAW = """```json
{
  "verdicts": [
    {"finding_id": "c1", "verdict": "ACCEPT"},
    {"finding_id": "c2", "verdict": "MODIFY",
     "modification": {"severity": "CRITICAL", "rationale": "Unhandled zero divisor."}}
  ],
  "summary": "1 ACCEPT, 1 MODIFY."
}
```
"""


# ---------- Helpers ----------

def _diff_text() -> str:
    return (FIXTURE / "diff.patch").read_text()


def _preseed_cwe_cache(monkeypatch, tmp_path):
    cache = tmp_path / "cwe.json"
    cache.write_text(json.dumps({"CWE-89": "SQL Injection"}))
    monkeypatch.setattr(V, "CWE_CACHE_PATH", cache)
    monkeypatch.setattr(V, "_download_cwe_list",
                        lambda: pytest.fail("should not download"))


# ---------- E2E: pipeline replay without Docker ----------

class TestPipelineReplay:
    """Drive the orchestrator pipeline by hand, stubbing Docker calls.

    This covers the filter/merge regression surface: we feed canned LLM
    outputs through the real validator, test-runner disposition logic
    (without executing tests), semgrep stub, and merger.
    """

    def test_hallucinated_cwe_is_dropped(self, tmp_path, monkeypatch):
        _preseed_cwe_cache(monkeypatch, tmp_path)
        # URL reachability must succeed for CWE-89 but we don't really hit the net.
        monkeypatch.setattr(V, "url_reachable", lambda url, timeout=5.0:
                            "89" in url)

        diff_text = _diff_text()
        diff = V.parse_diff(diff_text)
        cwe = V.CWEStore()

        raw = O.extract_json(CLAUDE_ROUND1_RAW)
        findings = raw["findings"]
        validated = [V.validate_finding(f, diff, cwe) for f in findings]

        # CWE-89 + valid URL -> passes
        c1 = next(f for f in validated if f["id"] == "c1")
        assert c1["validator_status"] == "passed"

        # c3 cites CWE-99999 which is absent from our canned cache
        c3 = next(f for f in validated if f["id"] == "c3")
        assert c3["validator_status"] == "dropped"
        assert any("cwe" in r.lower() for r in c3["validator_reasons"])

    def test_irrelevant_test_is_dropped(self, tmp_path, monkeypatch):
        _preseed_cwe_cache(monkeypatch, tmp_path)
        diff_text = _diff_text()
        diff = V.parse_diff(diff_text)
        cwe = V.CWEStore()

        g = O.extract_json(GEMINI_ROUND1_RAW)["findings"][0]
        result = V.validate_finding(g, diff, cwe)
        assert result["validator_status"] == "dropped"
        assert any("relevan" in r.lower() for r in result["validator_reasons"])

    def test_full_merge_high_confidence_vs_modified(self, tmp_path, monkeypatch):
        _preseed_cwe_cache(monkeypatch, tmp_path)
        monkeypatch.setattr(V, "url_reachable",
                            lambda url, timeout=5.0: "89" in url)

        diff_text = _diff_text()
        diff = V.parse_diff(diff_text)
        cwe = V.CWEStore()

        c = O.extract_json(CLAUDE_ROUND1_RAW)["findings"]
        g = O.extract_json(GEMINI_ROUND1_RAW)["findings"]
        for f in c:
            f["source"] = "claude"
        for f in g:
            f["source"] = "gemini"
        findings = c + g

        validated = [V.validate_finding(f, diff, cwe) for f in findings]
        surviving = [f for f in validated if f["validator_status"] == "passed"]

        # Round 2 verdicts
        claude_verdicts = {
            v["finding_id"]: V.validate_verdict(v, diff)
            for v in O.extract_json(CLAUDE_ROUND2_RAW)["verdicts"]
        }
        gemini_verdicts = {
            v["finding_id"]: V.validate_verdict(v, diff)
            for v in O.extract_json(GEMINI_ROUND2_RAW)["verdicts"]
        }
        deepseek_verdicts = {
            v["finding_id"]: V.validate_verdict(v, diff)
            for v in O.extract_json(DEEPSEEK_ROUND2_RAW)["verdicts"]
        }

        annotated = MG.annotate_with_verdicts(surviving, claude_verdicts,
                                              gemini_verdicts,
                                              deepseek_verdicts)
        by_id = {f["id"]: f for f in annotated}

        # c1: all three ACCEPT -> HIGH_CONFIDENCE
        assert by_id["c1"]["confidence"] == "HIGH_CONFIDENCE"

        # c2: Claude ACCEPT + Gemini/DeepSeek MODIFY -> majority MODIFY ->
        # MODIFIED, severity bumped to CRITICAL
        assert by_id["c2"]["confidence"] == "MODIFIED"
        assert by_id["c2"]["severity"] == "CRITICAL"

        # Report generation smoke test
        report = MG.build_report(annotated)
        assert "HIGH_CONFIDENCE" in report
        assert "MODIFIED" in report
        assert "CWE-89" in report
        assert "deepseek=" in report

    def test_disputed_when_refute_valid(self, tmp_path, monkeypatch):
        _preseed_cwe_cache(monkeypatch, tmp_path)
        monkeypatch.setattr(V, "url_reachable",
                            lambda url, timeout=5.0: "89" in url)

        diff_text = _diff_text()
        diff = V.parse_diff(diff_text)
        cwe = V.CWEStore()

        finding = O.extract_json(CLAUDE_ROUND1_RAW)["findings"][0]
        finding["source"] = "claude"
        validated = V.validate_finding(finding, diff, cwe)
        assert validated["validator_status"] == "passed"

        # Claude REFUTEs with valid diff citation; Gemini ACCEPTs.
        # Cited lines must actually be in the diff hunks; the diff parser
        # includes line 14 (context/added) in the patch. Use 14.
        refute = {
            "finding_id": "c1",
            "verdict": "REFUTE-BY-EXPLANATION",
            "diff_citations": [{"file": "app.py",
                                "line": sorted(diff.lines_for("app.py"))[0]}],
            "explanation": "Already parameterized one line above.",
        }
        accept = {"finding_id": "c1", "verdict": "ACCEPT"}
        cv = V.validate_verdict(refute, diff)
        gv = V.validate_verdict(accept, diff)
        dv = V.validate_verdict(dict(accept), diff)
        assert cv["validator_status"] == "passed", cv

        # Claude REFUTE (valid) + Gemini/DeepSeek ACCEPT: a disputed verdict
        # poisons the set regardless of the majority.
        annotated = MG.annotate_with_verdicts(
            [validated], {"c1": cv}, {"c1": gv}, {"c1": dv}
        )
        assert annotated[0]["confidence"] == "DISPUTED"

    def test_disputed_refute_is_discarded_when_citation_bad(
        self, tmp_path, monkeypatch
    ):
        _preseed_cwe_cache(monkeypatch, tmp_path)
        monkeypatch.setattr(V, "url_reachable",
                            lambda url, timeout=5.0: "89" in url)

        diff_text = _diff_text()
        diff = V.parse_diff(diff_text)
        cwe = V.CWEStore()

        finding = O.extract_json(CLAUDE_ROUND1_RAW)["findings"][0]
        finding["source"] = "claude"
        validated = V.validate_finding(finding, diff, cwe)

        bad_refute = {
            "finding_id": "c1",
            "verdict": "REFUTE-BY-EXPLANATION",
            "diff_citations": [{"file": "app.py", "line": 99999}],
            "explanation": "Cites a line that doesn't exist in diff.",
        }
        accept = {"finding_id": "c1", "verdict": "ACCEPT"}
        cv = V.validate_verdict(bad_refute, diff)
        gv = V.validate_verdict(accept, diff)
        dv = V.validate_verdict(dict(accept), diff)
        assert cv["validator_status"] == "discarded"
        assert cv["effective_verdict"] == "ACCEPT"

        annotated = MG.annotate_with_verdicts(
            [validated], {"c1": cv}, {"c1": gv}, {"c1": dv}
        )
        # REFUTE discarded -> ACCEPT -> three ACCEPT -> HIGH_CONFIDENCE
        assert annotated[0]["confidence"] == "HIGH_CONFIDENCE"


class TestJSONExtraction:
    def test_extracts_fenced_json(self):
        raw = "prose\n```json\n{\"a\": 1}\n```\ntrailing"
        assert O.extract_json(raw) == {"a": 1}

    def test_extracts_last_of_multiple_blocks(self):
        raw = "```json\n{\"a\": 1}\n```\n```json\n{\"b\": 2}\n```"
        assert O.extract_json(raw) == {"b": 2}

    def test_fallback_to_bare_json(self):
        raw = "here is the finding: {\"findings\": []} done"
        assert O.extract_json(raw) == {"findings": []}

    def test_bare_json_with_trailing_prose(self):
        # Finding 4: raw_decode from the first `{` stops at the end of the
        # object, so trailing prose after a valid object doesn't break parsing.
        assert O.extract_json('{"a": 1} trailing junk') == {"a": 1}

    def test_empty_input(self):
        assert O.extract_json("") == {}

    def test_malformed_returns_empty(self):
        assert O.extract_json("not json at all [unclosed") == {}


class TestParseFindings:
    """_parse_findings stamps deterministic, source-prefixed ids (finding 5)."""

    def test_overwrites_llm_id_and_preserves_original(self):
        raw = '```json\n{"findings": [{"id": "x1", "problem": "p"}]}\n```'
        out = O._parse_findings(
            (("claude", raw, "c"),),
            lambda prefix, seq: f"{prefix}-{seq + 1}")
        assert out[0]["id"] == "c-1"
        assert out[0]["original_id"] == "x1"
        assert out[0]["source"] == "claude"

    def test_colliding_ids_are_made_unique(self):
        # Two reviewers both emit id "dup"; deterministic ids must not collide.
        raw = '```json\n{"findings": [{"id": "dup", "problem": "p"}]}\n```'
        out = O._parse_findings(
            (("claude", raw, "c"), ("gemini", raw, "g")),
            lambda prefix, seq: f"{prefix}-{seq + 1}")
        assert [f["id"] for f in out] == ["c-1", "g-2"]
        assert all(f["original_id"] == "dup" for f in out)


# ---------- Full pipeline drive (real pipeline/pipeline_repo/main) ----------

# app.py before the staged change: parameterized query + zero-div guard.
_APP_BEFORE = '''\
import sqlite3


class UserService:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_by_name(self, username: str):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
        return cursor.fetchone()

    def divide(self, a: int, b: int) -> float:
        if b == 0:
            raise ValueError("divide by zero")
        return a / b
'''

# app.py after the staged change: SQL injection + guard removed (mirrors the
# fixture-repo bugs so the canned findings validate against the real diff).
_APP_AFTER = '''\
import sqlite3


class UserService:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_by_name(self, username: str):
        cursor = self.conn.cursor()
        # BUG: classic CWE-89 SQL injection via string concat.
        query = "SELECT * FROM users WHERE name = '" + username + "'"
        cursor.execute(query)
        return cursor.fetchone()

    def divide(self, a: int, b: int) -> float:
        # BUG: no zero-division guard.
        return a / b
'''

# Deepseek emits nothing in round 1 for these fixtures; the pipeline degrades
# to the survivors from the other two reviewers.
DEEPSEEK_ROUND1_EMPTY = '```json\n{"findings": []}\n```'

# Round-2 verdicts reference the *stamped* ids (c-1, c-2), not the LLM-supplied
# ids, plus the canned SonarQube CRITICAL finding pulled into the cross-check.
CROSS_CHECK_RAW = """```json
{
  "verdicts": [
    {"finding_id": "c-1", "verdict": "ACCEPT"},
    {"finding_id": "c-2", "verdict": "ACCEPT"},
    {"finding_id": "sonar-crit-1", "verdict": "ACCEPT"}
  ]
}
```
"""

SONAR_CRITICAL_FINDING = {
    "id": "sonar-crit-1",
    "category": "security",
    "severity": "CRITICAL",
    "file": "app.py",
    "line": 11,
    "problem": "SonarQube ground-truth: tainted input reaches SQL.",
    "suggestion": "Use a prepared statement.",
    "evidence": {"rule_id": "python:S3649"},
    "source": "sonarqube",
    "validator_status": "passed",
    "validator_reasons": [],
}


def _init_git_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.io"], cwd=root,
                   check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)


def _fake_reviewers(round1: tuple[str, str, str], round2: str):
    """Stub for run_reviewers_parallel: dispatch on prompt content. The
    cross-check prompt carries a '## Findings to Evaluate' section that the
    round-1 prompt does not."""
    def stub(prompt_file, project_root):
        text = Path(prompt_file).read_text()
        if "Findings to Evaluate" in text:
            return round2, round2, round2
        return round1
    return stub


class TestPipelineEndToEnd:
    """Drive the real O.pipeline / O.pipeline_repo / O.main against a temporary
    git repo, stubbing only the Docker/LLM/SAST boundaries and validator net."""

    def _work_dir_factory(self, monkeypatch, tmp_path):
        """Redirect tempfile.mkdtemp into tmp_path and record created dirs."""
        created: list[Path] = []

        def fake_mkdtemp(prefix="wd-"):
            d = tmp_path / f"{prefix.rstrip('-')}-{len(created)}"
            d.mkdir()
            created.append(d)
            return str(d)

        monkeypatch.setattr(O.tempfile, "mkdtemp", fake_mkdtemp)
        return created

    def _common_stubs(self, monkeypatch, tmp_path, *, sonar=None):
        """Preseed the validator net + stub Semgrep. Returns a dict recording
        the diff_mode SonarQube was called with (None until called)."""
        _preseed_cwe_cache(monkeypatch, tmp_path)
        monkeypatch.setattr(V, "url_reachable",
                            lambda url, timeout=5.0: "89" in url)
        monkeypatch.setattr(O.SR, "run_semgrep",
                            lambda scan_root, *a, **k: "{}")
        sonar_call: dict = {"called": False, "diff_mode": "unset"}

        def fake_sonar(project_root, timeout=1800, diff_mode=None,
                       base_ref=None):
            sonar_call["called"] = True
            sonar_call["diff_mode"] = diff_mode
            return list(sonar or [])

        monkeypatch.setattr(O.SQ, "run_sonarqube", fake_sonar)
        return sonar_call

    def _staged_repo(self, tmp_path) -> Path:
        root = tmp_path / "repo"
        _init_git_repo(root)
        (root / "app.py").write_text(_APP_BEFORE)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=root,
                       check=True)
        # Stage the buggy change.
        (root / "app.py").write_text(_APP_AFTER)
        subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
        return root

    # ----- error-path exits -----

    def test_not_a_git_repo_exits_2(self, tmp_path, monkeypatch):
        self._work_dir_factory(monkeypatch, tmp_path)
        plain = tmp_path / "plain"
        plain.mkdir()
        rc = O.main(["--project-root", str(plain), "--all", "--no-preflight"])
        assert rc == 2

    def test_empty_diff_exits_1(self, tmp_path, monkeypatch):
        self._work_dir_factory(monkeypatch, tmp_path)
        root = tmp_path / "repo"
        _init_git_repo(root)
        (root / "app.py").write_text(_APP_BEFORE)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=root,
                       check=True)
        # Nothing staged -> git diff --cached is empty.
        rc = O.main(["--project-root", str(root), "--no-preflight"])
        assert rc == 1

    def test_preflight_failure_exits_3(self, tmp_path, monkeypatch):
        self._work_dir_factory(monkeypatch, tmp_path)
        root = self._staged_repo(tmp_path)
        monkeypatch.setattr(O.PF, "detect_check_target", lambda pr: True)
        monkeypatch.setattr(
            O.PF, "run_preflight",
            lambda pr, timeout=120: O.PF.PreflightResult(
                passed=False, exit_code=1, output="make check: 3 failures",
                was_skipped=False))
        rc = O.main(["--project-root", str(root)])
        assert rc == 3

    def test_missing_prompt_template_exits_2(self, tmp_path, monkeypatch):
        self._work_dir_factory(monkeypatch, tmp_path)
        self._common_stubs(monkeypatch, tmp_path)
        root = self._staged_repo(tmp_path)
        args = O._parse_args(["--project-root", str(root), "--no-preflight"])
        args.prompt = "does-not-exist"
        rc = O.pipeline(args)
        assert rc == 2

    def test_git_diff_failure_exits_2(self, tmp_path, monkeypatch):
        # Finding 6: git failure (None) is distinct from empty diff ("" -> 1).
        self._work_dir_factory(monkeypatch, tmp_path)
        root = self._staged_repo(tmp_path)
        monkeypatch.setattr(O, "generate_diff",
                            lambda project_root, mode, base: None)
        rc = O.main(["--project-root", str(root), "--no-preflight"])
        assert rc == 2

    # ----- happy paths -----

    def test_diff_mode_happy_path(self, tmp_path, monkeypatch):
        created = self._work_dir_factory(monkeypatch, tmp_path)
        sonar_call = self._common_stubs(monkeypatch, tmp_path,
                                        sonar=[SONAR_CRITICAL_FINDING])
        monkeypatch.setattr(
            O, "run_reviewers_parallel",
            _fake_reviewers((CLAUDE_ROUND1_RAW, GEMINI_ROUND1_RAW,
                             DEEPSEEK_ROUND1_EMPTY), CROSS_CHECK_RAW))
        root = self._staged_repo(tmp_path)

        rc = O.main(["--project-root", str(root), "--no-preflight",
                     "--no-test-runner", "--sonarqube"])
        assert rc == 0

        wd = created[-1]
        assert (wd / "report.md").exists()
        report = json.loads((wd / "report.json").read_text())
        ids = {f["id"] for f in report["findings"]}
        # Surviving LLM findings (stamped ids) + the SonarQube CRITICAL that
        # was pulled through the cross-check.
        assert "c-1" in ids  # SQL injection, survives validation
        assert "c-2" in ids  # zero-div bug, survives (test-runner skipped)
        assert "sonar-crit-1" in ids
        assert "c-3" not in ids  # hallucinated CWE, dropped by validator
        # Diff mode scopes the SonarQube scan to the diff.
        assert sonar_call["diff_mode"] == "staged"

    def test_repo_mode_sonar_scan_is_not_diff_scoped(self, tmp_path,
                                                     monkeypatch):
        # Finding 1: a --repo review must do a full SonarQube scan, so
        # diff_mode must be None (never the default "staged").
        self._work_dir_factory(monkeypatch, tmp_path)
        sonar_call = self._common_stubs(monkeypatch, tmp_path,
                                        sonar=[SONAR_CRITICAL_FINDING])
        monkeypatch.setattr(
            O, "run_reviewers_parallel",
            _fake_reviewers((CLAUDE_ROUND1_RAW, GEMINI_ROUND1_RAW,
                             DEEPSEEK_ROUND1_EMPTY), CROSS_CHECK_RAW))
        root = self._staged_repo(tmp_path)

        rc = O.main(["--project-root", str(root), "--repo", "--no-preflight",
                     "--sonarqube"])
        assert rc == 0
        assert sonar_call["called"] is True
        assert sonar_call["diff_mode"] is None
