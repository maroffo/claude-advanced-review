# ABOUTME: E2E regression tests for the orchestrator pipeline
# ABOUTME: Stubs Docker/LLM calls with canned responses; runs real validator + merge

from __future__ import annotations

import json
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

        annotated = MG.annotate_with_verdicts(surviving, claude_verdicts,
                                              gemini_verdicts)
        by_id = {f["id"]: f for f in annotated}

        # c1: both ACCEPT -> HIGH_CONFIDENCE
        assert by_id["c1"]["confidence"] == "HIGH_CONFIDENCE"

        # c2: Claude ACCEPT + Gemini MODIFY -> MODIFIED, severity bumped to CRITICAL
        assert by_id["c2"]["confidence"] == "MODIFIED"
        assert by_id["c2"]["severity"] == "CRITICAL"

        # Report generation smoke test
        report = MG.build_report(annotated)
        assert "HIGH_CONFIDENCE" in report
        assert "MODIFIED" in report
        assert "CWE-89" in report

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
        assert cv["validator_status"] == "passed", cv

        annotated = MG.annotate_with_verdicts(
            [validated], {"c1": cv}, {"c1": gv}
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
        assert cv["validator_status"] == "discarded"
        assert cv["effective_verdict"] == "ACCEPT"

        annotated = MG.annotate_with_verdicts(
            [validated], {"c1": cv}, {"c1": gv}
        )
        # REFUTE discarded -> treated as ACCEPT -> both ACCEPT -> HIGH_CONFIDENCE
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

    def test_empty_input(self):
        assert O.extract_json("") == {}

    def test_malformed_returns_empty(self):
        assert O.extract_json("not json at all [unclosed") == {}
