# ABOUTME: Unit tests for merge.classify_confidence and build_report
# ABOUTME: 2-of-3 majority: >= 2 ACCEPT = HIGH_CONFIDENCE, any genuine REJECT/REFUTE = DISPUTED

from __future__ import annotations

from merge.merger import (
    annotate_with_verdicts,
    build_report,
    classify_confidence,
    deduplicate_findings,
)


def _accept(finding_id: str = "f1") -> dict:
    return {"finding_id": finding_id, "verdict": "ACCEPT",
            "validator_status": "passed"}


def _modify(finding_id: str = "f1", severity: str = "WARNING") -> dict:
    return {
        "finding_id": finding_id,
        "verdict": "MODIFY",
        "validator_status": "passed",
        "modification": {"severity": severity, "rationale": "x"},
    }


def _reject(finding_id: str = "f1") -> dict:
    return {
        "finding_id": finding_id,
        "verdict": "REJECT-WITH-COUNTER-EVIDENCE",
        "validator_status": "passed",
        "counter_evidence": {"type": "security", "payload": {}},
    }


def _refute(finding_id: str = "f1", discarded: bool = False) -> dict:
    v = {
        "finding_id": finding_id,
        "verdict": "REFUTE-BY-EXPLANATION",
        "diff_citations": [{"file": "x.py", "line": 42}],
        "explanation": "...",
    }
    if discarded:
        v["validator_status"] = "discarded"
        v["effective_verdict"] = "ACCEPT"
    else:
        v["validator_status"] = "passed"
    return v


class TestClassifyConfidence:
    """Three-reviewer (Claude + Gemini + DeepSeek) majority rubric: decided on
    the verdicts present, needs >= 2 ACCEPT for HIGH_CONFIDENCE, tolerates one
    missing reviewer."""

    def test_all_three_accept_is_high_confidence(self):
        assert classify_confidence([_accept(), _accept(), _accept()]) == \
               "HIGH_CONFIDENCE"

    def test_two_accept_one_modify_is_high_confidence(self):
        # Majority ACCEPT wins even with one dissenting MODIFY.
        assert classify_confidence([_accept(), _accept(), _modify()]) == \
               "HIGH_CONFIDENCE"

    def test_one_accept_two_modify_is_modified(self):
        assert classify_confidence([_accept(), _modify(), _modify()]) == \
               "MODIFIED"

    def test_all_modify_is_modified(self):
        assert classify_confidence([_modify(), _modify(), _modify()]) == \
               "MODIFIED"

    def test_any_reject_with_counter_is_disputed(self):
        assert classify_confidence([_accept(), _accept(), _reject()]) == \
               "DISPUTED"

    def test_valid_refute_is_disputed(self):
        assert classify_confidence([_accept(), _accept(), _refute()]) == \
               "DISPUTED"

    def test_refute_discarded_falls_back_to_accept(self):
        # Invalid citations -> REFUTE effectively ACCEPT -> 3 ACCEPT -> HIGH.
        assert classify_confidence(
            [_accept(), _accept(), _refute(discarded=True)]) == \
            "HIGH_CONFIDENCE"

    # --- graceful degradation: one reviewer missing (only 2 present) ---

    def test_two_present_both_accept_is_high_confidence(self):
        assert classify_confidence([_accept(), _accept(), None]) == \
               "HIGH_CONFIDENCE"

    def test_two_present_accept_plus_modify_is_modified(self):
        # No ACCEPT majority among present, one wants changes -> MODIFIED.
        assert classify_confidence([_accept(), _modify(), None]) == "MODIFIED"

    def test_two_present_one_disputed_is_disputed(self):
        assert classify_confidence([_accept(), _reject(), None]) == "DISPUTED"

    # --- fewer than 2 present: no majority possible ---

    def test_only_one_present_is_unverified(self):
        assert classify_confidence([_accept(), None, None]) == "UNVERIFIED"

    def test_lone_disputing_verdict_is_unverified_not_disputed(self):
        # A single surviving reviewer cannot form a majority: a lone refutation
        # is UNVERIFIED, not DISPUTED (needs corroboration).
        assert classify_confidence([_reject(), None, None]) == "UNVERIFIED"

    def test_none_present_is_unverified(self):
        assert classify_confidence([None, None, None]) == "UNVERIFIED"


class TestBuildReport:
    def test_includes_sonarqube_section(self):
        sonar = [{"severity": "WARNING", "file": "x.go", "line": 10,
                  "problem": "duplicated literal", "category": "quality",
                  "source": "sonarqube", "evidence": {"rule_id": "go:S1192"}}]
        report = build_report([], sonar_findings=sonar)
        assert "## SonarQube (ground truth)" in report
        assert "duplicated literal" in report

    def test_includes_semgrep_and_sonarqube_sections(self):
        semgrep = [{"severity": "CRITICAL", "file": "a.py", "line": 1,
                    "problem": "sqli", "category": "security",
                    "source": "semgrep", "evidence": {"cwe_id": "CWE-89"}}]
        sonar = [{"severity": "WARNING", "file": "b.go", "line": 5,
                  "problem": "smell", "category": "quality",
                  "source": "sonarqube", "evidence": {"rule_id": "go:S1"}}]
        report = build_report([], semgrep_findings=semgrep, sonar_findings=sonar)
        assert "## Semgrep (ground truth)" in report
        assert "## SonarQube (ground truth)" in report

    def test_summary_includes_sonarqube_count(self):
        sonar = [{"severity": "INFO", "file": "x.go", "line": 1,
                  "problem": "unused", "category": "quality",
                  "source": "sonarqube", "evidence": {}}]
        report = build_report([], sonar_findings=sonar)
        assert "1 from SonarQube" in report

    def test_no_sonarqube_section_when_empty(self):
        report = build_report([], sonar_findings=[])
        assert "## SonarQube (ground truth)" not in report


class TestDeduplicateFindings:
    def test_removes_exact_duplicates(self):
        findings = [
            {"file": "a.py", "category": "bug", "severity": "WARNING",
             "problem": "null check missing on user input"},
            {"file": "a.py", "category": "bug", "severity": "WARNING",
             "problem": "null check missing on user input"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_keeps_highest_severity(self):
        findings = [
            {"file": "a.py", "category": "security", "severity": "WARNING",
             "problem": "SQL injection in query builder"},
            {"file": "a.py", "category": "security", "severity": "CRITICAL",
             "problem": "SQL injection in query builder"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"

    def test_different_files_not_deduped(self):
        findings = [
            {"file": "a.py", "category": "bug", "severity": "WARNING",
             "problem": "same problem description here"},
            {"file": "b.py", "category": "bug", "severity": "WARNING",
             "problem": "same problem description here"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_categories_not_deduped(self):
        findings = [
            {"file": "a.py", "category": "bug", "severity": "WARNING",
             "problem": "issue with error handling"},
            {"file": "a.py", "category": "architecture", "severity": "WARNING",
             "problem": "issue with error handling"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_empty_input(self):
        assert deduplicate_findings([]) == []

    def test_near_duplicate_problems_deduped(self):
        # First 60 chars identical, differ only after that
        base = "Null pointer dereference when calling user.get_profile() on"
        findings = [
            {"file": "a.py", "category": "bug", "severity": "WARNING",
             "problem": base + " line 42 in the main handler"},
            {"file": "a.py", "category": "bug", "severity": "INFO",
             "problem": base + " line 99 in the background worker"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "WARNING"

    def test_keeps_highest_severity_when_seen_first(self):
        # Higher severity arrives first: it must be retained, not overwritten
        # by the later lower-severity duplicate.
        findings = [
            {"file": "a.py", "category": "security", "severity": "CRITICAL",
             "problem": "SQL injection in query builder"},
            {"file": "a.py", "category": "security", "severity": "WARNING",
             "problem": "SQL injection in query builder"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"


def _finding(fid: str = "f1", severity: str = "WARNING") -> dict:
    return {"id": fid, "severity": severity, "category": "bug",
            "file": "a.py", "line": 1, "problem": "p", "suggestion": "s"}


def _modify_verdict(fid: str = "f1", severity: str | None = None,
                    suggestion: str | None = None) -> dict:
    mod: dict = {}
    if severity is not None:
        mod["severity"] = severity
    if suggestion is not None:
        mod["suggestion"] = suggestion
    return {"finding_id": fid, "verdict": "MODIFY", "modification": mod,
            "validator_status": "passed"}


class TestModifySeverity:
    """annotate_with_verdicts must never let a MODIFY downgrade a finding, and
    the highest proposed severity wins when reviewers disagree."""

    def test_upgrade_is_applied_and_original_preserved(self):
        f = _finding(severity="INFO")
        v = _modify_verdict(severity="CRITICAL")
        out = annotate_with_verdicts([f], {"f1": v}, {})[0]
        assert out["severity"] == "CRITICAL"
        assert out["original_severity"] == "INFO"

    def test_downgrade_is_ignored(self):
        f = _finding(severity="CRITICAL")
        v = _modify_verdict(severity="INFO")
        out = annotate_with_verdicts([f], {"f1": v}, {})[0]
        assert out["severity"] == "CRITICAL"
        assert "original_severity" not in out

    def test_highest_wins_across_reviewers(self):
        f = _finding(severity="INFO")
        cv = _modify_verdict(severity="WARNING")
        gv = _modify_verdict(severity="CRITICAL")
        out = annotate_with_verdicts([f], {"f1": cv}, {"f1": gv})[0]
        assert out["severity"] == "CRITICAL"
        assert out["original_severity"] == "INFO"

    def test_equal_severity_leaves_original_untouched(self):
        f = _finding(severity="WARNING")
        v = _modify_verdict(severity="WARNING")
        out = annotate_with_verdicts([f], {"f1": v}, {})[0]
        assert out["severity"] == "WARNING"
        assert "original_severity" not in out

    def test_modified_suggestion_surfaces(self):
        f = _finding()
        v = _modify_verdict(suggestion="Use a bound query instead.")
        out = annotate_with_verdicts([f], {"f1": v}, {})[0]
        assert out["modified_suggestion"] == "Use a bound query instead."


class TestRenderFindingEvidence:
    def _report(self, finding: dict) -> str:
        finding = {"severity": "WARNING", "file": "a.py", "line": 1,
                   "problem": "p", "category": "bug", **finding}
        return build_report([finding])

    def test_renders_big_o(self):
        report = self._report({"evidence": {"big_o": "O(n^2)"}})
        assert "**Big-O:** O(n^2)" in report

    def test_renders_convention_file(self):
        report = self._report({"evidence": {
            "convention_file": "STYLE.md",
            "convention_line_or_grep": "no bare except"}})
        assert "**Convention:**" in report
        assert "STYLE.md" in report

    def test_renders_principle(self):
        report = self._report({"evidence": {"principle": "Single Responsibility"}})
        assert "**Principle:** Single Responsibility" in report

    def test_renders_red_green_test_path(self):
        report = self._report({
            "test_path": "tests/test_a.py",
            "evidence": {"test_target_file": "a.py"}})
        assert "**Red-green test:** `tests/test_a.py`" in report
