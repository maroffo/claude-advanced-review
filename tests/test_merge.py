# ABOUTME: Unit tests for merge.classify_confidence and build_report
# ABOUTME: Both ACCEPT = HIGH_CONFIDENCE, any genuine REJECT/REFUTE = DISPUTED

from __future__ import annotations

from merge.merger import classify_confidence, build_report


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
    def test_both_accept_is_high_confidence(self):
        assert classify_confidence(_accept(), _accept()) == "HIGH_CONFIDENCE"

    def test_accept_plus_modify_is_modified(self):
        assert classify_confidence(_accept(), _modify()) == "MODIFIED"
        assert classify_confidence(_modify(), _accept()) == "MODIFIED"

    def test_reject_with_counter_is_disputed(self):
        assert classify_confidence(_accept(), _reject()) == "DISPUTED"
        assert classify_confidence(_reject(), _accept()) == "DISPUTED"

    def test_refute_valid_is_disputed(self):
        assert classify_confidence(_accept(), _refute()) == "DISPUTED"

    def test_refute_discarded_falls_back_to_accept(self):
        # Invalid citations -> REFUTE effectively ACCEPT -> HIGH_CONFIDENCE
        assert classify_confidence(_accept(), _refute(discarded=True)) == \
               "HIGH_CONFIDENCE"

    def test_both_modify_is_modified(self):
        assert classify_confidence(_modify(), _modify()) == "MODIFIED"

    def test_missing_one_verdict_is_unverified(self):
        assert classify_confidence(_accept(), None) == "UNVERIFIED"
        assert classify_confidence(None, _accept()) == "UNVERIFIED"

    def test_missing_both_verdicts_is_unverified(self):
        assert classify_confidence(None, None) == "UNVERIFIED"


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
