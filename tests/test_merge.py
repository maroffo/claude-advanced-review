# ABOUTME: Unit tests for merge.classify_confidence — the round-2 decision matrix
# ABOUTME: Both ACCEPT = HIGH_CONFIDENCE, any genuine REJECT/REFUTE = DISPUTED

from __future__ import annotations

from merge.merger import classify_confidence


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
