# ABOUTME: Unit tests for runner/semgrep_runner.py JSON parsing and mapping
# ABOUTME: Mocks the docker subprocess; real Semgrep execution covered by E2E

from __future__ import annotations

import json

import pytest

from runner import semgrep_runner as S


SEMGREP_JSON_SAMPLE = {
    "version": "1.50.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.sqli.sqli-in-raw-query.sqli-in-raw-query",
            "path": "api/users.py",
            "start": {"line": 45, "col": 9},
            "end": {"line": 45, "col": 80},
            "extra": {
                "message": "User input flows into a raw SQL query.",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "owasp": ["A03:2021 - Injection"],
                },
                "lines": "query = 'SELECT * FROM users WHERE name = ' + username",
            },
        },
        {
            "check_id": "python.lang.best-practice.unused-import.unused-import",
            "path": "api/users.py",
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 20},
            "extra": {
                "message": "Unused import: os",
                "severity": "INFO",
                "metadata": {},
            },
        },
    ],
    "errors": [],
}


class TestMapSemgrepResult:
    def test_maps_severity_error_to_critical(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["severity"] == "CRITICAL"

    def test_maps_severity_info_to_info(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][1])
        assert f["severity"] == "INFO"

    def test_extracts_file_and_line(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["file"] == "api/users.py"
        assert f["line"] == 45

    def test_extracts_cwe(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["evidence"]["cwe_id"] == "CWE-89"
        assert "89" in f["evidence"]["cwe_url"]

    def test_category_security_when_cwe_present(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["category"] == "security"

    def test_category_convention_when_no_cwe(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][1])
        assert f["category"] == "convention"

    def test_source_tagged_semgrep(self):
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["source"] == "semgrep"

    def test_validator_status_passed(self):
        """Semgrep findings bypass the validator — ground truth."""
        f = S.map_result(SEMGREP_JSON_SAMPLE["results"][0])
        assert f["validator_status"] == "passed"


class TestParseSemgrepOutput:
    def test_converts_all_results(self):
        out = S.parse_output(json.dumps(SEMGREP_JSON_SAMPLE))
        assert len(out) == 2

    def test_empty_results(self):
        out = S.parse_output(json.dumps({"results": [], "errors": []}))
        assert out == []

    def test_malformed_json_returns_empty(self):
        out = S.parse_output("not json at all")
        assert out == []
