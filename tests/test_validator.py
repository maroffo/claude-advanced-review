# ABOUTME: Unit tests for validator.py checks
# ABOUTME: Covers CWE, URL, syntax, relevance, REFUTE citation, full pipeline

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from validator import validator as V


# ---------- Fixtures ----------

SAMPLE_DIFF = """\
diff --git a/api/users.py b/api/users.py
index abc..def 100644
--- a/api/users.py
+++ b/api/users.py
@@ -40,6 +40,8 @@ class UserService:
     def get_by_name(self, username: str) -> User | None:
         cursor = self.conn.cursor()
-        query = "SELECT * FROM users WHERE name = '" + username + "'"
-        cursor.execute(query)
+        cursor.execute(
+            "SELECT * FROM users WHERE name = %s", (username,)
+        )
         row = cursor.fetchone()
         return User.from_row(row) if row else None
"""


@pytest.fixture
def diff_text():
    return SAMPLE_DIFF


@pytest.fixture
def parsed_diff(diff_text):
    return V.parse_diff(diff_text)


@pytest.fixture
def cwe_store(tmp_path, monkeypatch):
    """Force the CWE store to use a temp cache with a canned set of IDs."""
    cache = tmp_path / "cwe.json"
    cache.write_text(json.dumps({
        "CWE-79": "Improper Neutralization of Input During Web Page Generation",
        "CWE-89": "SQL Injection",
        "CWE-22": "Path Traversal",
    }))
    monkeypatch.setattr(V, "CWE_CACHE_PATH", cache)
    monkeypatch.setattr(V, "_download_cwe_list", lambda: pytest.fail(
        "should not attempt download when cache is fresh"))
    return V.CWEStore()


# ---------- CWE existence ----------

class TestCWEExists:
    def test_valid_id(self, cwe_store):
        assert cwe_store.contains("CWE-89") is True

    def test_unknown_id(self, cwe_store):
        assert cwe_store.contains("CWE-99999") is False

    def test_malformed_id(self, cwe_store):
        assert cwe_store.contains("CWE-abc") is False

    def test_missing_prefix(self, cwe_store):
        assert cwe_store.contains("89") is False

    def test_none(self, cwe_store):
        assert cwe_store.contains(None) is False


# ---------- URL reachability ----------

class TestURLReachable:
    def test_200_is_reachable(self, monkeypatch):
        resp = MagicMock(status_code=200)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        assert V.url_reachable("https://example.com") is True

    def test_404_is_not_reachable(self, monkeypatch):
        resp = MagicMock(status_code=404)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        assert V.url_reachable("https://example.com/missing") is False

    def test_timeout_is_not_reachable(self, monkeypatch):
        def boom(*a, **k):
            raise V.requests.exceptions.Timeout("slow")
        monkeypatch.setattr(V.requests, "head", boom)
        assert V.url_reachable("https://example.com") is False

    def test_3xx_counts_as_reachable(self, monkeypatch):
        resp = MagicMock(status_code=301)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        assert V.url_reachable("https://example.com") is True


# ---------- Test syntax ----------

class TestSyntax:
    def test_python_valid(self):
        code = "def test_x():\n    assert 1 + 1 == 2\n"
        assert V.test_syntax_ok(code, "python") is True

    def test_python_invalid(self):
        code = "def test_x(:\n    assert"
        assert V.test_syntax_ok(code, "python") is False

    def test_javascript_valid(self):
        code = "test('x', () => { expect(1+1).toBe(2); });"
        assert V.test_syntax_ok(code, "javascript") is True

    def test_javascript_unbalanced_braces(self):
        code = "test('x', () => { expect(1+1).toBe(2); "
        assert V.test_syntax_ok(code, "javascript") is False

    def test_unknown_language_defaults_to_pass(self):
        # Unknown languages shouldn't false-positive; we can't parse,
        # so we let it through and the test runner will catch broken code.
        assert V.test_syntax_ok("anything", "brainfuck") is True

    def test_empty_code(self):
        assert V.test_syntax_ok("", "python") is False


# ---------- Diff parsing ----------

class TestParseDiff:
    def test_extracts_changed_files(self, parsed_diff):
        assert "api/users.py" in parsed_diff.files

    def test_extracts_hunk_lines(self, parsed_diff):
        lines = parsed_diff.lines_for("api/users.py")
        # Lines 40..45ish should be present
        assert 41 in lines or 42 in lines

    def test_extracts_symbols(self, parsed_diff):
        syms = parsed_diff.symbols
        # Function or variable names that appear in the diff
        assert "username" in syms or "get_by_name" in syms


# ---------- Test relevance ----------

class TestRelevance:
    def test_test_imports_symbol_from_diff(self, parsed_diff):
        test = (
            "from api.users import UserService\n"
            "def test_sql_injection():\n"
            "    svc = UserService(conn)\n"
            "    svc.get_by_name(\"x'; DROP TABLE--\")\n"
        )
        assert V.test_is_relevant(test, "python", parsed_diff) is True

    def test_test_references_diff_file(self, parsed_diff):
        test = (
            "def test_something():\n"
            "    # covers api/users.py\n"
            "    assert True\n"
        )
        # The symbol match fails but the file path appears in a comment.
        # We are lenient: file path reference counts.
        assert V.test_is_relevant(test, "python", parsed_diff) is True

    def test_test_unrelated(self, parsed_diff):
        test = (
            "def test_math():\n"
            "    assert 2 + 2 == 4\n"
        )
        assert V.test_is_relevant(test, "python", parsed_diff) is False


# ---------- REFUTE citation ----------

class TestRefuteCitations:
    def test_citation_inside_hunk(self, parsed_diff):
        citations = [{"file": "api/users.py", "line": 42}]
        assert V.refute_citations_valid(citations, parsed_diff) is True

    def test_citation_wrong_file(self, parsed_diff):
        citations = [{"file": "api/orders.py", "line": 42}]
        assert V.refute_citations_valid(citations, parsed_diff) is False

    def test_citation_outside_hunk(self, parsed_diff):
        citations = [{"file": "api/users.py", "line": 9999}]
        assert V.refute_citations_valid(citations, parsed_diff) is False

    def test_mixed_citations_all_must_match(self, parsed_diff):
        citations = [
            {"file": "api/users.py", "line": 42},
            {"file": "api/users.py", "line": 9999},
        ]
        assert V.refute_citations_valid(citations, parsed_diff) is False

    def test_empty_citations(self, parsed_diff):
        assert V.refute_citations_valid([], parsed_diff) is False


# ---------- Full pipeline ----------

class TestValidateFinding:
    def _security_finding(self, **overrides):
        base = {
            "id": "f1",
            "category": "security",
            "severity": "CRITICAL",
            "file": "api/users.py",
            "line": 42,
            "problem": "SQL injection via string concat.",
            "suggestion": "Use parameterized query.",
            "evidence": {
                "cwe_id": "CWE-89",
                "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
            },
        }
        base.update(overrides)
        return base

    def _bug_finding(self, **overrides):
        base = {
            "id": "f2",
            "category": "bug",
            "severity": "WARNING",
            "file": "api/users.py",
            "line": 42,
            "problem": "Does not handle empty username.",
            "suggestion": "Raise ValueError on empty.",
            "evidence": {
                "test_language": "python",
                "test_target_file": "tests/test_users.py",
                "test_modifies_existing": False,
                "test": (
                    "from api.users import UserService\n"
                    "def test_empty_username_raises():\n"
                    "    svc = UserService(None)\n"
                    "    import pytest\n"
                    "    with pytest.raises(ValueError):\n"
                    "        svc.get_by_name('')\n"
                ),
            },
        }
        base.update(overrides)
        return base

    def test_security_passes(self, cwe_store, parsed_diff, monkeypatch):
        resp = MagicMock(status_code=200)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        result = V.validate_finding(self._security_finding(), parsed_diff, cwe_store)
        assert result["validator_status"] == "passed", result

    def test_security_drops_on_fake_cwe(self, cwe_store, parsed_diff, monkeypatch):
        resp = MagicMock(status_code=200)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        finding = self._security_finding(evidence={
            "cwe_id": "CWE-99999",
            "cwe_url": "https://cwe.mitre.org/data/definitions/99999.html",
        })
        result = V.validate_finding(finding, parsed_diff, cwe_store)
        assert result["validator_status"] == "dropped"
        assert any("cwe" in r.lower() for r in result["validator_reasons"])

    def test_security_drops_on_dead_url(self, cwe_store, parsed_diff, monkeypatch):
        resp = MagicMock(status_code=404)
        monkeypatch.setattr(V.requests, "head", lambda *a, **k: resp)
        result = V.validate_finding(self._security_finding(), parsed_diff, cwe_store)
        assert result["validator_status"] == "dropped"
        assert any("url" in r.lower() for r in result["validator_reasons"])

    def test_bug_passes(self, cwe_store, parsed_diff):
        result = V.validate_finding(self._bug_finding(), parsed_diff, cwe_store)
        assert result["validator_status"] == "passed", result

    def test_bug_drops_on_irrelevant_test(self, cwe_store, parsed_diff):
        finding = self._bug_finding()
        finding["evidence"]["test"] = "def test_math():\n    assert 1 + 1 == 2\n"
        result = V.validate_finding(finding, parsed_diff, cwe_store)
        assert result["validator_status"] == "dropped"
        assert any("relevan" in r.lower() for r in result["validator_reasons"])

    def test_bug_drops_on_bad_syntax(self, cwe_store, parsed_diff):
        finding = self._bug_finding()
        finding["evidence"]["test"] = "def test_x(:\n    syntax error"
        result = V.validate_finding(finding, parsed_diff, cwe_store)
        assert result["validator_status"] == "dropped"
        assert any("syntax" in r.lower() for r in result["validator_reasons"])

    def test_nitpick_autodemotes_to_info(self, cwe_store, parsed_diff):
        finding = {
            "id": "f3",
            "category": "nitpick",
            "severity": "WARNING",
            "file": "api/users.py",
            "line": 42,
            "problem": "Variable naming.",
            "suggestion": "Rename.",
            "evidence": {},
        }
        result = V.validate_finding(finding, parsed_diff, cwe_store)
        assert result["validator_status"] == "passed"
        assert result["severity"] == "INFO"


class TestValidateCrossCheck:
    def test_accept_unchanged(self, parsed_diff):
        verdict = {"finding_id": "f1", "verdict": "ACCEPT"}
        out = V.validate_verdict(verdict, parsed_diff)
        assert out["validator_status"] == "passed"

    def test_refute_with_valid_citation(self, parsed_diff):
        verdict = {
            "finding_id": "f1",
            "verdict": "REFUTE-BY-EXPLANATION",
            "diff_citations": [{"file": "api/users.py", "line": 42}],
            "explanation": "Already parameterized.",
        }
        out = V.validate_verdict(verdict, parsed_diff)
        assert out["validator_status"] == "passed"

    def test_refute_with_bad_citation_is_discarded(self, parsed_diff):
        verdict = {
            "finding_id": "f1",
            "verdict": "REFUTE-BY-EXPLANATION",
            "diff_citations": [{"file": "api/users.py", "line": 9999}],
            "explanation": "Wrong line.",
        }
        out = V.validate_verdict(verdict, parsed_diff)
        assert out["validator_status"] == "discarded"
        assert out["effective_verdict"] == "ACCEPT"  # Original claim wins
