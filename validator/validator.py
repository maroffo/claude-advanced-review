# ABOUTME: Deterministic validator for reviewer findings
# ABOUTME: Checks CWE existence, URL reachability, test syntax, relevance, REFUTE citations

from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import requests.exceptions


# ---------- Constants ----------

CACHE_DIR = Path.home() / ".cache" / "claude-advanced-review"
CWE_CACHE_PATH = CACHE_DIR / "cwe.json"
CWE_TTL_SECONDS = 30 * 24 * 3600  # 30 days
MITRE_CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
URL_TIMEOUT = 5.0

# Identifiers so generic they don't count as evidence of relevance.
# Uppercase SQL keywords covered separately via the "all-uppercase short" filter.
_NOISE = {
    "def", "from", "import", "as", "return", "class", "pass", "raise",
    "test", "self", "cls", "None", "True", "False",
    "if", "else", "elif", "for", "while", "in", "is", "and", "or", "not",
    "str", "int", "float", "list", "dict", "set", "tuple", "bool", "bytes",
    "try", "except", "finally", "with", "yield", "lambda", "assert",
    "function", "const", "let", "var", "async", "await",
    "print", "input", "range", "len", "type", "super",
    "public", "private", "protected", "static", "void",
    "null", "nil", "undefined",
}


# ---------- Diff parsing ----------

@dataclass
class ParsedDiff:
    files: set[str] = field(default_factory=set)
    hunks: dict[str, set[int]] = field(default_factory=dict)
    symbols: set[str] = field(default_factory=set)
    raw: str = ""

    def lines_for(self, file: str) -> set[int]:
        return self.hunks.get(file, set())


_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]+\b")
_HEADER_NEW_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(text: str) -> ParsedDiff:
    pd = ParsedDiff(raw=text)
    current_file: str | None = None
    new_line_no = 0
    for line in text.splitlines():
        m = _HEADER_NEW_FILE_RE.match(line)
        if m:
            current_file = m.group(1)
            pd.files.add(current_file)
            pd.hunks.setdefault(current_file, set())
            continue
        m = _HUNK_RE.match(line)
        if m:
            new_line_no = int(m.group(1))
            continue
        if current_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            pd.hunks[current_file].add(new_line_no)
            pd.symbols.update(_IDENT_RE.findall(line[1:]))
            new_line_no += 1
        elif line.startswith("-") and not line.startswith("---"):
            pd.symbols.update(_IDENT_RE.findall(line[1:]))
        elif line.startswith(" "):
            new_line_no += 1
    for f in pd.files:
        stem = Path(f).stem
        if stem:
            pd.symbols.add(stem)
    return pd


# ---------- CWE store ----------

class CWEStore:
    def __init__(self) -> None:
        self._data: dict[str, str] | None = None

    def _load(self) -> None:
        if self._data is not None:
            return
        if CWE_CACHE_PATH.exists():
            mtime = CWE_CACHE_PATH.stat().st_mtime
            if time.time() - mtime < CWE_TTL_SECONDS:
                try:
                    self._data = json.loads(CWE_CACHE_PATH.read_text())
                    return
                except (json.JSONDecodeError, OSError):
                    pass
        self._data = _download_cwe_list()
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CWE_CACHE_PATH.write_text(json.dumps(self._data))

    def contains(self, cwe_id: Any) -> bool:
        if not isinstance(cwe_id, str):
            return False
        if not re.fullmatch(r"CWE-\d+", cwe_id):
            return False
        self._load()
        return cwe_id in (self._data or {})


def _download_cwe_list() -> dict[str, str]:
    resp = requests.get(MITRE_CWE_XML_ZIP_URL, timeout=30)
    resp.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
    root = ET.fromstring(zf.read(xml_name))
    out: dict[str, str] = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "Weakness":
            wid = el.get("ID")
            if wid and wid.isdigit():
                out[f"CWE-{wid}"] = el.get("Name", "")
    return out


# ---------- URL check ----------

def url_reachable(url: str, timeout: float = URL_TIMEOUT) -> bool:
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        return 200 <= resp.status_code < 400
    except requests.exceptions.RequestException:
        return False


# ---------- Syntax checks ----------

def test_syntax_ok(code: str, language: str) -> bool:
    if not code or not code.strip():
        return False
    lang = (language or "").lower().strip()
    if lang == "python":
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    if lang in {"javascript", "typescript", "go", "ruby", "rust",
               "java", "kotlin", "swift", "bash"}:
        return _balanced(code)
    return True  # Unknown language: lenient


def _balanced(code: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    in_str: str | None = None
    escape = False
    for ch in code:
        if escape:
            escape = False
            continue
        if in_str:
            if ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            continue
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack and in_str is None


# ---------- Relevance check ----------

def test_is_relevant(code: str, language: str, diff: ParsedDiff) -> bool:
    # 1) Any diff file path appears literally in the test code.
    for f in diff.files:
        if f in code:
            return True
        stem = Path(f).stem
        if stem and re.search(rf"\b{re.escape(stem)}\b", code):
            return True
    # 2) Any non-noise symbol from diff appears in the test code.
    test_tokens = set(_IDENT_RE.findall(code))
    for tok in diff.symbols & test_tokens:
        if tok in _NOISE:
            continue
        if tok.isupper() and len(tok) <= 5:
            # Likely SQL keyword or env constant, not a meaningful link.
            continue
        if len(tok) < 3:
            continue
        return True
    return False


# ---------- REFUTE citation check ----------

def refute_citations_valid(citations: list[dict], diff: ParsedDiff) -> bool:
    if not citations:
        return False
    for c in citations:
        f = c.get("file")
        line = c.get("line")
        if not f or not isinstance(line, int):
            return False
        if f not in diff.files:
            return False
        if line not in diff.hunks.get(f, set()):
            return False
    return True


# ---------- Finding-level validation ----------

_REQUIRED_EVIDENCE: dict[str, tuple[str, ...]] = {
    "security": ("cwe_id", "cwe_url"),
    "bug": ("test_language", "test", "test_target_file"),
    "performance": (),  # big_o OR benchmark, handled inline
    "convention": ("convention_file", "convention_line_or_grep"),
    "architecture": ("principle", "application"),
    "nitpick": (),
}


def _drop(finding: dict, reasons: list[str]) -> dict:
    return {**finding, "validator_status": "dropped", "validator_reasons": reasons}


def _pass(finding: dict, severity: str | None = None) -> dict:
    out = {**finding, "validator_status": "passed", "validator_reasons": []}
    if severity:
        out["severity"] = severity
    return out


def validate_finding(finding: dict, diff: ParsedDiff, cwe_store: CWEStore) -> dict:
    category = finding.get("category")
    evidence = finding.get("evidence") or {}
    reasons: list[str] = []

    if category == "nitpick":
        return _pass(finding, severity="INFO")

    required = _REQUIRED_EVIDENCE.get(category)
    if required is None:
        return _drop(finding, [f"unknown category: {category}"])

    missing = [k for k in required if not evidence.get(k)]
    if missing:
        reasons.append(f"missing evidence fields: {missing}")

    if category == "security":
        cwe_id = evidence.get("cwe_id")
        cwe_url = evidence.get("cwe_url")
        if cwe_id and not cwe_store.contains(cwe_id):
            reasons.append(f"cwe unknown: {cwe_id}")
        if cwe_url and not url_reachable(cwe_url):
            reasons.append(f"cwe url unreachable: {cwe_url}")

    elif category == "bug":
        lang = evidence.get("test_language", "")
        test = evidence.get("test", "")
        if test:
            syntax_ok = test_syntax_ok(test, lang)
            if not syntax_ok:
                reasons.append(f"test syntax invalid for language {lang}")
            elif not test_is_relevant(test, lang, diff):
                reasons.append("test not relevant to diff (no symbol/file overlap)")

    elif category == "performance":
        if not evidence.get("big_o") and not evidence.get("benchmark"):
            reasons.append("performance requires big_o OR benchmark")

    elif category == "architecture":
        principle = evidence.get("principle", "")
        if principle and len(principle) < 3:
            reasons.append("architecture principle too short")

    if reasons:
        return _drop(finding, reasons)
    return _pass(finding)


def _file_has_line(file_path: str, line: int, project_root: Path) -> bool:
    """Check that a file exists and has at least `line` lines."""
    full = project_root / file_path
    if not full.is_file():
        return False
    if line <= 0:
        return True
    try:
        content = full.read_text(errors="replace")
        return content.count("\n") + 1 >= line
    except OSError:
        return False


def validate_finding_repo(finding: dict, project_root: Path,
                          cwe_store: CWEStore) -> dict:
    """Validate a finding in repo mode (no diff, check file/line existence)."""
    category = finding.get("category")
    evidence = finding.get("evidence") or {}
    reasons: list[str] = []

    if category == "nitpick":
        return _pass(finding, severity="INFO")

    required = _REQUIRED_EVIDENCE.get(category)
    if required is None:
        return _drop(finding, [f"unknown category: {category}"])

    missing = [k for k in required if not evidence.get(k)]
    if missing:
        reasons.append(f"missing evidence fields: {missing}")

    # Check file and line existence
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    if file_path and not _file_has_line(file_path, line, project_root):
        reasons.append(f"file/line not found: {file_path}:{line}")

    if category == "security":
        cwe_id = evidence.get("cwe_id")
        cwe_url = evidence.get("cwe_url")
        if cwe_id and not cwe_store.contains(cwe_id):
            reasons.append(f"cwe unknown: {cwe_id}")
        if cwe_url and not url_reachable(cwe_url):
            reasons.append(f"cwe url unreachable: {cwe_url}")

    elif category == "bug":
        lang = evidence.get("test_language", "")
        test = evidence.get("test", "")
        if test:
            if not test_syntax_ok(test, lang):
                reasons.append(f"test syntax invalid for language {lang}")

    elif category == "performance":
        if not evidence.get("big_o") and not evidence.get("benchmark"):
            reasons.append("performance requires big_o OR benchmark")

    elif category == "architecture":
        principle = evidence.get("principle", "")
        if principle and len(principle) < 3:
            reasons.append("architecture principle too short")

    if reasons:
        return _drop(finding, reasons)
    return _pass(finding)


def validate_verdict(verdict: dict, diff: ParsedDiff) -> dict:
    v = verdict.get("verdict")
    if v == "REFUTE-BY-EXPLANATION":
        cites = verdict.get("diff_citations", [])
        if not refute_citations_valid(cites, diff):
            return {
                **verdict,
                "validator_status": "discarded",
                "validator_reasons": ["REFUTE citations outside diff hunks"],
                "effective_verdict": "ACCEPT",
            }
    return {**verdict, "validator_status": "passed", "validator_reasons": []}


# ---------- CLI ----------

def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate reviewer findings against a diff."
    )
    parser.add_argument(
        "--mode",
        choices=("round1", "crosscheck"),
        required=True,
        help="round1 = validate findings; crosscheck = validate verdicts",
    )
    parser.add_argument("--findings", type=Path, required=True,
                        help="JSON file with findings or verdicts")
    parser.add_argument("--diff", type=Path, required=True,
                        help="Unified diff text file")
    parser.add_argument("--out", type=Path, required=True,
                        help="Output JSON path")
    args = parser.parse_args()

    diff = parse_diff(args.diff.read_text())
    payload = json.loads(args.findings.read_text())

    if args.mode == "round1":
        cwe = CWEStore()
        annotated = [validate_finding(f, diff, cwe)
                     for f in payload.get("findings", [])]
        out = {"findings": annotated}
    else:
        annotated = [validate_verdict(v, diff)
                     for v in payload.get("verdicts", [])]
        out = {"verdicts": annotated}

    args.out.write_text(json.dumps(out, indent=2))
    passed = sum(1 for x in annotated if x.get("validator_status") == "passed")
    dropped = sum(1 for x in annotated if x.get("validator_status") in
                  ("dropped", "discarded"))
    print(f"validator: {passed} passed, {dropped} dropped "
          f"({args.mode}) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
