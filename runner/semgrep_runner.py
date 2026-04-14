# ABOUTME: Runs Semgrep via Docker as a zero-hallucination third reviewer
# ABOUTME: Output is mapped to the same finding schema used by LLM reviewers

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SEMGREP_IMAGE = "semgrep/semgrep:latest"
SEMGREP_CONFIG = "--config=auto"


# ---------- Mapping ----------

_SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "WARNING",
    "INFO": "INFO",
}


_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _extract_cwe(metadata: dict) -> tuple[str | None, str | None]:
    raw = metadata.get("cwe") if isinstance(metadata, dict) else None
    if not raw:
        return None, None
    candidates: list[str] = []
    if isinstance(raw, list):
        candidates = [str(x) for x in raw]
    elif isinstance(raw, str):
        candidates = [raw]
    for c in candidates:
        m = _CWE_RE.search(c)
        if m:
            cwe_id = f"CWE-{m.group(1)}"
            url = f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
            return cwe_id, url
    return None, None


def map_result(result: dict) -> dict:
    extra = result.get("extra", {}) or {}
    metadata = extra.get("metadata", {}) or {}
    severity = _SEVERITY_MAP.get(
        str(extra.get("severity", "")).upper(), "INFO"
    )
    cwe_id, cwe_url = _extract_cwe(metadata)
    category = "security" if cwe_id else "convention"

    evidence: dict = {}
    if cwe_id:
        evidence["cwe_id"] = cwe_id
        evidence["cwe_url"] = cwe_url
    else:
        evidence["convention_file"] = ".semgrep"
        evidence["convention_line_or_grep"] = result.get("check_id", "")

    return {
        "id": f"semgrep-{result.get('check_id', 'x').split('.')[-1]}-"
              f"{result.get('path', '')}:{result.get('start', {}).get('line', 0)}",
        "category": category,
        "severity": severity,
        "file": result.get("path", ""),
        "line": result.get("start", {}).get("line", 0),
        "problem": extra.get("message", ""),
        "suggestion": extra.get("fix", "") or
                      "See Semgrep rule docs for remediation.",
        "evidence": evidence,
        "source": "semgrep",
        "check_id": result.get("check_id", ""),
        "validator_status": "passed",
        "validator_reasons": [],
    }


def parse_output(raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [map_result(r) for r in data.get("results", [])]


# ---------- Execution ----------

def run_semgrep(project_root: Path, timeout: int = 300) -> str:
    """Run Semgrep in Docker against the project, return raw JSON output."""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{project_root.resolve()}:/src:ro",
        "--workdir", "/src",
        SEMGREP_IMAGE,
        "semgrep", SEMGREP_CONFIG, "--json", "--quiet", "/src",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"semgrep: timeout after {timeout}s", file=sys.stderr)
        return "{}"
    except FileNotFoundError:
        print("semgrep: docker not found", file=sys.stderr)
        return "{}"
    if proc.returncode not in (0, 1):  # 1 = findings present; still OK
        print(f"semgrep: exit {proc.returncode}\n{proc.stderr[-500:]}",
              file=sys.stderr)
    return proc.stdout


# ---------- CLI ----------

def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Semgrep as a third reviewer.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    raw = run_semgrep(args.project_root, timeout=args.timeout)
    findings = parse_output(raw)
    args.out.write_text(json.dumps({"findings": findings}, indent=2))
    print(f"semgrep: {len(findings)} findings -> {args.out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
