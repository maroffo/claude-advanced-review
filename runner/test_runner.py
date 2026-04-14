# ABOUTME: Executes proposed red-green tests against the current codebase
# ABOUTME: Drops findings whose tests pass now (claim unproven), keeps those that fail (confirmed)

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ---------- Toolchain detection ----------

@dataclass
class Toolchain:
    language: str
    runner_cmd: list[str]
    # Given a test file path, produce the command to run it.
    # Callers append the test path (absolute or repo-relative) via `build_cmd`.
    test_flag_style: str = "path"  # "path" | "package" | "dir"
    env: dict[str, str] = field(default_factory=dict)


def detect_toolchain(project_root: Path) -> Toolchain | None:
    if (project_root / "pyproject.toml").exists() or \
       (project_root / "setup.py").exists():
        return Toolchain(
            language="python",
            runner_cmd=["pytest", "-q", "-x"],
            test_flag_style="path",
        )
    if (project_root / "package.json").exists():
        if (project_root / "pnpm-lock.yaml").exists():
            cmd = ["pnpm", "test", "--"]
        elif (project_root / "yarn.lock").exists():
            cmd = ["yarn", "test"]
        else:
            cmd = ["npm", "test", "--"]
        # Assume jest-like; user's project `test` script must accept a path.
        lang = "javascript"
        if (project_root / "tsconfig.json").exists():
            lang = "typescript"
        return Toolchain(language=lang, runner_cmd=cmd, test_flag_style="path")
    if (project_root / "go.mod").exists():
        return Toolchain(
            language="go",
            runner_cmd=["go", "test"],
            test_flag_style="package",
        )
    if (project_root / "Cargo.toml").exists():
        return Toolchain(
            language="rust",
            runner_cmd=["cargo", "test"],
            test_flag_style="dir",
        )
    if (project_root / "Gemfile").exists():
        return Toolchain(
            language="ruby",
            runner_cmd=["bundle", "exec", "rspec"],
            test_flag_style="path",
        )
    return None


# ---------- Extension mapping ----------

_EXT_MAP = {
    "python": ".py",
    "javascript": ".test.js",
    "typescript": ".test.ts",
    "go": "_test.go",
    "ruby": "_spec.rb",
    "rust": ".rs",
    "java": "Test.java",
    "kotlin": "Test.kt",
    "swift": "Tests.swift",
    "bash": ".sh",
}


def extension_for(language: str) -> str:
    return _EXT_MAP.get((language or "").lower(), ".txt")


# ---------- Test status classification ----------

_ERROR_SIGNATURES = (
    "ImportError",
    "ModuleNotFoundError",
    "SyntaxError",
    "cannot find package",
    "error: unresolved import",
    "LoadError",
    "require_relative",
    "ERROR tests/",
    "collection error",
)


def classify_test_result(exit_code: int, stderr: str) -> str:
    if exit_code == 0:
        return "passed"
    text = stderr or ""
    for sig in _ERROR_SIGNATURES:
        if sig in text:
            return "errored"
    return "failed"


# ---------- Disposition ----------

def apply_disposition(finding: dict, *, test_status: str | None,
                      test_path: str | None) -> dict:
    out = dict(finding)
    if finding.get("category") != "bug":
        out["runner_status"] = "not_applicable"
        return out
    if test_status == "failed":
        out["runner_status"] = "confirmed"
    elif test_status == "passed":
        out["runner_status"] = "unproven"
    elif test_status == "errored":
        out["runner_status"] = "errored"
    else:
        out["runner_status"] = "skipped"
    if test_path:
        out["test_path"] = test_path
    return out


# ---------- Execution ----------

_TEST_FN_RE = {
    "python": re.compile(r"^\s*def\s+(test_[A-Za-z0-9_]+)\s*\(", re.M),
    "go": re.compile(r"^\s*func\s+(Test[A-Za-z0-9_]+)\s*\(", re.M),
    "javascript": re.compile(
        r"(?:^|\s)(?:it|test)\s*\(\s*['\"]([^'\"]+)['\"]", re.M),
    "typescript": re.compile(
        r"(?:^|\s)(?:it|test)\s*\(\s*['\"]([^'\"]+)['\"]", re.M),
    "ruby": re.compile(
        r"(?:^|\s)(?:it|specify)\s+['\"]([^'\"]+)['\"]", re.M),
}


def _extract_test_name(code: str, language: str) -> str | None:
    r = _TEST_FN_RE.get(language.lower())
    if not r:
        return None
    m = r.search(code)
    return m.group(1) if m else None


def _write_test_file(code: str, language: str, finding_id: str,
                     review_tests_dir: Path) -> Path:
    review_tests_dir.mkdir(parents=True, exist_ok=True)
    ext = extension_for(language)
    # Test files must start with `test_` for pytest to collect, or use
    # language-appropriate naming.
    if language.lower() == "python":
        filename = f"test_review_{finding_id}{ext}"
    else:
        filename = f"review_{finding_id}{ext}"
    path = review_tests_dir / filename
    path.write_text(code)
    return path


def _run_test(tc: Toolchain, test_path: Path, test_name: str | None,
              project_root: Path) -> tuple[int, str, str]:
    cmd = list(tc.runner_cmd)
    if tc.language == "python":
        cmd.append(str(test_path))
        if test_name:
            cmd.append(f"-k {test_name}")
    elif tc.language in ("javascript", "typescript"):
        cmd.append(str(test_path))
    elif tc.language == "go":
        # go test must be run against a package; placing a single file is
        # awkward. For the v1 pipeline we require the test file to live
        # inside a package directory the user can pass as PROJECT_ROOT;
        # orchestration fallback: run from the file's parent directory.
        cmd = ["go", "test", "-run", test_name or ".", str(test_path.parent)]
    elif tc.language == "rust":
        # cargo test filters by substring of test name.
        if test_name:
            cmd.append(test_name)
    elif tc.language == "ruby":
        cmd.append(str(test_path))

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after 120s"
    except FileNotFoundError as e:
        return 127, "", f"runner not found: {e}"


def run_bug_finding(finding: dict, tc: Toolchain,
                    review_tests_dir: Path,
                    project_root: Path) -> dict:
    evidence = finding.get("evidence") or {}
    code = evidence.get("test", "")
    language = evidence.get("test_language", "")
    if not code or not language:
        return apply_disposition(finding, test_status="skipped",
                                 test_path=None)
    test_path = _write_test_file(code, language, finding.get("id", "anon"),
                                 review_tests_dir)
    test_name = _extract_test_name(code, language)
    code_exit, stdout, stderr = _run_test(tc, test_path, test_name,
                                          project_root)
    status = classify_test_result(code_exit, stderr + "\n" + stdout)
    result = apply_disposition(finding, test_status=status,
                               test_path=str(test_path.relative_to(project_root))
                                          if test_path.is_relative_to(project_root)
                                          else str(test_path))
    result["runner_exit_code"] = code_exit
    if stderr:
        result["runner_stderr_tail"] = stderr[-500:]
    # If the test proved nothing or errored, remove the test file to keep
    # review-tests/ lean; only keep confirmed tests.
    if status != "failed" and test_path.exists():
        try:
            test_path.unlink()
        except OSError:
            pass
    return result


# ---------- CLI ----------

def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Run proposed red-green tests, drop unproven claims.",
    )
    parser.add_argument("--findings", type=Path, required=True,
                        help="Validator output JSON (findings).")
    parser.add_argument("--project-root", type=Path, required=True,
                        help="Target project to test against.")
    parser.add_argument("--review-tests-dir", type=Path, required=True,
                        help="Where to write surviving red-green tests.")
    parser.add_argument("--out", type=Path, required=True,
                        help="Output JSON with runner_status per finding.")
    parser.add_argument("--skip", action="store_true",
                        help="Skip test execution, pass findings through.")
    args = parser.parse_args()

    payload = json.loads(args.findings.read_text())
    findings = payload.get("findings", [])

    if args.skip:
        findings = [apply_disposition(f, test_status="skipped",
                                      test_path=None) for f in findings]
        args.out.write_text(json.dumps({"findings": findings}, indent=2))
        print("test-runner: skipped (--skip)", file=sys.stderr)
        return 0

    tc = detect_toolchain(args.project_root)
    if tc is None:
        findings = [apply_disposition(f, test_status="skipped",
                                      test_path=None) for f in findings]
        args.out.write_text(json.dumps({"findings": findings}, indent=2))
        print("test-runner: no toolchain detected, skipping",
              file=sys.stderr)
        return 0

    out_findings: list[dict] = []
    for f in findings:
        if f.get("validator_status") != "passed":
            out_findings.append({**f, "runner_status": "skipped_upstream"})
            continue
        if f.get("category") != "bug":
            out_findings.append(apply_disposition(f, test_status=None,
                                                  test_path=None))
            continue
        out_findings.append(run_bug_finding(f, tc, args.review_tests_dir,
                                            args.project_root))

    args.out.write_text(json.dumps({"findings": out_findings}, indent=2))
    confirmed = sum(1 for x in out_findings
                    if x.get("runner_status") == "confirmed")
    unproven = sum(1 for x in out_findings
                   if x.get("runner_status") == "unproven")
    errored = sum(1 for x in out_findings
                  if x.get("runner_status") == "errored")
    print(f"test-runner: {confirmed} confirmed, {unproven} unproven, "
          f"{errored} errored -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
