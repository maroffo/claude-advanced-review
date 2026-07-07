# ABOUTME: Executes proposed red-green tests against the current codebase
# ABOUTME: Drops findings whose tests pass now (claim unproven), keeps those that fail (confirmed)

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Hard wall-clock ceiling for a single sandboxed test run (seconds).
DEFAULT_TIMEOUT = 120

# Per-toolchain sandbox image. Module-level so operators can override.
# Kept deliberately minimal (upstream slim images); project deps are NOT
# installed inside the container, which is why many runs land on
# "sandbox_unavailable" (see classify_sandbox_result) rather than a verdict.
SANDBOX_IMAGES = {
    "python": "python:3.12-slim",
    "javascript": "node:22-slim",
    "typescript": "node:22-slim",
    "go": "golang:1.23",
    "rust": "rust:1-slim",
    "ruby": "ruby:3-slim",
}


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


# ---------- Sandbox result classification ----------

# Docker/host-level failures: the container never ran the test at all.
_DOCKER_INFRA_SIGNATURES = (
    "Cannot connect to the Docker daemon",
    "Unable to find image",
    "manifest unknown",
    "no such image",
    "pull access denied",
    "permission denied while trying to connect",
    "Error response from daemon",
    "docker: Error",
)

# Toolchain/harness deps missing INSIDE the container. A non-zero exit here
# means "we could not evaluate the claim", NOT "the bug is real": the ephemeral
# slim image has none of the project's dependencies installed. These signatures
# are intentionally specific (framework globals / import machinery) so a genuine
# assertion failure in the reviewed code is never misread as a missing dep.
_SANDBOX_DEP_SIGNATURES = (
    # python
    "ImportError",
    "ModuleNotFoundError",
    # node / jest / mocha (globals absent because the framework isn't installed)
    "Cannot find module",
    "ReferenceError: describe is not defined",
    "ReferenceError: it is not defined",
    "ReferenceError: test is not defined",
    "ReferenceError: expect is not defined",
    # go
    "cannot find package",
    "no required module provides package",
    "cannot find module providing package",
    # rust
    "error: unresolved import",
    "error[E0432]",
    "error[E0433]",
    # ruby
    "cannot load such file",
    "LoadError",
)


def classify_sandbox_result(exit_code: int | None, output: str,
                            language: str) -> tuple[str, str | None]:
    """Map a sandbox run to (status, reason).

    status is one of:
      "failed"              -> test failed on current code => bug demonstrated
      "passed"              -> test passed => claim unproven (dropped upstream)
      "sandbox_unavailable" -> no verdict possible (finding survives, reason set)

    The heuristic separates "test failed because the bug is real" from "test
    failed because the sandbox lacks project deps / the container broke":
      - infra signatures or exit 125/126/127 -> container never ran the test
      - coreutils `timeout` exits 124         -> wall-clock hit, no verdict
      - dep/harness signatures                -> framework/imports missing
      - pytest exit 2/3/4/5                    -> usage / no-tests-collected
      - exit 0                                 -> clean pass
      - any other non-zero                     -> genuine test failure = bug
    """
    text = output or ""
    for sig in _DOCKER_INFRA_SIGNATURES:
        if sig in text:
            return "sandbox_unavailable", f"docker/image error: {sig}"
    if exit_code in (125, 126, 127):
        return ("sandbox_unavailable",
                f"container could not start (exit {exit_code})")
    if exit_code == 124:
        return "sandbox_unavailable", "test timed out in sandbox"
    for sig in _SANDBOX_DEP_SIGNATURES:
        if sig in text:
            return "sandbox_unavailable", f"toolchain deps unavailable: {sig}"
    # pytest reserves 2 (usage), 3 (internal), 4 (usage), 5 (no tests). None of
    # these demonstrate a bug; only exit 1 = "tests failed".
    if language == "python" and exit_code in (2, 3, 4, 5):
        return ("sandbox_unavailable",
                f"pytest could not run the test (exit {exit_code})")
    if exit_code == 0:
        return "passed", None
    return "failed", None


# ---------- Disposition ----------

def apply_disposition(finding: dict, *, test_status: str | None,
                      test_path: str | None, reason: str | None = None) -> dict:
    out = dict(finding)
    if finding.get("category") != "bug":
        out["runner_status"] = "not_applicable"
        return out
    if test_status == "failed":
        out["runner_status"] = "confirmed"
    elif test_status == "passed":
        out["runner_status"] = "unproven"
    elif test_status == "sandbox_unavailable":
        # Sandbox could not deliver a verdict. The finding SURVIVES (the
        # orchestrator drops only "unproven"), mirroring "skipped"; the reason
        # is recorded so a human knows why it went unverified.
        out["runner_status"] = "sandbox_unavailable"
    elif test_status == "errored":
        out["runner_status"] = "errored"
    else:
        out["runner_status"] = "skipped"
    if reason:
        out["runner_reason"] = reason
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


def build_container_script(tc: Toolchain, container_test_path: str,
                           test_name: str | None) -> str:
    """Build the shell script the container runs against the mounted test.

    The script is executed as `sh -c <script>` so we can (a) fall back from
    pytest to a bare interpreter and (b) let coreutils `timeout` wrap it.
    Paths are shell-quoted; project deps are absent, so most non-python
    toolchains resolve to "sandbox_unavailable" unless the test is
    self-contained.
    """
    lang = (tc.language or "").lower()
    p = shlex.quote(container_test_path)
    if lang == "python":
        # `-k name` stays TWO shell tokens (regression fix: the old host path
        # passed a single "-k name" argv token, which pytest silently ignored).
        k = f"-k {shlex.quote(test_name)} " if test_name else ""
        return (
            f"if python -m pytest --version >/dev/null 2>&1; then "
            f"python -m pytest -q -x {k}{p}; "
            f"else python {p}; fi"
        )
    if lang in ("javascript", "typescript"):
        return f"node {p}"
    if lang == "go":
        run = f"-run {shlex.quote(test_name)} " if test_name else ""
        return f"go test {run}{p}"
    if lang == "rust":
        filt = f" {shlex.quote(test_name)}" if test_name else ""
        return (f"rustc --test {p} -o /tmp/review_test "
                f"&& /tmp/review_test{filt}")
    if lang == "ruby":
        return f"ruby {p}"
    return f"cat {p}"


def build_sandbox_cmd(image: str, project_root: Path, host_test_path: Path,
                      container_test_path: str, script: str,
                      timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Assemble the ephemeral, network-less, read-only `docker run` argv.

    The project and the proposed test file are mounted read-only; the only
    writable surface is a tmpfs at /tmp. `timeout` inside the container gives a
    hard wall clock independent of the host-side subprocess timeout.
    """
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--pids-limit", "256",
        "--memory", "1g",
        "--read-only",
        "--tmpfs", "/tmp",
        "-v", f"{Path(project_root).resolve()}:/workspace:ro",
        "-v", f"{Path(host_test_path).resolve()}:{container_test_path}:ro",
        "-w", "/workspace",
        image,
        "timeout", str(timeout), "sh", "-c", script,
    ]


def _run_test_in_sandbox(
    tc: Toolchain, test_path: Path, test_name: str | None,
    project_root: Path, timeout: int = DEFAULT_TIMEOUT,
) -> tuple[str, int | None, str, str, str | None]:
    """Execute the proposed test in an ephemeral Docker sandbox.

    NEVER falls back to host execution. Returns
    (status, exit_code, stdout, stderr, reason) where status is one of
    "failed" | "passed" | "sandbox_unavailable".
    """
    image = SANDBOX_IMAGES.get((tc.language or "").lower())
    if image is None:
        reason = f"no sandbox image for language '{tc.language}'"
        return "sandbox_unavailable", None, "", "", reason

    container_path = f"/review/{test_path.name}"
    script = build_container_script(tc, container_path, test_name)
    cmd = build_sandbox_cmd(image, project_root, test_path, container_path,
                            script, timeout)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            # Host-side backstop: a bit longer than the in-container `timeout`
            # so the container's own kill fires first when possible.
            timeout=timeout + 30,
        )
    except FileNotFoundError:
        reason = "docker not installed on host"
        return "sandbox_unavailable", None, "", reason, reason
    except subprocess.TimeoutExpired:
        reason = f"sandbox wall-clock timeout after {timeout + 30}s"
        return "sandbox_unavailable", 124, "", reason, reason

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    status, reason = classify_sandbox_result(
        proc.returncode, combined, (tc.language or "").lower())
    return status, proc.returncode, proc.stdout, proc.stderr, reason


def run_bug_finding(finding: dict, tc: Toolchain,
                    review_tests_dir: Path,
                    project_root: Path,
                    timeout: int = DEFAULT_TIMEOUT) -> dict:
    evidence = finding.get("evidence") or {}
    code = evidence.get("test", "")
    language = evidence.get("test_language", "")
    if not code or not language:
        return apply_disposition(finding, test_status="skipped",
                                 test_path=None)
    # File writing is unchanged (host-side, for the human). Only EXECUTION
    # moves into the sandbox; the LLM-authored test never runs on the host.
    test_path = _write_test_file(code, language, finding.get("id", "anon"),
                                 review_tests_dir)
    test_name = _extract_test_name(code, language)
    status, code_exit, _stdout, stderr, reason = _run_test_in_sandbox(
        tc, test_path, test_name, project_root, timeout)
    result = apply_disposition(
        finding, test_status=status, reason=reason,
        test_path=str(test_path.relative_to(project_root))
        if test_path.is_relative_to(project_root)
        else str(test_path))
    if code_exit is not None:
        result["runner_exit_code"] = code_exit
    if stderr:
        result["runner_stderr_tail"] = stderr[-500:]
    # Keep every surviving test on disk for the human reviewer (confirmed AND
    # sandbox_unavailable). Only the "unproven" ones (test passed) are dropped.
    if status == "passed" and test_path.exists():
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
    unavailable = sum(1 for x in out_findings
                      if x.get("runner_status") == "sandbox_unavailable")
    print(f"test-runner: {confirmed} confirmed, {unproven} unproven, "
          f"{errored} errored, {unavailable} sandbox-unavailable "
          f"-> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
