# ABOUTME: End-to-end orchestrator for claude-advanced-review
# ABOUTME: Glue: preflight -> diff -> round1 -> validate -> test-run -> semgrep -> sonarqube -> round2 -> merge

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from validator import validator as V  # noqa: E402
from runner import test_runner as TR  # noqa: E402
from runner import semgrep_runner as SR  # noqa: E402
from runner import sonarqube_runner as SQ  # noqa: E402
from runner import preflight_runner as PF  # noqa: E402
from merge import merger as MG  # noqa: E402


# ---------- Docker reviewer calls ----------

CLAUDE_IMAGE = "claude-reviewer:latest"
GEMINI_IMAGE = "gemini-reviewer:latest"
GEMINI_KEY_PATH = Path.home() / ".config" / "gemini-api-key"


def _read_gemini_key() -> str:
    if not GEMINI_KEY_PATH.exists():
        raise SystemExit(f"missing {GEMINI_KEY_PATH}")
    return GEMINI_KEY_PATH.read_text().strip()


def run_claude(prompt_file: Path, project_root: Path,
               timeout: int = 300) -> str:
    cmd = [
        "docker", "run", "--rm",
        "-v", "claude-reviewer-auth:/home/node/.claude:ro",
        "-v", f"{project_root.resolve()}:/workspace:ro",
        CLAUDE_IMAGE, "--print", "--model", "opus",
        prompt_file.read_text(),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        print(f"claude: timeout after {timeout}s", file=sys.stderr)
        return ""


def run_gemini(prompt_file: Path, project_root: Path,
               timeout: int = 300) -> str:
    key = _read_gemini_key()
    cmd = [
        "docker", "run", "--rm",
        "-e", f"GEMINI_API_KEY={key}",
        "-v", f"{project_root.resolve()}:/workspace:ro",
        GEMINI_IMAGE,
        "-p", prompt_file.read_text(),
        "-m", "gemini-3.1-pro-preview",
        "--sandbox", "false",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        # Strip known noisy lines from Gemini CLI
        raw = proc.stdout
        cleaned = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("[WARN] Skipping unreadable")
            and not line.startswith("Warning: Could not read")
        )
        return cleaned
    except subprocess.TimeoutExpired:
        print(f"gemini: timeout after {timeout}s", file=sys.stderr)
        return ""


def run_reviewers_parallel(prompt_file: Path,
                           project_root: Path) -> tuple[str, str]:
    with cf.ThreadPoolExecutor(max_workers=2) as pool:
        f_claude = pool.submit(run_claude, prompt_file, project_root)
        f_gemini = pool.submit(run_gemini, prompt_file, project_root)
        return f_claude.result(), f_gemini.result()


# ---------- JSON extraction from LLM output ----------

_JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)
_JSON_BARE_RE = re.compile(r"(\{[\s\S]*\})")


def extract_json(raw: str) -> dict[str, Any]:
    """Extract the last JSON block from an LLM response."""
    if not raw:
        return {}
    matches = list(_JSON_BLOCK_RE.finditer(raw))
    if matches:
        payload = matches[-1].group(1).strip()
    else:
        # Fallback: largest {...} blob
        m = _JSON_BARE_RE.search(raw)
        if not m:
            return {}
        payload = m.group(1)
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        # Last-ditch: trim to the first complete object
        try:
            decoder = json.JSONDecoder()
            return decoder.raw_decode(payload)[0]
        except json.JSONDecodeError:
            return {}


# ---------- Diff generation ----------

def generate_diff(project_root: Path, mode: str, base: str) -> str:
    git = ["git", "-C", str(project_root)]
    if mode == "staged":
        cmd = git + ["diff", "--cached"]
    elif mode == "all":
        cmd = git + ["diff", "HEAD"]
    elif mode == "branch":
        cmd = git + ["diff", f"{base}...HEAD"]
    else:
        raise ValueError(f"unknown diff mode: {mode}")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f"git diff failed: {proc.stderr}", file=sys.stderr)
        return ""
    return proc.stdout


# ---------- Prompt composition ----------

def build_prompt(template_path: Path, diff_text: str,
                 findings: list[dict] | None = None) -> str:
    tmpl = template_path.read_text()
    parts = [tmpl, "", "## Code Changes to Review", "", "```diff",
             diff_text, "```", ""]
    if findings is not None:
        parts += [
            "## Findings to Evaluate",
            "",
            "Each finding below was produced by another reviewer. Your job "
            "is to demolish them per prompt rules above.",
            "",
            "```json",
            json.dumps({"findings": findings}, indent=2),
            "```",
            "",
        ]
    return "\n".join(parts)


# ---------- Main pipeline ----------

def pipeline(args: argparse.Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    if not (project_root / ".git").exists():
        print(f"not a git repo: {project_root}", file=sys.stderr)
        return 2

    # 0) Pre-flight: make check
    if not args.no_preflight:
        if PF.detect_check_target(project_root):
            print("preflight: running make check...", file=sys.stderr)
            pf = PF.run_preflight(project_root)
            if not pf.passed:
                print("preflight: FAILED. Fix before review.\n",
                      file=sys.stderr)
                print(pf.output, file=sys.stderr)
                return 3
            print("preflight: passed", file=sys.stderr)
        else:
            print("preflight: no make check target found, skipping "
                  "(run /project-checks to scaffold one)",
                  file=sys.stderr)

    # 1) Diff
    diff_text = generate_diff(project_root, args.diff_mode, args.base)
    if not diff_text.strip():
        print("empty diff; nothing to review (hint: --all or --branch)",
              file=sys.stderr)
        return 1

    work_dir = Path(tempfile.mkdtemp(prefix="advanced-review-"))
    (work_dir / "diff.patch").write_text(diff_text)
    print(f"work_dir: {work_dir}", file=sys.stderr)

    # 2) Round 1 reviewers
    prompt_path = REPO_ROOT / "prompts" / f"{args.prompt}.md"
    if not prompt_path.exists():
        print(f"prompt template not found: {prompt_path}", file=sys.stderr)
        return 2
    round1_prompt = build_prompt(prompt_path, diff_text)
    (work_dir / "round1_prompt.md").write_text(round1_prompt)

    print("round 1: running reviewers...", file=sys.stderr)
    raw_claude, raw_gemini = run_reviewers_parallel(
        work_dir / "round1_prompt.md", project_root,
    )
    (work_dir / "round1_claude.txt").write_text(raw_claude)
    (work_dir / "round1_gemini.txt").write_text(raw_gemini)

    claude_out = extract_json(raw_claude) or {"findings": []}
    gemini_out = extract_json(raw_gemini) or {"findings": []}

    findings: list[dict] = []
    for f in claude_out.get("findings", []):
        f.setdefault("id", f"c-{len(findings)+1}")
        f["source"] = "claude"
        findings.append(f)
    for f in gemini_out.get("findings", []):
        f.setdefault("id", f"g-{len(findings)+1}")
        f["source"] = "gemini"
        findings.append(f)
    print(f"round 1: {len(findings)} raw findings", file=sys.stderr)

    # 3) Validator
    diff = V.parse_diff(diff_text)
    cwe = V.CWEStore()
    validated = [V.validate_finding(f, diff, cwe) for f in findings]
    (work_dir / "validated.json").write_text(
        json.dumps({"findings": validated}, indent=2))
    dropped = [f for f in validated if f["validator_status"] == "dropped"]
    print(f"validator: dropped {len(dropped)}", file=sys.stderr)

    # 4) Test runner (bug findings)
    review_tests_dir = project_root / "review-tests"
    tc = TR.detect_toolchain(project_root)
    tested: list[dict] = []
    for f in validated:
        if f.get("validator_status") != "passed":
            tested.append({**f, "runner_status": "skipped_upstream"})
            continue
        if f.get("category") != "bug":
            tested.append(TR.apply_disposition(f, test_status=None,
                                               test_path=None))
            continue
        if args.no_test_runner or tc is None:
            tested.append({**f, "runner_status": "skipped"})
            continue
        tested.append(TR.run_bug_finding(f, tc, review_tests_dir,
                                          project_root))

    (work_dir / "tested.json").write_text(
        json.dumps({"findings": tested}, indent=2))

    # Drop unproven tests
    surviving = [f for f in tested
                 if f.get("validator_status") == "passed"
                 and f.get("runner_status") != "unproven"]
    print(f"after test runner: {len(surviving)} surviving", file=sys.stderr)

    # 5) Semgrep (parallel with step 4 in a follow-up; sequential for v1)
    semgrep_findings: list[dict] = []
    if not args.no_semgrep:
        print("semgrep: running...", file=sys.stderr)
        raw = SR.run_semgrep(project_root)
        semgrep_findings = SR.parse_output(raw)
        (work_dir / "semgrep.json").write_text(
            json.dumps({"findings": semgrep_findings}, indent=2))
        print(f"semgrep: {len(semgrep_findings)} findings", file=sys.stderr)

    # 5b) SonarQube (ground truth, persistent container)
    sonar_findings: list[dict] = []
    if not args.no_sonarqube:
        print("sonarqube: running...", file=sys.stderr)
        sonar_findings = SQ.run_sonarqube(project_root)
        (work_dir / "sonarqube.json").write_text(
            json.dumps({"findings": sonar_findings}, indent=2))
        print(f"sonarqube: {len(sonar_findings)} findings", file=sys.stderr)

    # 6) Cross-check round 2
    # Include CRITICAL/WARNING from LLM surviving + SonarQube ground truth
    sonar_cw = [f for f in sonar_findings
                if f.get("severity") in ("CRITICAL", "WARNING")]
    cw_findings = [f for f in surviving
                   if f.get("severity") in ("CRITICAL", "WARNING")]
    cw_findings.extend(sonar_cw)
    claude_verdicts: dict[str, dict] = {}
    gemini_verdicts: dict[str, dict] = {}

    if cw_findings and not args.no_cross_check:
        cross_prompt_path = REPO_ROOT / "prompts" / "cross-check.md"
        cross_prompt = build_prompt(cross_prompt_path, diff_text,
                                    findings=cw_findings)
        (work_dir / "round2_prompt.md").write_text(cross_prompt)
        print(f"round 2: cross-check on {len(cw_findings)} findings...",
              file=sys.stderr)
        raw_c2_claude, raw_c2_gemini = run_reviewers_parallel(
            work_dir / "round2_prompt.md", project_root,
        )
        (work_dir / "round2_claude.txt").write_text(raw_c2_claude)
        (work_dir / "round2_gemini.txt").write_text(raw_c2_gemini)

        vc = extract_json(raw_c2_claude).get("verdicts", [])
        vg = extract_json(raw_c2_gemini).get("verdicts", [])
        vc = [V.validate_verdict(v, diff) for v in vc]
        vg = [V.validate_verdict(v, diff) for v in vg]
        claude_verdicts = {v["finding_id"]: v for v in vc
                           if v.get("finding_id")}
        gemini_verdicts = {v["finding_id"]: v for v in vg
                           if v.get("finding_id")}
        (work_dir / "claude_verdicts.json").write_text(
            json.dumps({"verdicts": list(claude_verdicts.values())}, indent=2))
        (work_dir / "gemini_verdicts.json").write_text(
            json.dumps({"verdicts": list(gemini_verdicts.values())}, indent=2))

    # 7) Merge
    annotated = MG.annotate_with_verdicts(surviving, claude_verdicts,
                                          gemini_verdicts)
    # SonarQube CRITICAL/WARNING that went through cross-check get verdicts too
    sonar_annotated = MG.annotate_with_verdicts(sonar_cw, claude_verdicts,
                                                gemini_verdicts)
    sonar_info = [f for f in sonar_findings
                  if f.get("severity") not in ("CRITICAL", "WARNING")]
    all_sonar = sonar_annotated + sonar_info

    report_md = MG.build_report(annotated, semgrep_findings=semgrep_findings,
                                sonar_findings=all_sonar)
    out_md = work_dir / "report.md"
    out_json = work_dir / "report.json"
    out_md.write_text(report_md)
    out_json.write_text(json.dumps(
        {"findings": annotated + semgrep_findings + all_sonar}, indent=2))

    print(f"\nReport: {out_md}")
    print(f"JSON:   {out_json}")
    if review_tests_dir.exists() and any(review_tests_dir.iterdir()):
        print(f"Tests:  {review_tests_dir}")
    return 0


# ---------- CLI ----------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced review with verifiable claims.",
    )
    parser.add_argument("--project-root", default=os.getcwd(),
                        help="Git repository to review (default: cwd)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_const", dest="diff_mode",
                      const="all", help="Review all uncommitted changes")
    mode.add_argument("--branch", dest="base", metavar="BASE",
                      help="Review current branch vs BASE (default main)")
    parser.add_argument("--prompt", default="default",
                        choices=("default", "ci-style"))
    parser.add_argument("--no-preflight", action="store_true")
    parser.add_argument("--no-semgrep", action="store_true")
    parser.add_argument("--no-sonarqube", action="store_true")
    parser.add_argument("--no-cross-check", action="store_true")
    parser.add_argument("--no-test-runner", action="store_true")
    args = parser.parse_args(argv)
    if args.base is not None:
        args.diff_mode = "branch"
    elif not hasattr(args, "diff_mode") or args.diff_mode is None:
        args.diff_mode = "staged"
    if args.base is None:
        args.base = "main"
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    return pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
