# ABOUTME: End-to-end orchestrator for claude-advanced-review
# ABOUTME: Glue: preflight -> diff/collect -> round1 -> validate -> SAST -> round2 -> merge (diff + repo modes)

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
from runner import repo_collector as RC  # noqa: E402
from merge import merger as MG  # noqa: E402


# ---------- Docker reviewer calls ----------

CLAUDE_IMAGE = "claude-reviewer:latest"
GEMINI_IMAGE = "gemini-reviewer:latest"
DEEPSEEK_IMAGE = "deepseek-reviewer:latest"
GEMINI_KEY_PATH = Path.home() / ".config" / "gemini-api-key"
DEEPSEEK_KEY_PATH = Path.home() / ".config" / "deepseek-api-key"

# deepseek-reasoner (R1) can spend several minutes reasoning before answering,
# so it gets a longer wall-clock budget than the other two reviewers.
CLAUDE_TIMEOUT = 300
GEMINI_TIMEOUT = 300
DEEPSEEK_TIMEOUT = 600


def _read_gemini_key() -> str:
    if not GEMINI_KEY_PATH.exists():
        raise SystemExit(f"missing {GEMINI_KEY_PATH}")
    return GEMINI_KEY_PATH.read_text().strip()


def _read_deepseek_key() -> str:
    if not DEEPSEEK_KEY_PATH.exists():
        raise SystemExit(f"missing {DEEPSEEK_KEY_PATH}")
    return DEEPSEEK_KEY_PATH.read_text().strip()


def _classify_failure(name: str, proc: subprocess.CompletedProcess,
                      secret: str | None = None) -> None:
    """Log why a reviewer produced no usable output. A non-zero exit is a
    failure (auth, rate limit, crash), distinct from a clean empty answer.
    Surfaces a re-login hint on auth failure so a stale token never degrades
    silently. `secret` (the reviewer's API key, if any) is redacted from the
    logged tail so a CLI that echoes it on error cannot leak it."""
    blob = f"{proc.stdout}\n{proc.stderr}"
    low = blob.lower()
    is_auth = ("invalid authentication" in low or "unauthorized" in low
               or ("401" in blob and "auth" in low))
    if is_auth:
        print(f"{name}: FAILED (auth expired/invalid; re-login the reviewer "
              f"volume/key)", file=sys.stderr)
        return
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = tail[-1] if tail else "no output"
    if secret:
        reason = reason.replace(secret, "***")
    print(f"{name}: FAILED (exit {proc.returncode}: {reason})",
          file=sys.stderr)


def run_claude(prompt_file: Path, project_root: Path,
               timeout: int = CLAUDE_TIMEOUT) -> str:
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
    except subprocess.TimeoutExpired:
        print(f"claude: FAILED (timeout after {timeout}s)", file=sys.stderr)
        return ""
    if proc.returncode != 0:
        _classify_failure("claude", proc)
        return ""
    return proc.stdout


def run_gemini(prompt_file: Path, project_root: Path,
               timeout: int = GEMINI_TIMEOUT) -> str:
    key = _read_gemini_key()
    # Pass the key by name only: Docker forwards the value from this process's
    # environment, keeping the secret out of the container's argv (ps-visible).
    cmd = [
        "docker", "run", "--rm",
        "-e", "GEMINI_API_KEY",
        "-v", f"{project_root.resolve()}:/workspace:ro",
        GEMINI_IMAGE,
        "-p", prompt_file.read_text(),
        "-m", "gemini-3.1-pro-preview",
        "--sandbox", "false",
        "--skip-trust",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout,
                              env={**os.environ, "GEMINI_API_KEY": key})
    except subprocess.TimeoutExpired:
        print(f"gemini: FAILED (timeout after {timeout}s)", file=sys.stderr)
        return ""
    if proc.returncode != 0:
        _classify_failure("gemini", proc, secret=key)
        return ""
    # Strip known noisy lines from Gemini CLI
    cleaned = "\n".join(
        line for line in proc.stdout.splitlines()
        if not line.startswith("[WARN] Skipping unreadable")
        and not line.startswith("Warning: Could not read")
    )
    return cleaned


def run_deepseek(prompt_file: Path, project_root: Path,
                 timeout: int = DEEPSEEK_TIMEOUT) -> str:
    key = _read_deepseek_key()
    # Pass the key by name only: Docker forwards the value from this process's
    # environment, keeping the secret out of the container's argv (ps-visible).
    cmd = [
        "docker", "run", "--rm",
        "-e", "DEEPSEEK_API_KEY",
        "-v", f"{project_root.resolve()}:/workspace:ro",
        DEEPSEEK_IMAGE,
        "--provider", "deepseek",
        "--model", "deepseek-reasoner",
        "-p", "-t", "read", "--no-session",
        prompt_file.read_text(),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout,
                              env={**os.environ, "DEEPSEEK_API_KEY": key})
    except subprocess.TimeoutExpired:
        print(f"deepseek: FAILED (timeout after {timeout}s)", file=sys.stderr)
        return ""
    if proc.returncode != 0:
        _classify_failure("deepseek", proc, secret=key)
        return ""
    return proc.stdout


def run_reviewers_parallel(prompt_file: Path,
                           project_root: Path) -> tuple[str, str, str]:
    """Run all three reviewers concurrently. A reviewer that fails (timeout,
    auth, crash) yields an empty string and is reported on stderr; the pipeline
    degrades to the survivors rather than aborting."""
    with cf.ThreadPoolExecutor(max_workers=3) as pool:
        f_claude = pool.submit(run_claude, prompt_file, project_root)
        f_gemini = pool.submit(run_gemini, prompt_file, project_root)
        f_deepseek = pool.submit(run_deepseek, prompt_file, project_root)
        raw_claude = f_claude.result()
        raw_gemini = f_gemini.result()
        raw_deepseek = f_deepseek.result()
    status = " | ".join(
        f"{name} {'OK' if raw else 'FAILED'}"
        for name, raw in (("claude", raw_claude), ("gemini", raw_gemini),
                          ("deepseek", raw_deepseek))
    )
    print(f"reviewer status: {status}", file=sys.stderr)
    return raw_claude, raw_gemini, raw_deepseek


def _collect_verdicts(work_dir: Path, diff: Any | None, raw_claude: str,
                      raw_gemini: str, raw_deepseek: str,
                      ) -> tuple[dict[str, dict], dict[str, dict],
                                 dict[str, dict]]:
    """Parse round-2 verdicts for all three reviewers, persisting raw output
    and verdicts to the work dir. Returns one finding_id -> verdict map per
    reviewer (empty if that reviewer failed). When `diff` is provided (diff
    mode) verdicts are validated against it; in repo mode there is no diff to
    validate against, so `diff=None` takes the verdicts raw."""
    results: list[dict[str, dict]] = []
    for source, raw in (("claude", raw_claude), ("gemini", raw_gemini),
                        ("deepseek", raw_deepseek)):
        (work_dir / f"round2_{source}.txt").write_text(raw)
        verdicts = extract_json(raw).get("verdicts", [])
        if diff is not None:
            verdicts = [V.validate_verdict(v, diff) for v in verdicts]
        by_id = {v["finding_id"]: v for v in verdicts if v.get("finding_id")}
        (work_dir / f"{source}_verdicts.json").write_text(
            json.dumps({"verdicts": list(by_id.values())}, indent=2))
        results.append(by_id)
    return results[0], results[1], results[2]


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
    raw_claude, raw_gemini, raw_deepseek = run_reviewers_parallel(
        work_dir / "round1_prompt.md", project_root,
    )
    (work_dir / "round1_claude.txt").write_text(raw_claude)
    (work_dir / "round1_gemini.txt").write_text(raw_gemini)
    (work_dir / "round1_deepseek.txt").write_text(raw_deepseek)

    findings: list[dict] = []
    for source, raw, prefix in (("claude", raw_claude, "c"),
                                ("gemini", raw_gemini, "g"),
                                ("deepseek", raw_deepseek, "d")):
        out = extract_json(raw) or {"findings": []}
        for f in out.get("findings", []):
            f.setdefault("id", f"{prefix}-{len(findings)+1}")
            f["source"] = source
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
        sonar_findings = SQ.run_sonarqube(
            project_root,
            diff_mode=args.diff_mode,
            base_ref=args.base,
        )
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
    deepseek_verdicts: dict[str, dict] = {}

    if cw_findings and not args.no_cross_check:
        cross_prompt_path = REPO_ROOT / "prompts" / "cross-check.md"
        cross_prompt = build_prompt(cross_prompt_path, diff_text,
                                    findings=cw_findings)
        (work_dir / "round2_prompt.md").write_text(cross_prompt)
        print(f"round 2: cross-check on {len(cw_findings)} findings...",
              file=sys.stderr)
        raw_c2_claude, raw_c2_gemini, raw_c2_deepseek = run_reviewers_parallel(
            work_dir / "round2_prompt.md", project_root,
        )
        claude_verdicts, gemini_verdicts, deepseek_verdicts = (
            _collect_verdicts(work_dir, diff, raw_c2_claude, raw_c2_gemini,
                              raw_c2_deepseek))

    # 7) Merge
    annotated = MG.annotate_with_verdicts(surviving, claude_verdicts,
                                          gemini_verdicts, deepseek_verdicts)
    # SonarQube CRITICAL/WARNING that went through cross-check get verdicts too
    sonar_annotated = MG.annotate_with_verdicts(sonar_cw, claude_verdicts,
                                                gemini_verdicts,
                                                deepseek_verdicts)
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
    mode.add_argument("--repo", nargs="?", const=".", metavar="PATH",
                      help="Full-repo review (optionally scoped to PATH)")
    parser.add_argument("--prompt", default="default",
                        choices=("default", "ci-style", "repo-review"))
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


def pipeline_repo(args: argparse.Namespace) -> int:
    """Full-repository review: collect files, chunk, LLM per chunk, SAST, merge."""
    project_root = Path(args.project_root).resolve()
    repo_path = (project_root / args.repo).resolve() if args.repo != "." else project_root

    if not (project_root / ".git").exists():
        print(f"not a git repo: {project_root}", file=sys.stderr)
        return 2

    # 0) Pre-flight
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

    work_dir = Path(tempfile.mkdtemp(prefix="advanced-review-repo-"))
    print(f"work_dir: {work_dir}", file=sys.stderr)

    # 1) Collect files and generate skeleton
    print("repo: collecting files...", file=sys.stderr)
    files = RC.collect_files(repo_path)
    if not files:
        print(f"repo: no reviewable files found in {repo_path}",
              file=sys.stderr)
        return 1
    print(f"repo: {len(files)} files collected", file=sys.stderr)

    skeleton = RC.generate_skeleton(files)
    (work_dir / "skeleton.txt").write_text(skeleton)

    # 2) Chunk by directory
    chunks = RC.chunk_by_directory(files)
    print(f"repo: {len(chunks)} chunks", file=sys.stderr)

    # 3) LLM review per chunk
    prompt_path = REPO_ROOT / "prompts" / "repo-review.md"
    prompt_template = prompt_path.read_text()
    cwe = V.CWEStore()
    all_findings: list[dict] = []

    for i, chunk_files in enumerate(chunks):
        chunk_label = f"chunk {i+1}/{len(chunks)}"
        print(f"repo: reviewing {chunk_label}...", file=sys.stderr)

        # Build file contents for this chunk
        file_contents: list[str] = []
        for f in chunk_files:
            try:
                rel = f.relative_to(project_root)
            except ValueError:
                rel = f.name
            try:
                content = f.read_text(errors="replace")
            except OSError:
                continue
            file_contents.append(f"### {rel}\n```\n{content}\n```")

        files_block = "\n\n".join(file_contents)
        prompt_text = prompt_template.replace("{{SKELETON}}", skeleton)
        prompt_text = prompt_text.replace("{{FILES}}", files_block)

        prompt_file = work_dir / f"chunk_{i}_prompt.md"
        prompt_file.write_text(prompt_text)

        # Run reviewers
        raw_claude, raw_gemini, raw_deepseek = run_reviewers_parallel(
            prompt_file, project_root)
        (work_dir / f"chunk_{i}_claude.txt").write_text(raw_claude)
        (work_dir / f"chunk_{i}_gemini.txt").write_text(raw_gemini)
        (work_dir / f"chunk_{i}_deepseek.txt").write_text(raw_deepseek)

        chunk_findings: list[dict] = []
        for source, raw, prefix in (("claude", raw_claude, "c"),
                                    ("gemini", raw_gemini, "g"),
                                    ("deepseek", raw_deepseek, "d")):
            out = extract_json(raw) or {"findings": []}
            for f in out.get("findings", []):
                f.setdefault("id", f"{prefix}-{i}-{len(chunk_findings)+1}")
                f["source"] = source
                chunk_findings.append(f)

        # Validate (repo mode: check file/line existence, no diff)
        validated = [V.validate_finding_repo(f, project_root, cwe)
                     for f in chunk_findings]
        passed = [f for f in validated if f["validator_status"] == "passed"]
        dropped = len(validated) - len(passed)
        print(f"  {chunk_label}: {len(passed)} passed, {dropped} dropped",
              file=sys.stderr)
        all_findings.extend(passed)

    # 4) Deduplicate cross-chunk
    before_dedup = len(all_findings)
    all_findings = MG.deduplicate_findings(all_findings)
    print(f"repo: dedup {before_dedup} -> {len(all_findings)}",
          file=sys.stderr)

    # 5) Semgrep
    semgrep_findings: list[dict] = []
    if not args.no_semgrep:
        print("semgrep: running...", file=sys.stderr)
        raw = SR.run_semgrep(project_root)
        semgrep_findings = SR.parse_output(raw)
        print(f"semgrep: {len(semgrep_findings)} findings", file=sys.stderr)

    # 5b) SonarQube
    sonar_findings: list[dict] = []
    if not args.no_sonarqube:
        print("sonarqube: running...", file=sys.stderr)
        sonar_findings = SQ.run_sonarqube(
            project_root,
            diff_mode=args.diff_mode,
            base_ref=args.base,
        )
        print(f"sonarqube: {len(sonar_findings)} findings", file=sys.stderr)

    # 6) Cross-check on CRITICAL/WARNING
    cw_findings = [f for f in all_findings
                   if f.get("severity") in ("CRITICAL", "WARNING")]
    claude_verdicts: dict[str, dict] = {}
    gemini_verdicts: dict[str, dict] = {}
    deepseek_verdicts: dict[str, dict] = {}

    if cw_findings and not args.no_cross_check:
        cross_prompt_path = REPO_ROOT / "prompts" / "cross-check.md"
        # Build a pseudo-diff context from file contents for cross-check
        cross_files = {f.get("file", "") for f in cw_findings}
        file_ctx = []
        for fp in cross_files:
            full = project_root / fp
            if full.is_file():
                try:
                    file_ctx.append(f"### {fp}\n```\n{full.read_text(errors='replace')}\n```")
                except OSError:
                    pass
        file_context = "\n\n".join(file_ctx)
        cross_prompt = build_prompt(cross_prompt_path, file_context,
                                    findings=cw_findings)
        (work_dir / "cross_check_prompt.md").write_text(cross_prompt)
        print(f"round 2: cross-check on {len(cw_findings)} findings...",
              file=sys.stderr)
        raw_c2_claude, raw_c2_gemini, raw_c2_deepseek = run_reviewers_parallel(
            work_dir / "cross_check_prompt.md", project_root,
        )
        # Repo mode has no diff, so verdicts are taken raw (diff=None).
        claude_verdicts, gemini_verdicts, deepseek_verdicts = _collect_verdicts(
            work_dir, None, raw_c2_claude, raw_c2_gemini, raw_c2_deepseek)

    # 7) Merge
    annotated = MG.annotate_with_verdicts(all_findings, claude_verdicts,
                                          gemini_verdicts, deepseek_verdicts)
    report_md = MG.build_report(annotated, semgrep_findings=semgrep_findings,
                                sonar_findings=sonar_findings)
    out_md = work_dir / "report.md"
    out_json = work_dir / "report.json"
    out_md.write_text(report_md)
    out_json.write_text(json.dumps(
        {"findings": annotated + semgrep_findings + sonar_findings}, indent=2))

    print(f"\nReport: {out_md}")
    print(f"JSON:   {out_json}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if args.repo is not None:
        return pipeline_repo(args)
    return pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
