# ABOUTME: Merge round-1 findings with round-2 verdicts, Semgrep, and SonarQube output
# ABOUTME: Deduplicates cross-chunk findings and emits a final markdown report + JSON

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------- Confidence classification ----------

def _effective_verdict(v: dict | None) -> str | None:
    if v is None:
        return None
    if v.get("validator_status") == "discarded" and v.get("effective_verdict"):
        return v["effective_verdict"]
    return v.get("verdict")


def classify_confidence(claude_verdict: dict | None,
                        gemini_verdict: dict | None) -> str:
    """Apply the merge matrix from SKILL.md step 7.

    | Outcome | Tag |
    |---------|-----|
    | both ACCEPT | HIGH_CONFIDENCE |
    | one ACCEPT + one MODIFY (or both MODIFY) | MODIFIED |
    | any REJECT-WITH-COUNTER-EVIDENCE | DISPUTED |
    | any validated REFUTE-BY-EXPLANATION | DISPUTED |
    | any missing verdict | UNVERIFIED |
    """
    cv = _effective_verdict(claude_verdict)
    gv = _effective_verdict(gemini_verdict)

    if cv is None or gv is None:
        return "UNVERIFIED"

    disputed = {"REJECT-WITH-COUNTER-EVIDENCE", "REFUTE-BY-EXPLANATION"}
    if cv in disputed or gv in disputed:
        return "DISPUTED"

    if cv == "ACCEPT" and gv == "ACCEPT":
        return "HIGH_CONFIDENCE"

    if "MODIFY" in (cv, gv):
        return "MODIFIED"

    return "UNVERIFIED"


# ---------- Report rendering ----------

_SEVERITY_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}


def _finding_sort_key(f: dict) -> tuple:
    return (
        _SEVERITY_ORDER.get(f.get("severity", "INFO"), 99),
        f.get("confidence", "UNVERIFIED") != "HIGH_CONFIDENCE",
        f.get("file", ""),
        f.get("line", 0),
    )


def build_report(findings: list[dict],
                 semgrep_findings: list[dict] | None = None,
                 sonar_findings: list[dict] | None = None) -> str:
    findings = sorted(findings, key=_finding_sort_key)
    out: list[str] = ["# Advanced Review Report", ""]

    total_critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    total_warning = sum(1 for f in findings if f.get("severity") == "WARNING")
    total_info = sum(1 for f in findings if f.get("severity") == "INFO")
    total_semgrep = len(semgrep_findings or [])
    total_sonar = len(sonar_findings or [])

    out.append(
        f"**Summary:** {total_critical} CRITICAL, {total_warning} WARNING, "
        f"{total_info} INFO from LLM reviewers; {total_semgrep} from Semgrep; "
        f"{total_sonar} from SonarQube."
    )
    out.append("")

    for sev in ("CRITICAL", "WARNING", "INFO"):
        section = [f for f in findings if f.get("severity") == sev]
        if not section:
            continue
        out.append(f"## {sev}")
        out.append("")
        for f in section:
            out.extend(_render_finding(f))

    if semgrep_findings:
        out.append("## Semgrep (ground truth)")
        out.append("")
        for f in sorted(semgrep_findings, key=_finding_sort_key):
            out.extend(_render_finding(f, source_override="semgrep"))

    if sonar_findings:
        out.append("## SonarQube (ground truth)")
        out.append("")
        for f in sorted(sonar_findings, key=_finding_sort_key):
            out.extend(_render_finding(f, source_override="sonarqube"))

    return "\n".join(out)


def _render_finding(f: dict, source_override: str | None = None) -> list[str]:
    source = source_override or f.get("source", "unknown")
    confidence = f.get("confidence", "UNVERIFIED")
    file = f.get("file", "?")
    line = f.get("line", "?")
    out = [
        f"### [{confidence}] {file}:{line} — {f.get('problem', '(no description)')}",
        "",
        f"- **Source:** {source}",
        f"- **Category:** {f.get('category', '?')}",
        f"- **Suggestion:** {f.get('suggestion', '(none)')}",
    ]

    ev = f.get("evidence") or {}
    if ev.get("cwe_id"):
        out.append(f"- **CWE:** [{ev['cwe_id']}]({ev.get('cwe_url', '')})")
    if ev.get("test_target_file") and f.get("test_path"):
        out.append(f"- **Red-green test:** `{f['test_path']}`")
    if ev.get("big_o"):
        out.append(f"- **Big-O:** {ev['big_o']}")
    if ev.get("convention_file"):
        out.append(f"- **Convention:** "
                   f"{ev['convention_file']} — `{ev.get('convention_line_or_grep','')}`")
    if ev.get("principle"):
        out.append(f"- **Principle:** {ev['principle']}")

    cv = f.get("claude_verdict")
    gv = f.get("gemini_verdict")
    if cv or gv:
        out.append(f"- **Cross-check:** "
                   f"claude={_effective_verdict(cv) or '—'}, "
                   f"gemini={_effective_verdict(gv) or '—'}")

    out.append("")
    return out


# ---------- Cross-chunk deduplication ----------

def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate findings across chunks by (file, category, problem_key).

    When multiple chunks flag the same issue on the same file, keep the one
    with the highest severity. Uses the first 60 chars of the problem as a
    dedup key (catches near-identical descriptions from different chunks).
    """
    _SEV_RANK = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (
            f.get("file", ""),
            f.get("category", ""),
            f.get("problem", "")[:60].lower().strip(),
        )
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        else:
            # Keep highest severity
            old_rank = _SEV_RANK.get(existing.get("severity", "INFO"), 2)
            new_rank = _SEV_RANK.get(f.get("severity", "INFO"), 2)
            if new_rank < old_rank:
                seen[key] = f

    return list(seen.values())


# ---------- Merge pipeline ----------

def annotate_with_verdicts(findings: list[dict],
                           claude_verdicts: dict[str, dict],
                           gemini_verdicts: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        fid = f.get("id")
        cv = claude_verdicts.get(fid)
        gv = gemini_verdicts.get(fid)
        confidence = classify_confidence(cv, gv)
        merged = {**f, "claude_verdict": cv, "gemini_verdict": gv,
                  "confidence": confidence}

        # MODIFY: surface the corrected severity/suggestion
        for verdict in (cv, gv):
            if verdict and verdict.get("verdict") == "MODIFY":
                mod = verdict.get("modification", {}) or {}
                if mod.get("severity"):
                    merged["severity"] = mod["severity"]
                if mod.get("suggestion"):
                    merged["modified_suggestion"] = mod["suggestion"]
        out.append(merged)
    return out


# ---------- CLI ----------

def _main() -> int:
    parser = argparse.ArgumentParser(description="Merge findings into a final report.")
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--claude-verdicts", type=Path)
    parser.add_argument("--gemini-verdicts", type=Path)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--sonarqube", type=Path)
    parser.add_argument("--out-md", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()

    findings = json.loads(args.findings.read_text()).get("findings", [])

    def _load_verdicts(path: Path | None) -> dict[str, dict]:
        if not path or not path.exists():
            return {}
        data = json.loads(path.read_text())
        return {v["finding_id"]: v for v in data.get("verdicts", [])
                if v.get("finding_id")}

    claude_verdicts = _load_verdicts(args.claude_verdicts)
    gemini_verdicts = _load_verdicts(args.gemini_verdicts)
    semgrep = []
    if args.semgrep and args.semgrep.exists():
        semgrep = json.loads(args.semgrep.read_text()).get("findings", [])
    sonar = []
    if args.sonarqube and args.sonarqube.exists():
        sonar = json.loads(args.sonarqube.read_text()).get("findings", [])

    annotated = annotate_with_verdicts(findings, claude_verdicts, gemini_verdicts)
    merged_all = annotated + semgrep + sonar

    args.out_md.write_text(build_report(annotated, semgrep_findings=semgrep,
                                        sonar_findings=sonar))
    args.out_json.write_text(json.dumps({"findings": merged_all}, indent=2))
    print(f"merge: {len(annotated)} LLM, {len(semgrep)} semgrep, "
          f"{len(sonar)} sonarqube -> {args.out_md}, {args.out_json}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
