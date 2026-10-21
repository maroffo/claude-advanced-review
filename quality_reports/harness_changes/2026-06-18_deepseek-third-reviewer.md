# ABOUTME: Change-contract for adding DeepSeek as a third reviewer + failure classification in advanced-review
# ABOUTME: Six fields from arxiv 2605.18747 §5.2.3 (treat harness edits like safety-critical code)

# Harness Change Contract: DeepSeek third reviewer + reviewer failure classification

Authored before the change lands. Linked from the commit body. Append-only after merge.

## Component

Skill `advanced-review` (`orchestrator.py` reviewer calls + round-1/round-2 in both `pipeline` and `pipeline_repo`; `merge/merger.py` confidence rubric + `annotate_with_verdicts`; tests; `SKILL.md` description/flow/merge-matrix; `README.md`). Ports the robustness work done for the `second-opinion` skill and adds DeepSeek as a structurally different third reviewer.

## Failure mode targeted

Two coupled gaps. (1) `advanced-review` ran only Claude + Gemini, two Western frontier models whose agreement can be shared-model bias rather than truth. (2) `run_claude`/`run_gemini` caught only `TimeoutExpired`; a non-zero exit (expired OAuth `401`, rate limit, crash) returned empty stdout silently, so a dead reviewer was indistinguishable from a clean empty answer and never surfaced.

## Predicted improvement

Over the next ~10 `advanced-review` runs: (a) DeepSeek contributes a verdict that changes a finding's confidence tag vs the Claude+Gemini-only outcome in at least 1 case (third-lab signal is doing work); (b) any reviewer failure prints a `reviewer status:` line naming the failed reviewer and reason, 10/10, with a re-login hint on `401`; (c) a single reviewer failure never collapses all findings to `UNVERIFIED` (majority is computed on present verdicts, min 2).

## Invariants preserved

- A failed reviewer degrades to empty output; the pipeline still produces a report from the survivors (never aborts on one reviewer).
- Identical prompt to all three reviewers each round.
- The 2-of-3 majority rubric reproduces the old 2-reviewer outcomes when exactly two verdicts are present (verified: all pre-existing e2e merge assertions still pass unchanged).
- DeepSeek isolation matches the others: project mounted `:ro`, `-t read` (no edit/write/bash), `--no-session`, key passed in-memory via env.
- `make check` (ruff + pip-audit + pytest) and `make test-e2e` stay green.

## Falsification

If across the next 10 runs DeepSeek never changes any confidence tag relative to the two-reviewer baseline, the third reviewer is pure cost, drop it. If a reviewer failure is ever swallowed without a `reviewer status:`/`FAILED` line, or a single failure drops everything to `UNVERIFIED`, the robustness change is not working, revert it.

## Rollback

`git revert <commit>` in the claude-advanced-review repo. Affects: orchestrator.py, merge/merger.py, tests/test_merge.py, tests/e2e/test_orchestrator_e2e.py, SKILL.md, README.md.

---

## Result (filled in AFTER merge, append-only)

| Date | Sample size | Observed metric | Verdict |
|------|-------------|-----------------|---------|
