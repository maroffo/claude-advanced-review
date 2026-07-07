# ABOUTME: Change-contract for making the SonarQube step opt-in (--sonarqube) in advanced-review
# ABOUTME: Six fields from arxiv 2605.18747 §5.2.3 (treat harness edits like safety-critical code)

# Harness Change Contract: SonarQube step becomes opt-in

Authored before the change lands. Linked from the commit body. Append-only after merge.

## Component

Skill `advanced-review` (`orchestrator.py` CLI flag + step 5b gating in both `pipeline` and `pipeline_repo`; `SKILL.md` description/compatibility/options/step 5b; `tests/test_orchestrator_args.py` new).

## Failure mode targeted

SonarQube ran by default on every review. On any machine without the persistent `sonarqube-review` container already set up, `ensure_running()` pulls `sonarqube:community`, boots a server (~60-120s cold start, port 9000, two named volumes), and only then scans; on machines where that fails it still burns the 180s health-check timeout before degrading. The heaviest, most stateful step of the pipeline was the only one a user could not opt into, only out of (`--no-sonarqube`), and the default punished every fresh environment.

## Predicted improvement

Default runs (`/advanced-review` with no flags) never touch Docker for SonarQube: zero image pulls, zero port-9000 contention, no 180s worst-case wait, 10/10 runs. When `--sonarqube` is passed, behavior is byte-identical to the previous default-on path.

## Invariants preserved

- With `--sonarqube`, step 5b behavior is unchanged (same runner, same scoping, same graceful degradation to `[]` on server failure).
- Semgrep remains the default ground-truth reviewer, untouched.
- The skipped step logs `sonarqube: skipped (opt-in; pass --sonarqube to enable)` on stderr, so a skipped step is never silent.
- Merge matrix rows for sonarqube findings are unchanged (they simply see an empty list when skipped).
- `make check` (ruff + pip-audit + pytest) and `make test-e2e` stay green.

## Falsification

If within the next 10 reviews a real defect surfaces that SonarQube would have caught (verifiable by re-running with `--sonarqube` on the same diff) and the LLM reviewers plus Semgrep all missed it, the opt-out default was doing protective work: revert to default-on or add an auto-enable heuristic (run when the container already exists).

## Rollback

`git revert <commit>` in the claude-advanced-review repo. Affects: orchestrator.py, SKILL.md, tests/test_orchestrator_args.py.

---

## Result (filled in AFTER merge, append-only)

| Date | Sample size | Observed metric | Verdict |
|------|-------------|-----------------|---------|
