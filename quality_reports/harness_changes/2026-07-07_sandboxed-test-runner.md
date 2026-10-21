# ABOUTME: Change-contract for executing LLM-proposed red-green tests inside an ephemeral Docker sandbox
# ABOUTME: Six fields from arxiv 2605.18747 §5.2.3 (treat harness edits like safety-critical code)

# Harness Change Contract: sandboxed test runner (no host execution of LLM-authored tests)

Authored before the change lands. Linked from the commit body. Append-only after merge.

## Component

Runner `runner/test_runner.py` (execution path: new `SANDBOX_IMAGES` map, `build_container_script`, `build_sandbox_cmd`, `_run_test_in_sandbox`, `classify_sandbox_result`, `apply_disposition` gains a `sandbox_unavailable` status + `runner_reason`; host `_run_test` removed; `run_bug_finding` rewired to the sandbox) and its unit tests `tests/test_test_runner.py`. The orchestrator filter is untouched: it already drops only `unproven`, so the new `sandbox_unavailable` status survives like `skipped` with no edit there.

## Failure mode targeted

Host RCE via LLM-proposed test code (CWE-94/95). `_write_test_file` wrote `evidence.test` — a string authored by a reviewer LLM that had just read an untrusted diff — to `review-tests/`, then `_run_test` executed it with `subprocess.run(cmd, cwd=project_root)` under operator privileges. A prompt-injection payload in a reviewed diff could steer the LLM into emitting a "test" that runs arbitrary code on the host and exfiltrates API keys. One failure mode: untrusted test code executing on the host.

## Predicted improvement

Over the next ~10 `advanced-review` runs that reach the test runner: (a) every proposed test executes inside `docker run --rm --network none --read-only --pids-limit 256 --memory 1g` with the project and test file mounted `:ro` and only a `/tmp` tmpfs writable — no LLM-authored test process ever runs on the host, 10/10; (b) a clean in-sandbox failure still yields `confirmed` and a clean pass still yields `unproven`/dropped, so bug-detection recall is unchanged for tests the sandbox can actually run; (c) when the sandbox cannot deliver a verdict (docker/image missing, deps absent, timeout, container error) the finding SURVIVES as `sandbox_unavailable` with a human-readable `runner_reason`, never silently dropped and never re-run on the host.

## Invariants preserved

- NEVER fall back to host execution. Any inability to run in the sandbox degrades to `sandbox_unavailable`, not a host `subprocess.run` of the test.
- The orchestrator's "drop only `unproven`" rule is unchanged; `sandbox_unavailable` findings survive exactly like the old `skipped` status.
- Red-green semantics hold: test fails in sandbox => bug demonstrated (`confirmed`); test passes => claim `unproven` (dropped).
- Surviving tests (`confirmed` and `sandbox_unavailable`) are still written to `review-tests/` for the human; only `unproven` test files are deleted.
- The dep-vs-bug heuristic is conservative: import/framework-global/infra signatures and pytest usage exit codes (2/3/4/5) route to `sandbox_unavailable`, so a missing dependency is never misread as a real bug.
- `-k <name>` is passed as two shell tokens (regression fixed), so pytest name filtering is honored.
- `uv run pytest tests/test_test_runner.py` and `uv run ruff check` stay green.

## Falsification

If any LLM-proposed test is ever executed on the host (a `subprocess.run` whose argv[0] is not `docker`), the change failed its one job — revert. If a `sandbox_unavailable` finding is silently dropped, or a clean in-sandbox failure stops producing `confirmed`, the classification is broken — revert. If, across the next 10 real runs, effectively every finding lands on `sandbox_unavailable` because the bare slim images can never satisfy project deps, the sandbox is too austere to be useful and needs a deps-install step or per-project image before it earns its place.

## Rollback

`git revert <commit>` in the claude-advanced-review repo. Affects: `runner/test_runner.py`, `tests/test_test_runner.py`.

---

## Result (filled in AFTER merge, append-only)

| Date | Sample size | Observed metric | Verdict |
|------|-------------|-----------------|---------|
