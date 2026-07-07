# ABOUTME: Change-contract for the reviewer egress guard (internal network + allowlist proxy)
# ABOUTME: Six fields from arxiv 2605.18747 §5.2.3 (treat harness edits like safety-critical code)

# Harness Change Contract: reviewer containers get an egress guard

Authored before the change lands. Linked from the commit body. Append-only after merge.

## Component

Skill `advanced-review` (`orchestrator.py`: `EGRESS_*` constants, `_squid_conf`, `_egress_args`, `ensure_egress_guard`, `_egress_gate`, `egress` parameter threaded through `run_claude`/`run_gemini`/`run_deepseek`/`run_reviewers_parallel`/`_run_cross_check`, `--no-egress-guard` flag; `tests/test_orchestrator_reviewers.py`; `tests/e2e/test_orchestrator_e2e.py`; `SKILL.md` compatibility/options/step 2/troubleshooting; `README.md`).

## Failure mode targeted

Reviewer containers hold live credentials (Claude creds volume, Gemini/DeepSeek API keys in env) and open network while consuming untrusted diffs. A prompt-injection payload in a reviewed diff that steers the in-container CLI into an outbound request can exfiltrate those secrets to an attacker host (CWE-668/CWE-200). One failure mode: secret exfiltration from a reviewer container via unrestricted egress.

## Predicted improvement

With the guard on (default), a reviewer container can complete a TLS CONNECT only to the hosts in `EGRESS_ALLOWED_HOSTS` (exact model-API hosts, no wildcards); CONNECT to any other host is denied by the squid proxy and direct egress is impossible (internal network, no default route). Verified empirically before landing: all three real reviewers answered through the guard; `https://example.com` was refused with proxy 403; direct egress could not even resolve DNS.

## Invariants preserved

- All three reviewers still produce reviews with the guard on (verified live: `reviewer status: claude OK | gemini OK | deepseek OK` on a real staged diff with the guard created from scratch).
- Reviewer failure stays non-silent (`reviewer status:` line, `_classify_failure` redaction) and the pipeline still degrades to survivors.
- Guard setup is idempotent and fails CLOSED: setup failure aborts the review (exit 4) with an explicit override hint, never a silent open-network run.
- `--no-egress-guard` restores the previous behavior exactly (no `--network`, no proxy env).
- Key hygiene unchanged: secrets via env-name only, never argv; project mounts stay `:ro`.
- `make check` and `make test-e2e` stay green.

## Falsification

If over the next 10 reviews any reviewer fails ONLY when the guard is on (works with `--no-egress-guard`), the allowlist is starving a CLI dependency: add the missing host or, if the breakage is recurring and unfixable via the allowlist, revert. If a review ever proceeds open-network without `--no-egress-guard` being passed, the fail-closed gate is broken: revert immediately.

## Rollback

`git revert <commit>`; then `docker rm -f advanced-review-proxy && docker network rm advanced-review-egress` to clean up the infra.

---

## Result (filled in AFTER merge, append-only)

| Date | Sample size | Observed metric | Verdict |
|------|-------------|-----------------|---------|
