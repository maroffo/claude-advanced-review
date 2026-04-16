---
name: advanced-review
description: "Thorough code review with verifiable claims. Dual isolated reviewers (Claude + Gemini in Docker), deterministic validator, Semgrep and SonarQube as ground-truth reviewers, hostile cross-check round. Every finding must carry evidence: CWE id, executable red-green test, Big-O derivation, grep-able convention reference, or explicit principle. Use when user says advanced review, thorough review, deep review, or /advanced-review. For quick pre-commit review use gemini-review instead."
compatibility: "Requires Docker running; claude-reviewer:latest, gemini-reviewer:latest, semgrep/semgrep:latest, sonarqube:community, sonarsource/sonar-scanner-cli images available; Python 3.10+ on host for the validator."
---

# ABOUTME: Advanced code review with verifiable claims, SAST ground truth, and hostile cross-check
# ABOUTME: Kills hallucinations before they reach the human reviewer

# Advanced Review (Verifiable Claims Edition)

Two LLM reviewers run in isolated Docker containers, a deterministic validator
filters unprovable claims, Semgrep and SonarQube provide zero-hallucination
ground truth, and a hostile cross-check round tries to demolish what survives.
Humans only see findings that cleared every gate.

## Trigger

Activate when the user says: "advanced review", "thorough review", "deep review",
or `/advanced-review`.

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--all` | Review all uncommitted changes | staged only |
| `--branch [base]` | Review current branch vs base | `main` |
| `--prompt <name>` | Prompt template: `default` or `ci-style` | `default` |
| `--no-semgrep` | Skip the Semgrep third reviewer | off (Semgrep runs) |
| `--no-sonarqube` | Skip the SonarQube reviewer | off (SonarQube runs) |
| `--no-preflight` | Skip the pre-flight make check gate | off (preflight runs) |
| `--no-cross-check` | Skip round 2 (faster, less rigorous) | off (cross-check runs) |

## Execution Flow

The orchestrator script at `orchestrator.sh` runs these steps in order. Each
step feeds the next; any step producing zero findings short-circuits the rest
cleanly.

### Step 0 — Pre-flight gate (make check)

If the project has a `make check` target, the orchestrator runs it before
anything else. If it fails, the pipeline stops immediately with the raw
output. No diff, no LLM calls, no money spent on broken code.

Detection uses `make -n check` (dry-run): exit 0 or 1 means the target
exists, exit 2 means it doesn't.

If no `make check` target is found, the step is skipped with a suggestion:
"Run `/project-checks` to scaffold one."

Skip with `--no-preflight`.

### Step 1 — Generate the diff

```bash
# Default: staged only
DIFF=$(git diff --cached)
# --all: everything uncommitted
DIFF=$(git diff HEAD)
# --branch [base]: branch diff
DIFF=$(git diff "${BASE:-main}"...HEAD)
```

If the diff is empty, stop and tell the user to `git add`, pass `--all`, or
pass `--branch`.

### Step 2 — Round 1 reviewers (parallel)

Both reviewers receive the same prompt and diff. Output is JSON following the
schema in `prompts/default.md`: each finding carries `category`, `severity`,
`file:line`, `problem`, `suggestion`, and an `evidence` object whose required
fields depend on the category:

| Category | Evidence required |
|----------|-------------------|
| `security` | `cwe_id`, `cwe_url` |
| `bug` | `test` (code) + `test_language` + `test_target_file` (optional `test_modifies_existing`) |
| `performance` | `benchmark` (code) OR `big_o` (derivation) |
| `convention` | `convention_file` + `convention_line_or_grep` |
| `architecture` | `principle` + `application` (specific to the diff) |
| `nitpick` | none, auto-demoted to `INFO` |

Launch in parallel (single message, two Bash calls):

```bash
docker run --rm \
  -v claude-reviewer-auth:/home/node/.claude:ro \
  -v "$PROJECT_ROOT:/workspace:ro" \
  claude-reviewer:latest --print --model opus \
  "$(cat "$PROMPT_FILE")"
```

```bash
docker run --rm \
  -e GEMINI_API_KEY="$(cat ~/.config/gemini-api-key)" \
  -v "$PROJECT_ROOT:/workspace:ro" \
  gemini-reviewer:latest -p "$(cat "$PROMPT_FILE")" \
  -m gemini-3.1-pro-preview --sandbox false
```

### Step 3 — Deterministic validator

`validator/validator.py` reads the merged round-1 findings and runs five checks:

1. **CWE existence**: `cwe_id` must exist in the MITRE CWE list (downloaded
   on first run, cached at `~/.cache/claude-advanced-review/cwe.json` with 30d
   TTL).
2. **URL reachability**: `cwe_url` must return HTTP 200 (HEAD, 5s timeout).
3. **Test syntax**: `evidence.test` must parse as valid code in its declared
   language (Python `ast`, JS/TS via regex-level check, Go via `go/parser`,
   etc.).
4. **Relevance**: the test must reference at least one symbol or file path
   from the diff (AST scan of imports/calls).
5. **REFUTE citation**: for round-2 REFUTE-BY-EXPLANATION verdicts, cited
   `file:line` must exist inside the diff hunks (grep-style check).

Findings that fail their required checks are **dropped** (logged for
transparency). Findings move forward with `validator_status: "passed"`.

### Step 4 — External test runner

`runner/test-runner.sh` takes surviving `bug` findings and executes their
proposed tests against the current codebase. The runner detects project
toolchain by glob:

| Marker file | Runner |
|-------------|--------|
| `pyproject.toml` / `setup.py` | `pytest` |
| `package.json` | `npm test` / `yarn test` / `pnpm test` (detected from lockfile) |
| `go.mod` | `go test ./...` targeting the affected package |
| `Cargo.toml` | `cargo test` |
| `Gemfile` | `rspec` / `rails test` |

**Rule:** the test must FAIL on the current code. If it passes, the bug is not
demonstrated and the finding is dropped. Surviving tests are saved to
`review-tests/<finding-id>.{py,ts,go,...}` for the IMPLEMENT step of the
verification protocol (red-green contract for the engineer doing the fix).

**Modify-existing preference:** when the reviewer sets
`evidence.test_modifies_existing: true`, the runner applies the test as a
patch to the referenced existing test file rather than creating a new one,
inheriting imports and fixtures. Hard fallback to new file if the referenced
file doesn't exist.

### Step 5 — Semgrep (third reviewer, ground truth)

`runner/semgrep-runner.sh` runs `semgrep/semgrep:latest` with `--config=auto`
on the project. Output is parsed into the same finding schema used by the LLM
reviewers. Semgrep findings are tagged `source: "semgrep"` and **skip the
validator**: they are ground truth by construction.

Semgrep's role:
- Findings neither LLM caught: added to the final report directly.
- LLM findings overlapping with Semgrep: severity bumped to `HIGH_CONFIDENCE`.
- LLM security findings NOT corroborated by Semgrep: flagged for extra
  scrutiny in round 2.

Skip with `--no-semgrep`.

### Step 5b — SonarQube (ground truth, persistent container)

`runner/sonarqube_runner.py` manages a persistent `sonarqube-review` Docker
container running SonarQube Community Build. The container starts on first use
(~60-120s cold start) and stays running for subsequent reviews (~10-30s per
scan).

**Flow:**

1. `ensure_running()`: check/start the `sonarqube-review` container, wait for
   health check (`/api/system/status`).
2. `generate_project_key()`: unique key from `{repo}_{branch}_{short_sha}` to
   isolate scans across branches/projects.
3. `run_scan()`: `sonarsource/sonar-scanner-cli` via Docker with
   `-Dsonar.qualitygate.wait=true` (blocks until analysis completes) and
   `-Dsonar.working.dir=/tmp/.scannerwork-<uuid>` (no repo pollution).
4. `fetch_issues()`: `GET /api/issues/search` with pagination.
5. `cleanup_old_projects()`: best-effort deletion of project keys >24h old.

**Mapping:**

| SonarQube severity | Pipeline severity |
|--------------------|-------------------|
| BLOCKER | CRITICAL |
| CRITICAL | CRITICAL |
| MAJOR | WARNING |
| MINOR | INFO |
| INFO | INFO |

| SonarQube type | Pipeline category |
|----------------|-------------------|
| BUG | bug |
| VULNERABILITY | security |
| CODE_SMELL | quality |
| SECURITY_HOTSPOT | security |

SonarQube findings are tagged `source: "sonarqube"` and are **ground truth**
(bypass the validator). CRITICAL/WARNING findings enter the cross-check round 2
where LLMs can dispute contextual relevance but not structural existence.

Skip with `--no-sonarqube`.

### Step 6 — Round 2 cross-check (hostile defense)

Only `CRITICAL` and `WARNING` findings enter round 2. Each LLM reviewer
receives the other's findings and is prompted (see `prompts/cross-check.md`)
to **prove them false**. Default stance is adversarial; ACCEPT is the fallback
when they cannot debunk.

Four verdicts:

| Verdict | Meaning | Requires |
|---------|---------|----------|
| `ACCEPT` | Could not debunk | (nothing) |
| `MODIFY` | Claim valid but severity or fix is wrong | corrected version |
| `REJECT-WITH-COUNTER-EVIDENCE` | Claim is wrong, here's the hard proof | own evidence (test that passes on current code, CWE disputing the mapping, etc.) |
| `REFUTE-BY-EXPLANATION` | Claim is wrong, here's why in prose | `file:line` citations inside the diff that contradict the claim (validated in step 3) |

Launched in parallel as two fresh stateless Docker calls (same image and auth
as round 1, different prompt).

### Step 7 — Merge

| Round 1 flag | Cross-check outcome | Action |
|--------------|---------------------|--------|
| flagged | both ACCEPT | `HIGH_CONFIDENCE`, surface prominently |
| flagged | one ACCEPT, one MODIFY | Present both versions, note the divergence |
| flagged | any REJECT-WITH-COUNTER-EVIDENCE | `DISPUTED`, human decides |
| flagged | any REFUTE-BY-EXPLANATION (validated) | `DISPUTED`, human decides |
| flagged | REFUTE with invalid citation | Original claim wins (REFUTE discarded) |
| (semgrep only) | n/a | `GROUND_TRUTH`, added directly |
| (sonarqube, CRITICAL/WARNING) | cross-checked | confidence tag from verdicts |
| (sonarqube, INFO) | n/a | `GROUND_TRUTH`, added directly |

The final report is markdown with sections by severity, each finding showing:
- Source reviewer(s) and verdict chain
- `file:line`, problem, suggested fix
- Linked evidence (CWE link, saved test path, benchmark excerpt)
- Confidence tag (`HIGH_CONFIDENCE` / `MODIFIED` / `DISPUTED` / `GROUND_TRUTH`)

`review-tests/` is preserved for the engineer doing the fix.

## When to Use

- Before opening a PR (thorough review)
- After significant refactors
- Security-sensitive changes
- When the cost of a missed issue is higher than the cost of running the full
  pipeline (roughly 2x LLM cost of v1 plus the Semgrep container)

## When NOT to Use

- Quick pre-commit check (use `gemini-review`)
- Trivial changes (typos, formatting)
- When Docker is not running
- When you only need a style review (Semgrep and convention checks are cheaper
  standalone)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `docker: command not found` | Start Docker Desktop |
| `claude-reviewer` image missing | Build: `cd claude-forge/docker/isolated-reviewer && docker build -t claude-reviewer:latest .` |
| `gemini-reviewer` image missing | Build: `cd claude-forge/docker/isolated-gemini && docker build -t gemini-reviewer:latest .` |
| `semgrep/semgrep` image missing | `docker pull semgrep/semgrep:latest` |
| `sonarqube:community` image missing | `docker pull sonarqube:community` |
| `sonarsource/sonar-scanner-cli` image missing | `docker pull sonarsource/sonar-scanner-cli` |
| SonarQube slow first run | Normal: ~60-120s cold start. Container stays running for subsequent reviews |
| SonarQube container stopped | Runner auto-restarts it. Or: `docker start sonarqube-review` |
| SonarQube port 9000 conflict | Stop conflicting service or change port in `sonarqube_runner.py` |
| SonarQube token expired | Delete `~/.cache/claude-advanced-review/sonar-token` and rerun |
| Claude auth fails | Re-login: `docker run -it --rm -v claude-reviewer-auth:/home/node/.claude --entrypoint bash claude-reviewer:latest -c "claude login"` |
| Gemini API errors | Check `~/.config/gemini-api-key` exists and is valid |
| Validator: "CWE list not found" | Delete `~/.cache/claude-advanced-review/cwe.json` and rerun (forces refresh) |
| Test runner: "toolchain not detected" | Pass `--no-test-runner` to skip, or add a marker file the runner recognizes |
| Large diff timeout | Split by file path with `--branch` scoping, or review commit-by-commit |
| Findings survive everything but feel wrong | Check the `review-tests/` output, a surviving red-green test is usually the strongest signal |
