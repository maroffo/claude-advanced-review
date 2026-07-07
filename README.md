<!-- ABOUTME: Advanced code review skill with verifiable claims to reduce LLM hallucinations -->
<!-- ABOUTME: Three isolated reviewers + deterministic validator + Semgrep + hostile cross-check -->

# claude-advanced-review

Thorough code review that makes LLM reviewers put up or shut up. Every finding
must carry verifiable evidence; unprovable claims are dropped before the human
ever sees them.

## What this solves

Running three LLM reviewers in parallel (Claude, Gemini, DeepSeek, three
different labs) catches more issues than one, but they all still hallucinate:
fake CWE ids, bugs that aren't bugs, references to lines that don't exist. The
standard workflow makes the human the validator.

This skill shifts the burden onto the reviewers:

- **Evidence per finding category** — security claims require a real CWE id
  and reachable URL, bug claims require an executable red-green test,
  convention claims require a grep-able reference to the project's own rules.
- **Deterministic validator** — Python script verifies evidence *shape*
  (CWE in MITRE list, URL returns 200, test parses) before any human sees it.
- **External test runner** — proposed tests are executed against the current
  code; tests that don't currently fail are dropped (claim not demonstrated).
- **Semgrep as ground-truth reviewer** — zero-hallucination ground truth.
  Calibrates the LLM findings and surfaces issues neither LLM caught.
- **SonarQube as opt-in ground truth** — a second SAST reviewer, enabled with
  `--sonarqube`; a persistent container that adds structural bug, vulnerability,
  and code-smell findings.
- **Full-repo mode** — `--repo [path]` reviews the whole codebase (or a scoped
  subtree) instead of a diff, chunking files by directory.
- **Pre-flight make-check gate** — if the project has a `make check` target it
  runs first; a failing build stops the pipeline before any LLM money is spent.
- **Hostile cross-check** — a second round where each reviewer tries to
  demolish the other's findings. Accept only what survives.
- **REFUTE-BY-EXPLANATION** — genuine skepticism isn't penalized: a reviewer
  can reject a claim with a text rebuttal citing specific diff lines. Any
  disagreement surfaces to the human as DISPUTED.

## Status

Work in progress. See `SKILL.md` for the skill loaded into Claude Code.

## Repo layout

```
.
├── SKILL.md                    # Loaded by Claude Code as the user skill
├── orchestrator.py             # Pipeline logic: preflight → diff/collect → round1 → validate → tests → semgrep → sonarqube (opt-in) → round2 → merge
├── orchestrator.sh             # Thin uv-run wrapper around orchestrator.py
├── prompts/
│   ├── default.md              # Round 1 reviewer prompt (evidence required)
│   ├── cross-check.md          # Round 2 hostile defense prompt
│   ├── ci-style.md             # Legacy prompt kept for --prompt ci-style
│   └── repo-review.md          # Full-repo mode prompt (--repo)
├── validator/
│   └── validator.py            # CWE/URL/syntax/relevance/refute checks
├── runner/
│   ├── preflight_runner.py     # Pre-flight make check gate
│   ├── repo_collector.py       # Full-repo mode: collect files, build skeleton, chunk
│   ├── test_runner.py          # Run proposed bug tests, drop non-failing
│   ├── semgrep_runner.py       # Semgrep ground-truth reviewer (Docker)
│   └── sonarqube_runner.py     # SonarQube ground-truth reviewer (opt-in, --sonarqube)
├── merge/
│   └── merger.py               # Merge findings, resolve confidence from verdicts
├── Makefile                    # make check / test / test-e2e targets
├── pyproject.toml              # uv project and dependencies
└── tests/
    ├── e2e/                    # pytest orchestrator E2E
    └── fixture-repo/           # Toy repo with known issues for regression
```

## Install

Symlink into your Claude Code skills directory:

```sh
ln -s $(pwd) ~/.claude/skills/advanced-review
```

## Usage

Inside Claude Code:

```
/advanced-review
/advanced-review --all
/advanced-review --branch main
/advanced-review --sonarqube
/advanced-review --repo src/
```

## Dependencies

- `uv` (hard dependency: `orchestrator.sh` and the Makefile invoke it). Run
  `uv sync` once to materialize the venv.
- Docker (for isolated reviewers and Semgrep)
- `claude-reviewer:latest`, `gemini-reviewer:latest`, and `deepseek-reviewer:latest` images (see upstream)
- `~/.config/gemini-api-key` and `~/.config/deepseek-api-key`
- Python 3.10+ (validator)
- SonarQube images (`sonarqube:community`, `sonarsource/sonar-scanner-cli`),
  only needed when running with `--sonarqube`

## License

Private. Not for redistribution.
