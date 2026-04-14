<!-- ABOUTME: Advanced code review skill with verifiable claims to reduce LLM hallucinations -->
<!-- ABOUTME: Dual isolated reviewers + deterministic validator + Semgrep + hostile cross-check -->

# claude-advanced-review

Thorough code review that makes LLM reviewers put up or shut up. Every finding
must carry verifiable evidence; unprovable claims are dropped before the human
ever sees them.

## What this solves

Running two LLM reviewers in parallel catches more issues than one, but both
still hallucinate: fake CWE ids, bugs that aren't bugs, references to lines
that don't exist. The standard workflow makes the human the validator.

This skill shifts the burden onto the reviewers:

- **Evidence per finding category** — security claims require a real CWE id
  and reachable URL, bug claims require an executable red-green test,
  convention claims require a grep-able reference to the project's own rules.
- **Deterministic validator** — Python script verifies evidence *shape*
  (CWE in MITRE list, URL returns 200, test parses) before any human sees it.
- **External test runner** — proposed tests are executed against the current
  code; tests that don't currently fail are dropped (claim not demonstrated).
- **Semgrep as third reviewer** — zero-hallucination ground truth. Calibrates
  the LLM findings and surfaces issues neither LLM caught.
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
├── prompts/
│   ├── default.md              # Round 1 reviewer prompt (evidence required)
│   ├── cross-check.md          # Round 2 hostile defense prompt
│   └── ci-style.md             # Legacy prompt kept for --prompt ci-style
├── validator/
│   └── validator.py            # CWE/URL/syntax/relevance/refute checks
├── runner/
│   ├── test-runner.sh          # Run proposed tests, drop non-failing
│   └── semgrep-runner.sh       # Third reviewer: Semgrep in Docker
├── orchestrator.sh             # Glue: round1 → validate → tests → semgrep → round2 → merge
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
```

## Dependencies

- Docker (for isolated reviewers and Semgrep)
- `claude-reviewer:latest` and `gemini-reviewer:latest` images (see upstream)
- `~/.config/gemini-api-key`
- Python 3.10+ (validator)

## License

Private. Not for redistribution.
