---
name: advanced-review
description: "Thorough code review using two isolated reviewers (Claude + Gemini in Docker containers). Use when user says advanced review, thorough review, deep review, or /advanced-review. Runs both reviewers in parallel on the same diff, synthesizes findings. For quick pre-commit review use gemini-review instead."
compatibility: "Requires Docker running, claude-reviewer:latest and gemini-reviewer:latest images built."
---

# ABOUTME: Thorough code review using two isolated Docker reviewers (Claude + Gemini)
# ABOUTME: Same diff to both, zero config contamination, merged findings by severity

# Advanced Review (Isolated Dual Reviewer)

Both reviewers run in Docker with NO access to your `~/.claude/` config, memories,
or rules. They review the same diff independently, then findings are merged.

## Trigger

Activate when user says: "advanced review", "thorough review", "deep review", or `/advanced-review`.

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--all` | Review all uncommitted changes | staged only |
| `--branch [base]` | Review current branch vs base | main |
| `--prompt <name>` | Prompt template: `default` or `ci-style` | default |

## Execution Flow

### Step 1: Generate the diff

```bash
# Default: staged changes
DIFF=$(git diff --cached)

# With --all: all uncommitted
DIFF=$(git diff HEAD)

# With --branch [base]: branch diff
DIFF=$(git diff main...HEAD)
```

If the diff is empty, inform the user and suggest `git add`, `--all`, or `--branch`.

### Step 2: Build the review prompt

Load the template and compose the full prompt with the diff:

```bash
PROMPT_TEMPLATE=$(cat ~/.claude/skills/advanced-review/prompts/default.md)

PROMPT_FILE=$(mktemp)
cat > "$PROMPT_FILE" <<PROMPT_EOF
$PROMPT_TEMPLATE

## Code Changes to Review

\`\`\`diff
$DIFF
\`\`\`
PROMPT_EOF
```

The prompt file is identical for both reviewers.

### Step 3: Call both reviewers in parallel

Launch **two parallel Bash tool calls in a single message**.

Call 1 - Isolated Claude:
```bash
docker run --rm \
  -v claude-reviewer-auth:/home/node/.claude:ro \
  -v <PROJECT_ROOT>:/workspace:ro \
  claude-reviewer:latest \
  --print \
  --model opus \
  "$(cat <PROMPT_FILE>)"
```

Call 2 - Isolated Gemini:
```bash
docker run --rm \
  -e GEMINI_API_KEY="$(cat ~/.config/gemini-api-key)" \
  -v <PROJECT_ROOT>:/workspace:ro \
  gemini-reviewer:latest \
  -p "$(cat <PROMPT_FILE>)" \
  -m gemini-3.1-pro-preview \
  --sandbox false \
  2>&1 | grep -v "^\[WARN\] Skipping unreadable" | grep -v "^Warning: Could not read"
```

**Cleanup:**
```bash
rm -f "$PROMPT_FILE"
```

### Step 4: Merge and present findings

Deduplicate and merge findings from both reviewers into a single report:

#### Critical Issues
List issues flagged CRITICAL by either reviewer. If both flagged the same issue,
note "(both reviewers)" for stronger signal.

#### Warnings
Same merge logic. Deduplicate by file:line when both found the same issue.

#### Suggestions
Combine unique suggestions from both.

#### Agreement Summary

| Finding | Claude | Gemini | Action |
|---------|--------|--------|--------|
| ... | CRITICAL | CRITICAL | Must fix (strong signal) |
| ... | WARNING | not flagged | Review manually |
| ... | not flagged | WARNING | Review manually |

**Key insight:** Issues flagged by both reviewers independently are high-confidence
findings. Issues flagged by only one reviewer warrant a closer look but may be
false positives.

## When to Use

- Before opening a PR (thorough review)
- After significant refactors
- Security-sensitive changes
- When you want higher confidence than a single reviewer

## When NOT to Use

- Quick pre-commit check (use `gemini-review`)
- Trivial changes (typos, formatting)
- When Docker is not running

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "docker: command not found" | Start Docker Desktop |
| Image not found | Build: `cd docker/isolated-reviewer && docker build -t claude-reviewer:latest .` |
| Claude auth fails | Re-login: see `isolated-review.sh --login` |
| Gemini API errors | Check `~/.config/gemini-api-key` |
| Large diff timeout | Use `--branch` with specific file paths, or split the review |
