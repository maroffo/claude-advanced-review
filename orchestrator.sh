#!/usr/bin/env bash
# ABOUTME: Thin wrapper that execs orchestrator.py via uv in the repo venv
# ABOUTME: Keeps the SKILL.md entrypoint name stable even though logic is Python

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer the repo's uv-managed venv; fall back to system python if missing.
if command -v uv >/dev/null 2>&1; then
  exec uv run --project "$SCRIPT_DIR" python "$SCRIPT_DIR/orchestrator.py" "$@"
else
  exec python3 "$SCRIPT_DIR/orchestrator.py" "$@"
fi
