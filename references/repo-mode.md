# ABOUTME: Full-repository review mode (--repo) mechanics, file collection, chunking, and cost guidelines
# ABOUTME: Read when --repo flag is passed to advanced-review or when reviewing whole repositories

### Full-Repository Mode (`--repo`)

When `--repo [path]` is passed, the pipeline switches from diff-based to
full-repository review. Instead of generating a diff, it:

1. **Collects source files** under `path` (or the whole repo if no path).
   Skips `.git/`, `vendor/`, `node_modules/`, binaries, lockfiles.
2. **Generates a skeleton** of the codebase (class names, function signatures)
   via regex-based extraction. The skeleton is injected into every chunk's
   prompt so the LLM knows what exists in other files, reducing false positives.
3. **Chunks files by directory** (files in the same dir are grouped together).
   Chunks split at ~4000 lines to fit LLM context.
4. **LLM reviewers run per chunk** (Claude, Gemini, and DeepSeek, parallel per
   chunk, sequential across chunks). Uses `prompts/repo-review.md`.
5. **Validator checks file/line existence** (no diff relevance check).
6. **Cross-chunk deduplication** merges findings with same file + category +
   problem description, keeping the highest severity.
7. Steps 5-7 (Semgrep, SonarQube if `--sonarqube`, cross-check, merge) run
   as usual.

**Cost note:** `--repo` on a large codebase can be expensive. Use `--repo src/`
to scope to specific directories.
