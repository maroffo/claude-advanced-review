# ABOUTME: Tech debt discovered but not addressed, one line each, pointing back to origin
# ABOUTME: Review before starting new feature work in this repo

# Tech Debt

- Reviewer containers (Claude/Gemini/DeepSeek) run with open network, live creds volume / API keys in env, and Gemini `--sandbox false` while consuming untrusted diffs; fix needs a real egress policy (allow only each model's API endpoint), not a flag. Origin: 360 review 2026-07-07, finding 9 (Major). See `quality_reports/reviews/2026-07-07_360-review.md`.
- Round-1/round-2 prompts (up to 4000-line chunks) are passed as a single docker argv element in `run_claude`/`run_gemini`/`run_deepseek`; ARG_MAX risk on large chunks. Fix: pipe via stdin or mounted file. Origin: 360 review 2026-07-07, finding 19 (Minor).
- Repo mode hardcodes `prompts/repo-review.md` and never consults `--prompt`; deliberate for now (diff-mode-only option) but undocumented in code. Origin: 360 review 2026-07-07, follow-up note from pipeline de-dup.
