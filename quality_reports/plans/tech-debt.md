# ABOUTME: Tech debt discovered but not addressed, one line each, pointing back to origin
# ABOUTME: Review before starting new feature work in this repo

# Tech Debt

- Repo mode hardcodes `prompts/repo-review.md` and never consults `--prompt`; deliberate for now (diff-mode-only option) but undocumented in code. Origin: 360 review 2026-07-07, follow-up note from pipeline de-dup.
- Gemini reviewer still runs `--sandbox false` inside the egress-guarded network; the guard bounds exfiltration but the CLI sandbox itself stays off. Origin: 360 review 2026-07-07, finding 9 residue after the egress guard landed.
