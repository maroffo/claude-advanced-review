# ABOUTME: Session log 2026-07-07, SonarQube opt-in + 360 review + full fix wave (PR #7)
# ABOUTME: Fallback copy; mirror to vault "claude-advanced-review - Log" when Obsidian is running

## 2026-07-07: SonarQube opt-in + 360 review + fix completo (PR #7)

- SonarQube reso opt-in (`--sonarqube`); review a 360 gradi con 4 reviewer paralleli (architecture, security, test, dx): 25 finding, di cui 1 Critical.
- Fixati 25/25 in due ondate (5 software-engineer paralleli a scope disgiunti, poi follow-up sui 2 rinviati):
  - sandbox network-less per i test proposti dagli LLM (chiude il percorso RCE sul host, CWE-94/95);
  - egress guard per i container reviewer: rete Docker interna + proxy squid con allowlist di host esatti, fail-closed, verificato live (3/3 reviewer OK, CONNECT esterni rifiutati);
  - de-dup `pipeline()`/`pipeline_repo()` con fix del bug di scoping SonarQube in repo mode;
  - hardening: bind loopback + password random per SonarQube, allowlist SSRF nel validator, MODIFY solo al rialzo nel merger;
  - prompt via stdin (ARG_MAX), docs riallineate al codice.
- Test: da 179 a 310 (288 unit + 22 e2e, con e2e veri che chiamano la pipeline reale).
- PR #7 mergiata su main; skill attiva via symlink `~/.claude/skills/advanced-review`.
- Follow-up in issue #8: chiusura dei 3 change contract dopo ~10 run reali, `--sandbox false` di gemini, `--prompt` ignorato in repo mode.
- Report completo: `quality_reports/reviews/2026-07-07_360-review.md`.

### Decisioni chiave (con il perché)

- SonarQube opt-in invece di opt-out: il default puniva ogni macchina fresca (pull + boot 60-120s + porta 9000) per uno step non richiesto.
- Egress guard fail-closed: un guard che degrada a rete aperta in silenzio non protegge nulla; l'override è esplicito (`--no-egress-guard`).
- Allowlist a host esatti, niente wildcard: `.googleapis.com` avrebbe riaperto `storage.googleapis.com` come canale di esfiltrazione.
- `sandbox_unavailable` come stato che sopravvive: un test non eseguibile non è né provato né falso; scartarlo in silenzio avrebbe nascosto bug reali.
