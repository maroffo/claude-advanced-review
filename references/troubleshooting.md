# ABOUTME: Troubleshooting guide for advanced-review Docker, API keys, SonarQube, and validator errors
# ABOUTME: Read when advanced-review fails or produces errors during execution

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
| Egress guard setup failed (exit 4) | Check Docker is running and `ubuntu/squid:latest` can be pulled; stale proxy: `docker rm -f advanced-review-proxy` and rerun. Last resort: `--no-egress-guard` (open network) |
| Reviewer FAILED only with guard on | A CLI dependency needs a host missing from `EGRESS_ALLOWED_HOSTS` in `orchestrator.py`; add it there and rerun (the proxy is recreated automatically on allowlist change) |
| Gemini API errors | Check `~/.config/gemini-api-key` exists and is valid |
| Validator: "CWE list not found" | Delete `~/.cache/claude-advanced-review/cwe.json` and rerun (forces refresh) |
| Test runner: "toolchain not detected" | Pass `--no-test-runner` to skip, or add a marker file the runner recognizes |
| Large diff timeout | Split by file path with `--branch` scoping, or review commit-by-commit |
| Findings survive everything but feel wrong | Check the `review-tests/` output, a surviving red-green test is usually the strongest signal |
