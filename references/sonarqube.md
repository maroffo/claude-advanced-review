# ABOUTME: SonarQube opt-in ground-truth reviewer setup, execution flow, and severity mapping
# ABOUTME: Read when --sonarqube is passed to advanced-review or when configuring SonarQube

### Step 5b — SonarQube (opt-in ground truth, persistent container)

**Opt-in: runs only with `--sonarqube`.** Skipped by default because it
requires a persistent server container on port 9000 and two extra Docker
images; on a machine without them the step would spend minutes pulling and
booting SonarQube before contributing anything.

When enabled, `runner/sonarqube_runner.py` manages a persistent
`sonarqube-review` Docker container running SonarQube Community Build. The
container starts on first use (~60-120s cold start) and stays running for
subsequent reviews (~10-30s per scan).

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
