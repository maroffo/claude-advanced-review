# ABOUTME: Runs SonarQube via persistent Docker container as a ground-truth reviewer
# ABOUTME: Manages container lifecycle, scanner execution, and API result fetching

from __future__ import annotations

import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
import requests.exceptions


# ---------- Constants ----------

SONARQUBE_IMAGE = "sonarqube:community"
SCANNER_IMAGE = "sonarsource/sonar-scanner-cli"
CONTAINER_NAME = "sonarqube-review"
SONAR_PORT = 9000
SONAR_URL = f"http://localhost:{SONAR_PORT}"

CACHE_DIR = Path.home() / ".cache" / "claude-advanced-review"
TOKEN_CACHE_PATH = CACHE_DIR / "sonar-token"

DEFAULT_ADMIN_PASS = "admin"
NEW_ADMIN_PASS = "reviewpass!2026"


# ---------- Severity / category mapping ----------

_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MAJOR": "WARNING",
    "MINOR": "INFO",
    "INFO": "INFO",
}

_TYPE_TO_CATEGORY = {
    "BUG": "bug",
    "VULNERABILITY": "security",
    "CODE_SMELL": "quality",
    "SECURITY_HOTSPOT": "security",
}

_SAFE_KEY_RE = re.compile(r"[^A-Za-z0-9._-]")


# ---------- Helpers ----------

def _git_cmd(project_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(project_root)] + list(args),
        capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip()


def _container_exists() -> bool:
    proc = subprocess.run(
        ["docker", "inspect", CONTAINER_NAME],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def _container_running() -> bool:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
        capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip() == "true"


# ---------- Container lifecycle ----------

def ensure_running(timeout: int = 180) -> bool:
    """Ensure the sonarqube-review container is running and healthy."""
    if _container_running():
        return _wait_for_ready(timeout)

    if _container_exists():
        print("sonarqube: starting stopped container...", file=sys.stderr)
        subprocess.run(
            ["docker", "start", CONTAINER_NAME],
            capture_output=True, check=False,
        )
    else:
        print("sonarqube: creating container (first time, ~60-120s)...",
              file=sys.stderr)
        subprocess.run(
            ["docker", "run", "-d",
             "--name", CONTAINER_NAME,
             "-p", f"{SONAR_PORT}:9000",
             "-e", "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true",
             "-v", "sonarqube_review_data:/opt/sonarqube/data",
             "-v", "sonarqube_review_extensions:/opt/sonarqube/extensions",
             SONARQUBE_IMAGE],
            capture_output=True, check=False,
        )

    return _wait_for_ready(timeout)


def _wait_for_ready(timeout: int = 180) -> bool:
    """Poll /api/system/status until UP or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(
                f"{SONAR_URL}/api/system/status", timeout=5,
            )
            if resp.status_code == 200:
                status = resp.json().get("status")
                if status == "UP":
                    return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)
    print("sonarqube: timeout waiting for server", file=sys.stderr)
    return False


def _ensure_token() -> str:
    """Load cached token or generate a new one."""
    if TOKEN_CACHE_PATH.exists():
        token = TOKEN_CACHE_PATH.read_text().strip()
        if _token_valid(token):
            return token

    # First-time setup: change default password
    _change_default_password()

    # Try new password first, fall back to default if change failed
    admin_pass = _working_admin_password()

    # Generate new token
    resp = requests.post(
        f"{SONAR_URL}/api/user_tokens/generate",
        auth=("admin", admin_pass),
        data={"name": f"cli-review-{int(time.time())}"},
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["token"]

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_CACHE_PATH.write_text(token)
    return token


def _working_admin_password() -> str:
    """Determine which admin password works (new or default)."""
    for pw in (NEW_ADMIN_PASS, DEFAULT_ADMIN_PASS):
        try:
            resp = requests.get(
                f"{SONAR_URL}/api/authentication/validate",
                auth=("admin", pw),
                timeout=5,
            )
            if resp.status_code == 200 and resp.json().get("valid", False):
                return pw
        except requests.exceptions.RequestException:
            continue
    return NEW_ADMIN_PASS  # fallback


def _token_valid(token: str) -> bool:
    try:
        resp = requests.get(
            f"{SONAR_URL}/api/authentication/validate",
            auth=(token, ""),
            timeout=5,
        )
        return resp.status_code == 200 and resp.json().get("valid", False)
    except requests.exceptions.RequestException:
        return False


def _change_default_password() -> None:
    try:
        requests.post(
            f"{SONAR_URL}/api/users/change_password",
            auth=("admin", DEFAULT_ADMIN_PASS),
            data={
                "login": "admin",
                "previousPassword": DEFAULT_ADMIN_PASS,
                "password": NEW_ADMIN_PASS,
            },
            timeout=10,
        )
    except requests.exceptions.RequestException:
        pass  # Already changed or unreachable


# ---------- Project key ----------

def generate_project_key(project_root: Path) -> str:
    """Generate a unique project key from repo name, branch, and short SHA."""
    repo_name = _git_cmd(project_root, "rev-parse", "--show-toplevel")
    repo_name = Path(repo_name).name if repo_name else "unknown"
    branch = _git_cmd(project_root, "rev-parse", "--abbrev-ref", "HEAD") or "detached"
    short_sha = _git_cmd(project_root, "rev-parse", "--short", "HEAD") or "0000000"

    raw = f"{repo_name}_{branch}_{short_sha}"
    return _SAFE_KEY_RE.sub("-", raw)


# ---------- Diff scoping ----------

def _changed_paths(project_root: Path, diff_mode: str,
                   base_ref: str) -> list[str]:
    """Return changed files in the diff as repo-root-relative paths.

    Mirrors orchestrator.generate_diff modes:
    - "staged"  -> `git diff --cached --name-only`
    - "all"     -> `git diff HEAD --name-only`
    - "branch"  -> `git diff ${base}...HEAD --name-only`

    Empty list = either no diff or no recognised mode; the caller falls back
    to a full-repo scan rather than scoping to nothing.
    """
    if diff_mode == "staged":
        args = ["diff", "--cached", "--name-only"]
    elif diff_mode == "all":
        args = ["diff", "HEAD", "--name-only"]
    elif diff_mode == "branch":
        args = ["diff", f"{base_ref}...HEAD", "--name-only"]
    else:
        return []
    raw = _git_cmd(project_root, *args)
    if not raw:
        return []
    # `git diff --name-only` may emit deleted files; SonarQube can't scan
    # those, so filter to paths that still exist on disk.
    return [p for p in raw.splitlines()
            if p and (project_root / p).exists()]


def _find_tsconfigs(project_root: Path, sources: list[str]) -> list[str]:
    """For each source dir, walk up to the repo root and grab the nearest
    `tsconfig.json`. Returns repo-root-relative paths.

    Why this exists: SonarJS's TypeScript analysis discovers `tsconfig.json`
    via a project-wide filesystem walk that ignores `sonar.exclusions`. On
    a monorepo with git worktrees (e.g., `.claude/worktrees/agent-*/`) it
    finds dozens of stale tsconfigs and tries to load all of them, which
    reliably crashes the JS bridge with `WebSocket connection closed
    abnormally`. Passing `sonar.typescript.tsconfigPaths` explicitly limits
    discovery to just the configs relevant to the changed sources.

    Falls back to the root `tsconfig.json` if nothing is found higher than
    the source dir; returns an empty list only if there is no tsconfig at
    all (in which case we let SonarJS auto-discover, since the failure
    mode at that point is the same with or without the override).
    """
    found = set()
    repo_root = project_root.resolve()
    for src in sources:
        current = (project_root / src).resolve()
        while True:
            candidate = current / "tsconfig.json"
            if candidate.exists():
                found.add(str(candidate.relative_to(repo_root)))
                break
            if current == repo_root:
                break
            current = current.parent
    return sorted(found)


def _minimal_covering_dirs(paths: list[str]) -> list[str]:
    """Reduce a list of file paths to the minimal set of parent dirs.

    Example:
        ["lib/analytics-events/src/index.ts",
         "lib/analytics-events/test/foo.test.ts"]
        -> ["lib/analytics-events/src", "lib/analytics-events/test"]

    Files at repo root (parent == "") force a full-repo scan: there is no
    meaningful "parent dir" shorter than the repo root, and SonarQube's
    `sonar.sources` cannot mix the root with subdirs without scanning
    everything twice. Returning [] signals "fall back to full scan" to the
    caller. For everything else, drop subdirs of any other listed dir: if
    both `lib/foo` and `lib/foo/test` are present, `lib/foo` suffices.
    """
    if not paths:
        return []
    dirs = set()
    for p in paths:
        parent = str(Path(p).parent)
        if parent in ("", "."):
            # Any root-level change collapses scoping back to the full repo.
            return []
        dirs.add(parent)
    sorted_dirs = sorted(dirs, key=len)
    minimal: list[str] = []
    for d in sorted_dirs:
        if not any(d == m or d.startswith(m + "/") for m in minimal):
            minimal.append(d)
    return minimal


# ---------- Scanner ----------

def run_scan(project_root: Path, project_key: str, token: str,
             sonar_url: str = SONAR_URL, timeout: int = 1800,
             sources: list[str] | None = None) -> bool:
    """Run sonar-scanner-cli against the project. Returns True on success.

    Default timeout is 1800s (30 min) to accommodate large monorepos where
    the cold scan can comfortably exceed the previous 5-minute ceiling.
    Pass `sources` to scope the scan to specific repo-root-relative
    directories (e.g., the changed dirs of a PR diff) - omit for a full
    project scan.
    """
    scan_id = uuid.uuid4().hex[:8]
    if sources:
        # Translate repo-root-relative paths into mount-relative paths so
        # SonarQube sees only the changed subtree. Comma-separated list per
        # the scanner CLI contract.
        scoped = ",".join(f"/usr/src/{s}" if s != "." else "/usr/src"
                          for s in sources)
        sources_arg = f"-Dsonar.sources={scoped}"
    else:
        sources_arg = "-Dsonar.sources=/usr/src"
    # Even when `sonar.sources` is scoped, SonarJS does a project-wide
    # tsconfig discovery for cross-file type resolution. Without these
    # exclusions the scanner pulls in stale `.claude/worktrees/` (Agent
    # isolation residue), every `node_modules/`, and any compiled `dist/`,
    # which inflates the analysis 10-100x and reliably crashes the JS bridge
    # with `WebSocket connection closed abnormally` on monorepo-scale repos.
    exclusions_arg = (
        "-Dsonar.exclusions="
        "**/.claude/**,**/node_modules/**,**/dist/**,**/build/**,"
        "**/.next/**,**/.turbo/**,**/coverage/**"
    )
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-e", f"SONAR_HOST_URL={sonar_url}",
        "-e", f"SONAR_TOKEN={token}",
        "-v", f"{project_root.resolve()}:/usr/src:ro",
        SCANNER_IMAGE,
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.projectName={project_key}",
        sources_arg,
        exclusions_arg,
        "-Dsonar.qualitygate.wait=true",
        f"-Dsonar.working.dir=/tmp/.scannerwork-{scan_id}",
    ]
    # When scoped, pin the tsconfig list to the configs nearest each
    # source dir. SonarJS ignores `sonar.exclusions` for tsconfig discovery,
    # so without this override it still crawls into stale worktree
    # tsconfigs. With no scope this is a no-op (auto-discovery applies).
    if sources:
        tsconfigs = _find_tsconfigs(project_root, sources)
        if tsconfigs:
            mounted = ",".join(f"/usr/src/{tc}" for tc in tsconfigs)
            cmd.append(f"-Dsonar.typescript.tsconfigPaths={mounted}")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            print(f"sonarqube: scanner exit {proc.returncode}\n"
                  f"{proc.stderr[-500:]}", file=sys.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"sonarqube: scanner timeout after {timeout}s", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("sonarqube: docker not found", file=sys.stderr)
        return False


# ---------- API: fetch issues ----------

def fetch_issues(project_key: str, token: str,
                 sonar_url: str = SONAR_URL,
                 page_size: int = 500) -> list[dict]:
    """Fetch all open issues for a project via the SonarQube API."""
    all_issues: list[dict] = []
    page = 1
    while True:
        try:
            resp = requests.get(
                f"{sonar_url}/api/issues/search",
                auth=(token, ""),
                params={
                    "componentKeys": project_key,
                    "resolved": "false",
                    "ps": page_size,
                    "p": page,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.exceptions.RequestException, Exception) as exc:
            print(f"sonarqube: API error fetching issues: {exc}",
                  file=sys.stderr)
            return []

        issues = data.get("issues", [])
        all_issues.extend(issues)

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return all_issues


# ---------- Result mapping ----------

def map_result(issue: dict) -> dict:
    """Map a SonarQube API issue to the unified finding schema."""
    component = issue.get("component", "")
    # Strip project prefix: "project-key:path/to/file" -> "path/to/file"
    file_path = component.split(":", 1)[1] if ":" in component else ""

    severity = _SEVERITY_MAP.get(
        str(issue.get("severity", "")).upper(), "INFO",
    )
    category = _TYPE_TO_CATEGORY.get(
        str(issue.get("type", "")).upper(), "quality",
    )
    rule = issue.get("rule", "")
    line = issue.get("line", 0)

    return {
        "id": f"sonarqube-{rule.replace(':', '-')}-{file_path}:{line}",
        "category": category,
        "severity": severity,
        "file": file_path,
        "line": line,
        "problem": issue.get("message", ""),
        "suggestion": f"See SonarQube rule {rule} for remediation.",
        "evidence": {
            "rule_id": rule,
            "effort": issue.get("effort", ""),
        },
        "source": "sonarqube",
        "validator_status": "passed",
        "validator_reasons": [],
    }


def parse_output(issues: list[dict]) -> list[dict]:
    """Map a list of raw SonarQube issues to the unified finding schema."""
    return [map_result(issue) for issue in issues]


# ---------- Cleanup ----------

def cleanup_old_projects(token: str, sonar_url: str = SONAR_URL,
                         max_age_hours: int = 24) -> None:
    """Delete SonarQube projects older than max_age_hours (best-effort)."""
    try:
        resp = requests.get(
            f"{sonar_url}/api/projects/search",
            auth=(token, ""),
            params={"ps": 500},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.exceptions.RequestException, Exception):
        return

    now = datetime.now(timezone.utc)
    for comp in data.get("components", []):
        last_analysis = comp.get("lastAnalysisDate", "")
        if not last_analysis:
            continue
        try:
            # SonarQube uses ISO 8601 with timezone
            analyzed_at = datetime.fromisoformat(last_analysis)
            age_hours = (now - analyzed_at).total_seconds() / 3600
            if age_hours > max_age_hours:
                requests.post(
                    f"{sonar_url}/api/projects/delete",
                    auth=(token, ""),
                    data={"project": comp["key"]},
                    timeout=10,
                )
        except (ValueError, KeyError):
            continue


# ---------- Top-level entry point ----------

def run_sonarqube(project_root: Path, timeout: int = 1800,
                  diff_mode: str | None = None,
                  base_ref: str | None = None) -> list[dict]:
    """Full SonarQube flow: ensure server, scan, fetch findings.

    When `diff_mode` (and optionally `base_ref`) are passed, the scan is
    scoped to the changed dirs of the diff - on a large monorepo this
    drops scan time from O(repo) to O(diff). If no changed files are
    found (or the mode is unrecognised) the scan falls back to the whole
    project, matching the previous behaviour.
    """
    if not ensure_running():
        print("sonarqube: server not available, skipping", file=sys.stderr)
        return []

    token = _ensure_token()

    # Best-effort cleanup of old projects
    cleanup_old_projects(token)

    project_key = generate_project_key(project_root)

    sources: list[str] | None = None
    if diff_mode is not None:
        changed = _changed_paths(project_root, diff_mode,
                                 base_ref or "main")
        sources = _minimal_covering_dirs(changed) or None

    if sources:
        print(f"sonarqube: scanning as {project_key} "
              f"(scoped to {len(sources)} dir(s): {', '.join(sources)})...",
              file=sys.stderr)
    else:
        print(f"sonarqube: scanning as {project_key}...", file=sys.stderr)
    if not run_scan(project_root, project_key, token, timeout=timeout,
                    sources=sources):
        print("sonarqube: scan failed, skipping", file=sys.stderr)
        return []

    raw_issues = fetch_issues(project_key, token)
    findings = parse_output(raw_issues)
    print(f"sonarqube: {len(findings)} findings", file=sys.stderr)
    return findings
