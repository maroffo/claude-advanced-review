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


# ---------- Scanner ----------

def run_scan(project_root: Path, project_key: str, token: str,
             sonar_url: str = SONAR_URL, timeout: int = 300) -> bool:
    """Run sonar-scanner-cli against the project. Returns True on success."""
    scan_id = uuid.uuid4().hex[:8]
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-e", f"SONAR_HOST_URL={sonar_url}",
        "-e", f"SONAR_TOKEN={token}",
        "-v", f"{project_root.resolve()}:/usr/src:ro",
        SCANNER_IMAGE,
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.projectName={project_key}",
        "-Dsonar.sources=/usr/src",
        "-Dsonar.qualitygate.wait=true",
        f"-Dsonar.working.dir=/tmp/.scannerwork-{scan_id}",
    ]
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

def run_sonarqube(project_root: Path, timeout: int = 300) -> list[dict]:
    """Full SonarQube flow: ensure server, scan, fetch findings."""
    if not ensure_running():
        print("sonarqube: server not available, skipping", file=sys.stderr)
        return []

    token = _ensure_token()

    # Best-effort cleanup of old projects
    cleanup_old_projects(token)

    project_key = generate_project_key(project_root)

    print(f"sonarqube: scanning as {project_key}...", file=sys.stderr)
    if not run_scan(project_root, project_key, token, timeout=timeout):
        print("sonarqube: scan failed, skipping", file=sys.stderr)
        return []

    raw_issues = fetch_issues(project_key, token)
    findings = parse_output(raw_issues)
    print(f"sonarqube: {len(findings)} findings", file=sys.stderr)
    return findings
