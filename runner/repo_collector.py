# ABOUTME: Collect source files, generate skeleton, and chunk by directory
# ABOUTME: Powers the --repo full-repository review mode

from __future__ import annotations

import re
from pathlib import Path


# ---------- Constants ----------

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "node_modules", "vendor", "third_party", "dist", "build",
    ".next", ".nuxt", "target", ".gradle", ".idea", ".vscode",
    ".scannerwork", ".sonar", ".qodana", "review-tests",
    "venv", ".venv", "env", ".env",
}

SKIP_SUFFIXES = {
    ".lock", ".sum", ".mod",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".pdf", ".doc", ".docx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll", ".exe",
    ".db", ".sqlite", ".sqlite3",
}

SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "uv.lock", "Pipfile.lock", "Gemfile.lock", "Cargo.lock",
    "go.sum", "poetry.lock", "composer.lock",
}

SOURCE_SUFFIXES = {
    ".py", ".go", ".js", ".ts", ".jsx", ".tsx",
    ".rb", ".rs", ".java", ".kt", ".swift",
    ".c", ".h", ".cpp", ".hpp", ".cs",
    ".sh", ".bash", ".zsh",
    ".sql", ".graphql", ".proto",
    ".yaml", ".yml", ".toml", ".json", ".xml",
    ".md", ".txt", ".rst",
    ".html", ".css", ".scss",
    ".dockerfile", ".tf", ".hcl",
}

# Regex patterns for skeleton extraction
_PYTHON_DEF = re.compile(r"^([ \t]*(?:def|class|async def)\s+\S+.*?):", re.MULTILINE)
_GO_DEF = re.compile(r"^((?:func|type)\s+\S+.*?)(?:\s*\{|$)", re.MULTILINE)
_JS_DEF = re.compile(
    r"^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+\S+.*?"
    r"|class\s+\S+.*?)", re.MULTILINE,
)
_RUBY_DEF = re.compile(r"^[ \t]*((?:def|class|module)\s+\S+.*?)$", re.MULTILINE)
_RUST_DEF = re.compile(
    r"^[ \t]*(?:pub\s+)?(?:fn|struct|enum|trait|impl)\s+\S+.*?$", re.MULTILINE,
)

_LANG_PATTERNS: dict[str, re.Pattern] = {
    ".py": _PYTHON_DEF,
    ".go": _GO_DEF,
    ".js": _JS_DEF,
    ".jsx": _JS_DEF,
    ".ts": _JS_DEF,
    ".tsx": _JS_DEF,
    ".rb": _RUBY_DEF,
    ".rs": _RUST_DEF,
}


# ---------- File collection ----------

def _is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:512]
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(root: Path) -> list[Path]:
    """Collect reviewable source files under root, respecting skip lists."""
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip by directory name
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        # Skip hidden files/dirs
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        # Skip by exact name
        if path.name in SKIP_NAMES:
            continue
        # Skip by suffix
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        # Skip Makefile-like names without suffix check
        if path.suffix == "" and path.name not in ("Makefile", "Dockerfile",
                                                     "Rakefile", "Justfile"):
            continue
        # Skip binary files
        if _is_binary(path):
            continue
        files.append(path)
    return files


# ---------- Skeleton generation ----------

def _extract_definitions(path: Path, content: str) -> list[str]:
    suffix = path.suffix.lower()
    pattern = _LANG_PATTERNS.get(suffix)
    if pattern is None:
        return []
    return [m.group(0).rstrip() for m in pattern.finditer(content)]


def generate_skeleton(files: list[Path]) -> str:
    """Generate a lightweight skeleton of the codebase (class/function signatures)."""
    sections: list[str] = []
    for path in files:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            continue
        defs = _extract_definitions(path, content)
        if not defs:
            continue
        header = f"# {path.name}"
        sections.append(header + "\n" + "\n".join(defs))
    return "\n\n".join(sections)


# ---------- Directory-based chunking ----------

def chunk_by_directory(files: list[Path],
                       max_lines: int = 4000) -> list[list[Path]]:
    """Group files by parent directory, splitting if a group exceeds max_lines."""
    # Group by parent
    groups: dict[Path, list[Path]] = {}
    for f in files:
        groups.setdefault(f.parent, []).append(f)

    chunks: list[list[Path]] = []
    for _dir, dir_files in sorted(groups.items()):
        current_chunk: list[Path] = []
        current_lines = 0
        for f in dir_files:
            try:
                line_count = f.read_text(errors="replace").count("\n") + 1
            except OSError:
                line_count = 0
            if current_chunk and current_lines + line_count > max_lines:
                chunks.append(current_chunk)
                current_chunk = []
                current_lines = 0
            current_chunk.append(f)
            current_lines += line_count
        if current_chunk:
            chunks.append(current_chunk)
    return chunks
