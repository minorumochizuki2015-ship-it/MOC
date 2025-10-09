#!/usr/bin/env python3
"""
Normalize line endings to LF (\n) across the repository for text files.
Skips common binary and generated/cache directories.

Usage:
  python scripts/ops/normalize_eol.py
"""
import os

BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".rar",
    ".7z",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
}

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "observability/coverage/html",
    "backups",
    "data",
    "ORCH/LOGS",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
}


def is_binary_path(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in BINARY_EXTS


def should_exclude(path: str) -> bool:
    norm = path.replace("\\", "/")
    for d in EXCLUDE_DIRS:
        if norm.startswith(d + "/") or ("/" + d + "/") in norm or norm == d:
            return True
    return False


def normalize_file(p: str) -> bool:
    # Returns True if modified
    try:
        with open(p, "rb") as fh:
            data = fh.read()
        if b"\r" not in data:
            return False
        # Convert CRLF and CR to LF
        new = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if new != data:
            with open(p, "wb") as fh:
                fh.write(new)
            return True
        return False
    except Exception:
        return False


def main() -> int:
    repo_root = os.getcwd()
    changed = []
    for root, dirs, files in os.walk(repo_root):
        rel_root = os.path.relpath(root, repo_root).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        if rel_root and should_exclude(rel_root):
            dirs[:] = []
            continue
        for f in files:
            rel = os.path.join(rel_root, f).replace("\\", "/") if rel_root else f
            if should_exclude(rel) or is_binary_path(rel):
                continue
            p = os.path.join(root, f)
            if normalize_file(p):
                changed.append(rel)
    if changed:
        print("Normalized line endings to LF in:")
        for c in changed:
            print(f" - {c}")
    else:
        print("No files required normalization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
