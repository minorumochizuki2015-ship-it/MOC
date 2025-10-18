#!/usr/bin/env python3
"""
Check that all text files in the repository use LF line endings.
Exits with non-zero status if any CRLF (\r\n) is detected.

Exclusions:
- .git directory
- common binary files by extension
- coverage/html outputs
"""

import os
import sys

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
        if norm.startswith(d + "/") or ("/" + d + "/") in norm:
            return True
    return False


def main() -> int:
    repo_root = os.getcwd()
    bad_files = []
    for root, dirs, files in os.walk(repo_root):
        rel_root = os.path.relpath(root, repo_root).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        if rel_root and should_exclude(rel_root):
            # prune excluded dirs
            dirs[:] = []
            continue
        for f in files:
            rel = os.path.join(rel_root, f).replace("\\", "/") if rel_root else f
            if should_exclude(rel) or is_binary_path(rel):
                continue
            p = os.path.join(root, f)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
                # quick binary check
                if b"\x00" in data:
                    continue
                if b"\r\n" in data or b"\r" in data:
                    bad_files.append(rel)
            except Exception as e:
                print(f"[WARN] could not read {rel}: {e}")
    if bad_files:
        print("CRLF detected in the following files (LF is required):")
        for bf in bad_files:
            print(f" - {bf}")
        return 1
    print("OK: All checked files use LF line endings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
