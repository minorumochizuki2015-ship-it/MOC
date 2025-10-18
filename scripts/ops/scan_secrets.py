#!/usr/bin/env python3
"""
Simple secret scanner.
Searches repository for common secret patterns. Exits non-zero if any are found.
"""

import os
import re
import sys

PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "Generic SECRET",
        re.compile(r"SECRET[_-]?KEY\s*[:=]\s*['\"]?[A-Za-z0-9/_+=-]{12,}"),
    ),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("Private Key", re.compile(r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----")),
]

# Allowlist substrings to reduce false positives in examples/tests
SAFE_LINE_SUBSTRINGS = {"REDACTED", "CHANGEME", "jwt-ci", "webhook-ci"}

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "observability/coverage",
    "__pycache__",
    "backups",
    "data/logs",
}


def should_exclude(path: str) -> bool:
    norm = path.replace("\\", "/")
    for d in EXCLUDE_DIRS:
        if norm.startswith(d + "/") or ("/" + d + "/") in norm:
            return True
    return False


def main() -> int:
    repo_root = os.getcwd()
    findings = []
    for root, dirs, files in os.walk(repo_root):
        rel_root = os.path.relpath(root, repo_root).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        if rel_root and should_exclude(rel_root):
            dirs[:] = []
            continue
        for f in files:
            rel = os.path.join(rel_root, f).replace("\\", "/") if rel_root else f
            if should_exclude(rel):
                continue
            p = os.path.join(root, f)
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, start=1):
                        for name, rx in PATTERNS:
                            if rx.search(line):
                                # skip lines with safe placeholders
                                if any(s in line for s in SAFE_LINE_SUBSTRINGS):
                                    continue
                                findings.append((name, rel, i))
            except Exception as e:
                print(f"[WARN] could not read {rel}: {e}")
    if findings:
        print("[ERROR] Potential secrets detected:")
        for name, rel, i in findings:
            print(f" - {name} in {rel}:{i}")
        return 1
    print("OK: No secrets detected by basic patterns.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
