#!/usr/bin/env python3
"""
validate_orch_md.py --strict

Purpose:
  Validate MD files adhere to Windows absolute path policy and formatting rules.

Checks:
  - Evidence and referenced file paths must be Windows absolute paths:
      * Starts with 'C:\\' (or other drive letters) OR UNC path starting with '\\\\'
      * Uses only backslashes '\\' as separators
      * Must not contain forward slashes '/'
  - Specific sections in APPROVALS.md, WORK_TRACKING.md, CHECKLISTS must include
    evidence paths in Windows absolute format where applicable.

Exit codes:
  0: All checks passed
  1: Violations found (in --strict mode)

Usage:
  python scripts/ops/validate_orch_md.py --strict
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

WINDOWS_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:\\")
WINDOWS_UNC_PATH_RE = re.compile(r"^\\\\")
FORWARD_SLASH_RE = re.compile(r"/")


def is_windows_absolute_path(s: str) -> bool:
    return bool(WINDOWS_DRIVE_PATH_RE.match(s) or WINDOWS_UNC_PATH_RE.match(s))


def find_paths(text: str) -> List[str]:
    """Extract candidate Windows absolute paths from text.
    - Drive paths: C:\\Users\\... (must have at least one segment after drive)
    - UNC paths: \\\\server\\share\\... (must have server and share segments)
    Strips common trailing punctuation from extracted tokens.
    """
    drive_pat = r"[A-Za-z]:\\[^\s\|`\"'<>\)\]\}]+"
    unc_pat = r"\\\\[A-Za-z0-9._$-]+\\[^\s\|`\"'<>\)\]\}]+"
    candidates = re.findall(rf"(?:{drive_pat}|{unc_pat})", text)
    cleaned: List[str] = []
    for c in candidates:
        cleaned.append(c.rstrip("`.,;:)]）。」、・"))
    return cleaned


def validate_paths(paths: List[str]) -> List[Tuple[str, str]]:
    """Return list of (path, reason) for violations"""
    violations: List[Tuple[str, str]] = []
    for p in paths:
        if not is_windows_absolute_path(p):
            violations.append((p, "not_windows_absolute"))
            continue
        is_drive = bool(WINDOWS_DRIVE_PATH_RE.match(p))
        is_unc = bool(WINDOWS_UNC_PATH_RE.match(p))
        # colon must be only after drive letter (index 1) for drive paths; UNC paths have no colon
        if is_drive:
            colon_pos = p.find(":")
            if colon_pos != 1:
                violations.append((p, "colon_invalid_position"))
                continue
        if FORWARD_SLASH_RE.search(p):
            violations.append((p, "contains_forward_slash"))
            continue
        # Disallow common invalid characters (excluding ':' at position 1 and backslashes)
        if re.search(r"[<>\|?*]", p):
            violations.append((p, "contains_invalid_chars"))
            continue
    return violations


def validate_approvals_md(path: Path) -> List[Tuple[str, str]]:
    violations: List[Tuple[str, str]] = []
    text = path.read_text(encoding="utf-8")
    # Check table lines: last column should be evidence path when present
    for line in text.splitlines():
        if line.strip().startswith("|") and line.count("|") >= 2:
            cols = [c.strip() for c in line.strip().split("|")]
            # Skip header separator lines
            if set(cols) == {""}:
                continue
            # Heuristic: evidence column is the last non-empty cell
            evidence = None
            for c in reversed(cols):
                if c:
                    evidence = c
                    break
            if evidence and (
                "\\" in evidence or evidence.startswith("C:") or evidence.startswith("\\\\")
            ):
                v = validate_paths([evidence])
                violations.extend(v)
    # Also scan entire text for any path tokens
    violations.extend(validate_paths(find_paths(text)))
    return violations


def validate_generic_md(path: Path) -> List[Tuple[str, str]]:
    text = path.read_text(encoding="utf-8")
    return validate_paths(find_paths(text))


def main() -> int:
    strict = "--strict" in sys.argv
    repo_root = Path.cwd()

    targets = [
        repo_root / "ORCH" / "STATE" / "APPROVALS.md",
        repo_root / "WORK_TRACKING.md",
        repo_root / "ORCH" / "STATE" / "CHECKLISTS" / "phase4_execution_checklist.md",
    ]

    all_violations: List[Tuple[str, str, Path]] = []
    for t in targets:
        if not t.exists():
            all_violations.append((str(t), "missing_file", t))
            continue
        if t.name == "APPROVALS.md":
            v = validate_approvals_md(t)
        else:
            v = validate_generic_md(t)
        for p, reason in v:
            all_violations.append((p, reason, t))

    if all_violations:
        print("[MD Validation] Violations found:")
        for p, reason, file in all_violations:
            print(f" - {reason}: {p} (in {file})")
        if strict:
            print("[MD Validation] STRICT mode: failing due to violations.")
            return 1
    else:
        print("[MD Validation] All checks passed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
