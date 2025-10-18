#!/usr/bin/env python3
"""
Generate an accountability (root cause) markdown card that bundles:
- Minimal diff summary (files changed, insertions, deletions)
- Unified diff of changes
- UI-Audit report pointers (Lighthouse, Linkinator, Playwright)
- Rollback guidance

Outputs to ORCH/patches/YYYY-MM/diff_card.md by default.

Intended to be called from CI after tests. Safe to run locally.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Tuple


def run(cmd: list[str], cwd: str | None = None) -> Tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = proc.communicate()
    return proc.returncode, out.strip(), err.strip()


def get_git_summary() -> str:
    # Try to get shortstat between HEAD and working tree
    # Fallback to last commit shortstat
    code, out, _ = run(["git", "diff", "--shortstat"])
    if code == 0 and out:
        return out
    code, out, _ = run(["git", "show", "--shortstat", "--oneline"])
    return out if code == 0 else ""


def get_unified_diff() -> str:
    # unified diff with 3 lines of context
    code, out, _ = run(["git", "diff", "--unified=3"])
    if code == 0 and out:
        return out
    # If no working diff, show last commit diff
    code, out, _ = run(["git", "show", "-U3"])
    return out if code == 0 else ""


def detect_branch() -> str:
    code, out, _ = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return out if code == 0 else "unknown"


def main() -> int:
    # Resolve output directory
    now = datetime.now()
    default_dir = Path("ORCH") / "patches" / now.strftime("%Y-%m")

    out_dir = Path(os.environ.get("ACCOUNTABILITY_OUT_DIR", default_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / "diff_card.md"

    branch = detect_branch()
    summary = get_git_summary()
    unified = get_unified_diff()

    # Front-matter fields
    code, sha_in, _ = run(["git", "rev-parse", "origin/main"])
    if code != 0:
        sha_in = "unknown"
    code, sha_out, _ = run(["git", "rev-parse", "HEAD"])
    if code != 0:
        sha_out = "unknown"
    task_id = os.environ.get("TASK_ID", "ui-audit-p0")

    # UI-Audit pointers: these paths should match CI artifacts and local reports
    ui_artifacts = [
        "artifacts/ui_audit/",  # CI uploaded artifacts
        "observability/ui/report/",  # local reports (if any)
        "playwright-report/",  # Playwright HTML report
        "artifacts/preview/",  # preview captures
    ]

    content = f"""
---
task_id: {task_id}
sha_in: {sha_in}
sha_out: {sha_out}
metrics:
  lighthouse: pending_CI
  lcp: pending_CI
  cls: pending_CI
  linkinator_404: pending_CI
  playwright_tests: pending_CI
rollback_cmd: "git revert {sha_out}"
---

Accountability Card (Root Cause & Rollback)

- Branch: {branch}
- Timestamp: {now.isoformat()}

Minimal Diff Summary
--------------------
{summary or 'No changes detected.'}

Unified Diff
------------
```
{unified or 'No diff available.'}
```

UI-Audit Pointers
-----------------
- Lighthouse & LCP/CLS reports: artifacts/ui_audit/ or observability/ui/report/
- Linkinator results: artifacts/ui_audit/links/ (if split) or artifacts/ui_audit/
- Playwright artifacts: screenshots/, traces/ and playwright-report/

Rollback Guidance
-----------------
- If this change was committed but not pushed:
  - git restore . && git clean -fd
- If this change was pushed in a single commit:
  - git revert <commit-sha>
- If multiple commits:
  - git revert --no-commit <oldest>^..<newest> && git commit -m "Revert range"

Notes
-----
- Ensure CI multi-layered guards (Playwright/Lighthouse/Linkinator) are green.
- Ensure Design-UI/Web-Verify approval before merging UI-affecting changes.
""".strip()

    out_file.write_text(content, encoding="utf-8")
    print(f"[gen_root_cause_card] wrote: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
