#!/usr/bin/env python3
"""
Validate ORCH markdown/state structure and flags.
Checks presence of TASKS.md, APPROVALS.md, flags.md, and LOCKS/ dir.
Ensures flags.md contains required keys.
Enhanced with logical consistency checks for state/approval integration.
"""
import argparse
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

REQUIRED_FILES = [
    os.path.join("ORCH", "STATE", "TASKS.md"),
    os.path.join("ORCH", "STATE", "APPROVALS.md"),
    os.path.join("ORCH", "STATE", "flags.md"),
]

REQUIRED_DIRS = [
    os.path.join("ORCH", "STATE", "LOCKS"),
]


def parse_tasks_md(filepath: str) -> Dict[str, Dict[str, str]]:
    """Parse TASKS.md and return task records."""
    tasks = {}
    with open(filepath, "r", encoding="utf-8") as fh:
        content = fh.read()

    # Find table rows (skip header)
    lines = content.splitlines()
    in_table = False
    for line in lines:
        line = line.strip()
        if line.startswith("| task_id |"):
            in_table = True
            continue
        if in_table and line.startswith("|") and not line.startswith("|---"):
            parts = [p.strip() for p in line.split("|")[1:-1]]  # Remove empty first/last
            if (
                len(parts) >= 10
            ):  # task_id, title, state, owner, lock, lock_owner, lock_expires_at, due, artifact, notes
                task_id = parts[0]
                tasks[task_id] = {
                    "title": parts[1],
                    "state": parts[2],
                    "owner": parts[3],
                    "lock": parts[4],
                    "lock_owner": parts[5],
                    "lock_expires_at": parts[6],
                    "due": parts[7],
                    "artifact": parts[8],
                    "notes": parts[9],
                }
    return tasks


def parse_approvals_md(filepath: str) -> Dict[str, Dict[str, str]]:
    """Parse APPROVALS.md and return approval records."""
    approvals = {}
    with open(filepath, "r", encoding="utf-8") as fh:
        content = fh.read()

    # Find table rows (skip header)
    lines = content.splitlines()
    in_table = False
    for line in lines:
        line = line.strip()
        if line.startswith("| appr_id |"):
            in_table = True
            continue
        if in_table and line.startswith("|") and not line.startswith("|---"):
            parts = [p.strip() for p in line.split("|")[1:-1]]  # Remove empty first/last
            if (
                len(parts) >= 9
            ):  # appr_id, task_id, op, status, requested_by, approver, approver_role, ts_req, ts_dec, evidence
                appr_id = parts[0]
                approvals[appr_id] = {
                    "task_id": parts[1],
                    "op": parts[2],
                    "status": parts[3],
                    "requested_by": parts[4],
                    "approver": parts[5],
                    "approver_role": parts[6],
                    "ts_req": parts[7],
                    "ts_dec": parts[8],
                    "evidence": parts[9] if len(parts) > 9 else "",
                }
    return approvals


def validate_timestamp(ts_str: str) -> bool:
    """Validate ISO8601 timestamp format."""
    if ts_str == "-" or not ts_str:
        return True
    try:
        datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def is_windows_abs_path(path: str) -> bool:
    """Return True if path is a Windows absolute path (drive letter or UNC)."""
    return bool(re.match(r"^[A-Za-z]:\\", path)) or path.startswith("\\\\")


def check_logical_consistency(
    tasks: Dict[str, Dict[str, str]],
    approvals: Dict[str, Dict[str, str]],
    strict_abs_paths: bool = False,
) -> List[str]:
    """Check logical consistency between tasks and approvals."""
    errors = []

    # Group approvals by task_id
    task_approvals = {}
    for appr_id, approval in approvals.items():
        task_id = approval["task_id"]
        if task_id not in task_approvals:
            task_approvals[task_id] = []
        task_approvals[task_id].append((appr_id, approval))

    # Check each task
    for task_id, task in tasks.items():
        state = task["state"]

        # Check if DONE tasks have approved approvals
        if state == "DONE":
            if task_id in task_approvals:
                approved_count = sum(
                    1 for _, appr in task_approvals[task_id] if appr["status"] == "approved"
                )
                if approved_count == 0:
                    errors.append(f"Task {task_id} is DONE but has no approved approvals")
            # Note: DONE tasks without any approvals might be valid for simple operations

        # Check if tasks with pending approvals are not DONE
        if task_id in task_approvals:
            pending_count = sum(
                1 for _, appr in task_approvals[task_id] if appr["status"] == "pending"
            )
            if pending_count > 0 and state == "DONE":
                errors.append(f"Task {task_id} is DONE but has pending approvals")

    # Check approval constraints
    for appr_id, approval in approvals.items():
        # Self-approval check
        if approval["requested_by"] == approval["approver"] and approval["approver"] != "-":
            errors.append(
                f"Approval {appr_id}: self-approval detected ({approval['requested_by']} == {approval['approver']})"
            )

        # Role validation
        if approval["approver_role"] not in {"CMD", "AUDIT", "-"}:
            errors.append(
                f"Approval {appr_id}: invalid approver_role '{approval['approver_role']}'"
            )

        # Timestamp validation
        if not validate_timestamp(approval["ts_req"]):
            errors.append(f"Approval {appr_id}: invalid ts_req format '{approval['ts_req']}'")
        if not validate_timestamp(approval["ts_dec"]):
            errors.append(f"Approval {appr_id}: invalid ts_dec format '{approval['ts_dec']}'")

        # ts_dec >= ts_req check (when both are set)
        if approval["ts_req"] != "-" and approval["ts_dec"] != "-":
            try:
                req_dt = datetime.fromisoformat(approval["ts_req"].replace("Z", "+00:00"))
                dec_dt = datetime.fromisoformat(approval["ts_dec"].replace("Z", "+00:00"))
                if dec_dt < req_dt:
                    errors.append(
                        f"Approval {appr_id}: ts_dec ({approval['ts_dec']}) < ts_req ({approval['ts_req']})"
                    )
            except ValueError:
                pass  # Already caught by timestamp validation

        # Evidence path policy and existence check
        if approval["evidence"] and approval["evidence"] != "-":
            evidence_path = approval["evidence"]
            # Absolute path policy (Windows separators required)
            if strict_abs_paths:
                if not is_windows_abs_path(evidence_path):
                    errors.append(
                        f"Approval {appr_id}: evidence must be Windows absolute path (e.g., C:\\... or \\\\server\\...) — got '{evidence_path}'"
                    )
                if "/" in evidence_path:
                    errors.append(
                        f"Approval {appr_id}: evidence path must use Windows backslashes (\\) — got '{evidence_path}'"
                    )
            else:
                # Basic safety for non-strict mode
                if ".." in evidence_path:
                    errors.append(
                        f"Approval {appr_id}: unsafe evidence path contains '..' — '{evidence_path}'"
                    )

            # Existence check (only when path looks resolvable)
            try:
                if os.path.isabs(evidence_path) and not os.path.isfile(evidence_path):
                    errors.append(f"Approval {appr_id}: evidence file not found '{evidence_path}'")
            except Exception:
                # In case of malformed path, surface policy errors above and continue
                pass

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate ORCH markdown/state structure and flags."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict checks (e.g., evidence must be Windows absolute path with backslashes)",
    )
    args = parser.parse_args()
    missing = []
    for p in REQUIRED_FILES:
        if not os.path.isfile(p):
            missing.append(p)
    for d in REQUIRED_DIRS:
        if not os.path.isdir(d):
            missing.append(d + "/")
    if missing:
        print("[ERROR] Missing required files/dirs:")
        for m in missing:
            print(f" - {m}")
        return 1

    # Validate flags
    flags_path = os.path.join("ORCH", "STATE", "flags.md")
    with open(flags_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    keys = {}
    for ln in lines:
        if "=" in ln:
            k, v = ln.split("=", 1)
            keys[k.strip()] = v.strip()
    required_keys = {"AUTO_DECIDE": {"shadow", "on", "off"}, "FREEZE": {"on", "off"}}
    missing_keys = [k for k in required_keys if k not in keys]
    invalid_values = [
        (k, keys.get(k))
        for k, allowed in required_keys.items()
        if k in keys and keys[k] not in allowed
    ]

    if missing_keys or invalid_values:
        if missing_keys:
            print("[ERROR] Missing flags:")
            for k in missing_keys:
                print(f" - {k}")
        if invalid_values:
            print("[ERROR] Invalid flag values:")
            for k, v in invalid_values:
                print(f" - {k}={v} (allowed: {sorted(required_keys[k])})")
        return 1

    # Enhanced logical consistency checks
    try:
        tasks = parse_tasks_md(os.path.join("ORCH", "STATE", "TASKS.md"))
        approvals = parse_approvals_md(os.path.join("ORCH", "STATE", "APPROVALS.md"))

        consistency_errors = check_logical_consistency(
            tasks, approvals, strict_abs_paths=args.strict
        )
        if consistency_errors:
            print("[ERROR] Logical consistency violations:")
            for error in consistency_errors:
                print(f" - {error}")
            return 1

    except Exception as e:
        print(f"[ERROR] Failed to parse ORCH state files: {e}")
        return 1

    print("OK: ORCH state files, flags.md, and logical consistency are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
