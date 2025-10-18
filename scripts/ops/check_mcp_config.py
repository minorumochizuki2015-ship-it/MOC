#!/usr/bin/env python3
"""
MCP config consistency checker (Windows-focused path policy)

Checks the following across .trae/mcp_servers.* files:
- Path normalization: forward slashes only ('/'), no backslashes ('\\')
- Safety: no '..' segments, no drive letters (e.g., 'C:/')
- Absolute style: paths must start with '/'
- Positional roots only: deny '--root' flag usage in command/args
- Root count consistency: JSON vs YAML must have the same number of roots (strict mode)

Exit code:
- 0: All checks passed
- 1: Violations detected (details printed)

Usage:
  python scripts/ops/check_mcp_config.py --strict
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple, cast

RE_DRIVE = re.compile(r"^[A-Za-z]:/")
RE_BACKSLASH = re.compile(r"\\")
RE_DOTDOT = re.compile(r"(^|/)\.\.(/|$)")


def _is_path_violation(path: str) -> List[str]:
    violations: List[str] = []
    if RE_BACKSLASH.search(path):
        violations.append("contains backslash \\")
    if RE_DOTDOT.search(path):
        violations.append("contains '..' segment")
    if RE_DRIVE.match(path):
        violations.append("contains drive letter (e.g., C:/)")
    if not path.startswith("/"):
        violations.append("does not start with '/' (absolute-style required)")
    return violations


def _deny_flag_args_present(args: List[str]) -> bool:
    return any(a.strip() == "--root" for a in args)


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return cast(Dict[str, Any], json.load(f))


def _load_yaml(path: str) -> Dict[str, Any]:
    import yaml  # PyYAML

    with open(path, "r", encoding="utf-8") as f:
        return cast(Dict[str, Any], yaml.safe_load(f))


def _extract_roots_from_json(doc: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (roots, full_args) from .trae/mcp_servers*.json structure.

    Expected structure:
      {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", <roots...>]}}}
    """
    roots: List[str] = []
    args: List[str] = []
    try:
        fs = doc["mcpServers"]["filesystem"]
        args = list(fs.get("args", []))
        # Assume roots start after the package specifier
        # Find index of '@modelcontextprotocol/server-filesystem'
        try:
            pkg_idx = args.index("@modelcontextprotocol/server-filesystem")
            roots = [a for a in args[pkg_idx + 1 :] if isinstance(a, str)]
        except ValueError:
            # Not present; treat any string args after the first two as roots conservatively
            roots = [a for a in args[2:] if isinstance(a, str)]
    except Exception:
        pass
    return roots, args


def _extract_roots_from_yaml(doc: Dict[str, Any]) -> Tuple[List[str], str]:
    """Return (roots_list, start_command) from .trae/mcp_servers.yaml"""
    roots: List[str] = []
    start_cmd: str = ""
    try:
        servers = doc.get("servers", {})
        fs = servers.get("Filesystem", {})
        roots = list(fs.get("roots", []) or [])
        start = fs.get("start", {})
        start_cmd = str(start.get("command", ""))
    except Exception:
        pass
    return roots, start_cmd


def _extract_roots_from_start_command(start_cmd: str) -> List[str]:
    """Parse positional roots from a single-line start command string.
    Example:
      npx @modelcontextprotocol/server-filesystem "/observability" "/artifacts"
    """
    # naive parse: split by whitespace while respecting quotes
    import shlex

    try:
        parts = shlex.split(start_cmd)
    except Exception:
        parts = start_cmd.split()

    # everything after package token is considered positional roots
    roots: List[str] = []
    try:
        pkg_idx = parts.index("@modelcontextprotocol/server-filesystem")
        for p in parts[pkg_idx + 1 :]:
            if p.startswith("--"):
                # flags are not allowed for roots
                continue
            roots.append(p)
    except ValueError:
        # If not found, take trailing quoted strings as roots conservatively
        trailing = [
            p for p in parts if p.startswith("/") or p.startswith("\\") or RE_DRIVE.match(p)
        ]
        roots.extend(trailing)
    return roots


def check(strict: bool = False) -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    trae_dir = os.path.join(repo_root, ".trae")
    json_main = os.path.join(trae_dir, "mcp_servers.json")
    json_min = os.path.join(trae_dir, "mcp_servers_min.json")
    yaml_file = os.path.join(trae_dir, "mcp_servers.yaml")

    violations: List[str] = []

    # JSON main
    if os.path.exists(json_main):
        docj = _load_json(json_main)
        roots_j, args_j = _extract_roots_from_json(docj)
        if _deny_flag_args_present(args_j):
            violations.append(f"{json_main}: args contain '--root' flag (positional roots only)")
        for r in roots_j:
            for v in _is_path_violation(r):
                violations.append(f"{json_main}: root '{r}' {v}")
    else:
        violations.append(f"Missing file: {json_main}")

    # JSON min
    if os.path.exists(json_min):
        docm = _load_json(json_min)
        roots_m, args_m = _extract_roots_from_json(docm)
        if _deny_flag_args_present(args_m):
            violations.append(f"{json_min}: args contain '--root' flag (positional roots only)")
        for r in roots_m:
            for v in _is_path_violation(r):
                violations.append(f"{json_min}: root '{r}' {v}")
        if strict:
            # In strict mode, min config must be single-root
            if len(roots_m) != 1:
                violations.append(
                    f"{json_min}: expected single root in strict mode, found {len(roots_m)}"
                )
    else:
        violations.append(f"Missing file: {json_min}")

    # YAML
    if os.path.exists(yaml_file):
        docy = _load_yaml(yaml_file)
        roots_y, start_cmd = _extract_roots_from_yaml(docy)
        # roots list violations
        for r in roots_y:
            for v in _is_path_violation(r):
                violations.append(f"{yaml_file}: roots entry '{r}' {v}")
        # start.command violations
        if start_cmd:
            parts_roots = _extract_roots_from_start_command(start_cmd)
            # deny flags
            if "--root" in start_cmd:
                violations.append(
                    f"{yaml_file}: start.command contains '--root' flag (positional roots only)"
                )
            for r in parts_roots:
                for v in _is_path_violation(r):
                    violations.append(f"{yaml_file}: start.command root '{r}' {v}")
            if strict:
                # Require consistency between declared roots and start.command roots
                if len(parts_roots) != len(roots_y):
                    violations.append(
                        f"{yaml_file}: start.command roots count ({len(parts_roots)}) != roots list count ({len(roots_y)}) in strict mode"
                    )
    else:
        violations.append(f"Missing file: {yaml_file}")

    # Cross-file root count consistency (strict only): JSON main vs YAML
    if strict and os.path.exists(json_main) and os.path.exists(yaml_file):
        roots_j, _ = _extract_roots_from_json(_load_json(json_main))
        roots_y, _ = _extract_roots_from_yaml(_load_yaml(yaml_file))
        if len(roots_j) != len(roots_y):
            violations.append(
                f"Cross-file mismatch: {os.path.basename(json_main)} roots ({len(roots_j)}) != {os.path.basename(yaml_file)} roots ({len(roots_y)})"
            )

    if violations:
        print("MCP config consistency check FAILED:")
        for v in violations:
            print(f" - {v}")
        return 1
    else:
        print("MCP config consistency check OK")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Check MCP config path/style consistency")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict cross-file and single-root checks",
    )
    args = parser.parse_args()
    sys.exit(check(strict=args.strict))


if __name__ == "__main__":
    main()
