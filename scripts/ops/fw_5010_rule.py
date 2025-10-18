"""
Firewall rule operations for port 5010 without PowerShell.

- Implements: ensure, enable, disable, show, remove
- Uses `netsh advfirewall` on Windows (admin privileges required)
- Mirrors behavior of scripts/ops/fw_5010_rule.ps1 but in Python

Usage examples:

  python scripts/ops/fw_5010_rule.py --action ensure
  python scripts/ops/fw_5010_rule.py --action enable
  python scripts/ops/fw_5010_rule.py --action disable
  python scripts/ops/fw_5010_rule.py --action show
  python scripts/ops/fw_5010_rule.py --action remove

Notes:
- Must be run in an elevated (Administrator) terminal on Windows.
- On non-Windows platforms, this script performs a no-op and exits with code 0.
"""

from __future__ import annotations

import argparse
import platform
import shlex
import subprocess
import sys
from typing import List, Tuple


DISPLAY_NAME_DEFAULT = "ORCH-Next Dev 5010 Inbound"
PORT_DEFAULT = 5010
PROFILE_DEFAULT = "Private"
REMOTE_IP_DEFAULT = "LocalSubnet"


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_admin_windows() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        # If detection fails, assume not admin to be safe
        return False


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", f"cmd failed: {e}"


def netsh_cmd(*parts: str) -> List[str]:
    """Build a netsh command list suitable for subprocess without PowerShell.

    Example:
      netsh advfirewall firewall add rule name="X" protocol=TCP dir=in localport=5010 action=allow profile=private remoteip=localsubnet enable=no
    """
    return ["netsh", *parts]


def show_rule(name: str) -> Tuple[int, str]:
    rc, out, err = run_cmd(netsh_cmd("advfirewall", "firewall", "show", "rule", f"name={name}"))
    # netsh prints localized output; we just return raw text
    text = out or err
    return rc, text


def rule_exists(name: str) -> bool:
    rc, text = show_rule(name)
    if rc != 0:
        return False
    # Heuristic: when rule exists, output contains the name; when not, contains "No rules match the specified criteria." (English) or localized message
    lowered = (text or "").lower()
    if not lowered.strip():
        return False
    # Try multiple heuristics
    return (name.lower() in lowered) or ("no rules match" not in lowered)


def ensure_rule(name: str, port: int, profile: str, remote_ip: str) -> None:
    if rule_exists(name):
        print(f"[FW] Rule '{name}' already exists")
        return
    # Add rule disabled by default
    cmd = netsh_cmd(
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={name}",
        "protocol=TCP",
        "dir=in",
        f"localport={port}",
        "action=allow",
        f"profile={profile}",
        f"remoteip={remote_ip}",
        "enable=no",
    )
    rc, out, err = run_cmd(cmd)
    if rc == 0:
        print(f"[FW] Created rule '{name}' (Port={port}, Profile={profile}, Remote={remote_ip}, Enabled=False)")
    else:
        sys.stderr.write(err or out or "Unknown error\n")
        sys.exit(rc or 1)


def set_rule_enabled(name: str, enabled: bool) -> None:
    cmd = netsh_cmd(
        "advfirewall",
        "firewall",
        "set",
        "rule",
        f"name={name}",
        "new",
        f"enable={'yes' if enabled else 'no'}",
    )
    rc, out, err = run_cmd(cmd)
    if rc == 0:
        print(f"[FW] {'Enabled' if enabled else 'Disabled'} '{name}'")
    else:
        sys.stderr.write(err or out or "Unknown error\n")
        sys.exit(rc or 1)


def remove_rule(name: str) -> None:
    cmd = netsh_cmd(
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={name}",
    )
    rc, out, err = run_cmd(cmd)
    if rc == 0:
        print(f"[FW] Removed '{name}'")
    else:
        # If rule doesn't exist, netsh returns non-zero; don't fail hard for remove
        msg = err or out or "Unknown error"
        if "No rules match" in msg:
            print("[FW] Skip remove: rule not found")
        else:
            sys.stderr.write(msg + "\n")
            sys.exit(rc or 1)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Firewall rule ops for 5010 without PowerShell")
    parser.add_argument("--action", "-a", choices=["ensure", "create", "enable", "disable", "show", "remove"], default="ensure")
    parser.add_argument("--name", default=DISPLAY_NAME_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--profile", default=PROFILE_DEFAULT)
    parser.add_argument("--remote", default=REMOTE_IP_DEFAULT)
    args = parser.parse_args(argv)

    if not is_windows():
        print("[FW] Non-Windows platform detected; no-op (rule ops are Windows-specific)")
        return 0

    if not is_admin_windows():
        # 'show' は参照系のため昇格なしでも許可（netshのshowは非昇格でも概ね実行可能）
        if args.action != "show":
            print("[FW] Access denied: Administrator privileges are required for firewall operations.")
            print("      Please re-run this command in an elevated (Run as administrator) terminal.")
            return 1

    action = args.action
    name = args.name
    port = args.port
    profile = args.profile
    remote = args.remote

    if action in ("ensure", "create"):
        ensure_rule(name, port, profile, remote)
        if action == "create":
            print("[FW] Done (create)")
            return 0

    if action == "enable":
        set_rule_enabled(name, True)
    elif action == "disable":
        set_rule_enabled(name, False)
    elif action == "show":
        rc, text = show_rule(name)
        print(text)
        return rc
    elif action == "remove":
        remove_rule(name)

    print(f"[FW] Done ({action})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())