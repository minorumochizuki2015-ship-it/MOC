"""
Resource Guard (non-blocking)

Checks disk free space and optionally fails when below threshold.
Environment variables:
  - RESOURCE_GUARD_DISK_MIN_FREE_GB (int, default: 1)
  - RESOURCE_GUARD_STRICT ("true"/"false", default: "false")
"""

from __future__ import annotations

import os
import shutil
import sys


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y"}


def main() -> int:
    min_free_gb_str = os.environ.get("RESOURCE_GUARD_DISK_MIN_FREE_GB", "1")
    strict = parse_bool(os.environ.get("RESOURCE_GUARD_STRICT"), default=False)
    try:
        min_free_gb = int(min_free_gb_str)
    except ValueError:
        print(f"Invalid RESOURCE_GUARD_DISK_MIN_FREE_GB='{min_free_gb_str}', defaulting to 1 GB")
        min_free_gb = 1

    total, used, free = shutil.disk_usage(".")
    free_gb = free / (1024**3)

    print(f"Resource Guard: free={free_gb:.2f} GB, min_required={min_free_gb} GB, strict={strict}")

    if free_gb < min_free_gb:
        msg = f"Resource Guard: LOW DISK SPACE (free={free_gb:.2f} GB < {min_free_gb} GB)"
        print(msg)
        return 1 if strict else 0

    print("Resource Guard: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
