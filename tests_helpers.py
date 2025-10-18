"""
Reusable test helpers for Windows-resilient filesystem cleanup.

Provides:
- unlink_with_retry(path, attempts=10, delay=0.2)
- cleanup_temp_dir(temp_dir, attempts=10, delay=0.2)
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path


def unlink_with_retry(path: Path, attempts: int = 10, delay: float = 0.2) -> None:
    """Delete a file with retry to handle transient Windows locks.

    Silently retries on PermissionError and OSError up to `attempts` times,
    waiting `delay` seconds between retries. If unlink still fails, the error
    is suppressed to keep tests resilient.
    """
    for _ in range(attempts):
        try:
            path.unlink()
            return
        except (PermissionError, OSError):
            time.sleep(delay)
            continue
    # Final attempt (best effort)
    try:
        path.unlink()
    except Exception:
        # Suppress any remaining error to avoid flaky tests
        pass


def cleanup_temp_dir(temp_dir: Path, attempts: int = 10, delay: float = 0.2) -> None:
    """Cleanup helper used in test tearDown.

    - Unlinks files under `temp_dir` with retry.
    - Finally removes the directory tree with ignore_errors=True.
    """
    # Unlink all files (best effort with retry)
    for file in temp_dir.rglob("*"):
        if file.is_file():
            unlink_with_retry(file, attempts=attempts, delay=delay)

    # Forcefully remove the directory tree
    shutil.rmtree(temp_dir, ignore_errors=True)
