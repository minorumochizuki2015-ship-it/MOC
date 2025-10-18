#!/usr/bin/env python3
import os
from pathlib import Path

import pytest

from src.tools.eol_utils import write_json_lf, write_text_lf

LOCKS_DIR = Path("ORCH/STATE/LOCKS")


@pytest.mark.unit
def test_write_json_lf_to_locks_has_only_lf():
    """Ensure JSON written to ORCH/STATE/LOCKS uses LF line endings (no CRLF)."""
    LOCKS_DIR.mkdir(parents=True, exist_ok=True)
    target = LOCKS_DIR / "test_eol.json"

    try:
        write_json_lf(target, {"ok": True, "msg": "LF only"})
        data = target.read_bytes()

        # Must contain LF and must NOT contain CRLF
        assert b"\n" in data
        assert b"\r\n" not in data
    finally:
        if target.exists():
            target.unlink()


@pytest.mark.unit
def test_write_text_lf_to_locks_has_only_lf():
    """Ensure text written to ORCH/STATE/LOCKS uses LF line endings (no CRLF)."""
    LOCKS_DIR.mkdir(parents=True, exist_ok=True)
    target = LOCKS_DIR / "test_eol.txt"

    try:
        content = "line1\nline2\nline3"
        write_text_lf(target, content)
        data = target.read_bytes()

        assert b"\n" in data
        assert b"\r\n" not in data
    finally:
        if target.exists():
            target.unlink()
