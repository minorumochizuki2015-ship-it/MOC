#!/usr/bin/env python3
"""
EOL utilities for consistent LF writes on all platforms.

Provides helper functions to write text/JSON files using LF ("\n") line endings
by passing newline="\n" to Python's open(). This enforces the project rule for
files under ORCH/STATE/LOCKS/ and can be used elsewhere to avoid CRLF issues.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_text_lf(path: str | Path, text: str) -> None:
    """Write text to file using UTF-8 and LF ("\n") line endings.

    Ensures parent directories exist. Does not append a trailing newline.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def write_json_lf(
    path: str | Path,
    obj: Any,
    *,
    ensure_ascii: bool = False,
    indent: int | None = 2,
) -> None:
    """Write JSON to file using UTF-8 and LF ("\n") line endings.

    - ensure_ascii=False preserves Unicode characters.
    - indent=2 produces readable, stable formatting (set to None for compact).
    - No trailing newline is added to keep output consistent with existing files.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=ensure_ascii, indent=indent)
