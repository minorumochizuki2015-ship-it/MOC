# src/common/paths.py
from __future__ import annotations
from pathlib import Path
import os, sys

MARKERS = ("pyproject.toml", "main_modern.py", ".git")

def _discover_root(start: Path | None = None) -> Path:
    # 環境変数優先
    env = os.environ.get("GC_ROOT")
    if env:
        p = Path(env).resolve()
        if p.exists():
            return p
    cur = (start or Path(__file__)).resolve()
    for up in [cur, *cur.parents]:
        if any((up / m).exists() for m in MARKERS) and (up / "src").exists():
            return up
    # フォールバック: 2つ上で src/ を要求
    up2 = Path(__file__).resolve().parents[2]
    if (up2 / "src").exists():
        return up2
    return Path.cwd().resolve()

ROOT = _discover_root()
SRC  = ROOT / "src"
DATA = ROOT / "data"
LOGS = DATA / "logs" / "current"
DOCS = ROOT / "docs"

def activate() -> None:
    r = str(ROOT)
    if r not in sys.path:
        sys.path.insert(0, r)
    try:
        os.chdir(r)
    except Exception:
        pass
