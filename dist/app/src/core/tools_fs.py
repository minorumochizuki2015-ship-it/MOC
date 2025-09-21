from __future__ import annotations

import fnmatch
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# ルート固定（ワークスペース外アクセス禁止）
ROOT = Path(os.environ.get("GC_WORKSPACE", ".")).resolve()

def _safe(p: str|Path) -> Path:
    q = Path(p)
    if not q.is_absolute():
        q = (ROOT / q).resolve()
    q = q.resolve()
    if str(q) == str(ROOT) or str(q).startswith(str(ROOT) + os.sep):
        return q
    raise PermissionError("path escapes workspace")

def list_dir(pattern: str="**/*", limit: Union[int, str]=200) -> List[str]:
    try:
        limit = int(limit)
    except Exception:
        limit = 200
    hits = []
    for p in ROOT.glob(pattern):
        if len(hits) >= limit: break
        if p.is_file(): hits.append(str(p.relative_to(ROOT)))
    return hits

def read_file(path: str, max_bytes: int=256_000, encoding: str="utf-8") -> Dict[str, Any]:
    q = _safe(path)
    if not q.exists() or q.is_dir():
        return {"error": "not found"}
    b = q.read_bytes()[:max_bytes]
    try:
        text = b.decode(encoding)
        kind = "text"
    except UnicodeDecodeError:
        text = b.hex()[:32_768]
        kind = "hex"
    return {"path": str(q), "kind": kind, "content": text}

def write_file(path: str, content: str, encoding: str="utf-8") -> Dict[str, Any]:
    q = _safe(path)
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(content, encoding=encoding, newline="\n")
    return {"ok": True, "path": str(q), "bytes": q.stat().st_size}

def modify_file(path: str, find: str, replace: str, encoding: str="utf-8", count: int=0) -> Dict[str, Any]:
    q = _safe(path)
    if not q.exists() or q.is_dir():
        return {"error": "not found"}
    s = q.read_text(encoding=encoding)
    if count and count > 0:
        new, n = s.replace(find, replace, count), s.count(find, 0, len(s))
    else:
        new, n = s.replace(find, replace), s.count(find)
    if new == s:
        return {"ok": True, "changed": 0}
    q.write_text(new, encoding=encoding, newline="\n")
    return {"ok": True, "changed": n}

def search(pattern: str="*.py", text: Optional[str]=None, limit: int=100) -> List[Dict[str, Any]]:
    out = []
    for p in ROOT.rglob(pattern):
        if len(out) >= limit: break
        if not p.is_file(): continue
        if text:
            try:
                if text in p.read_text(encoding="utf-8", errors="ignore"):
                    out.append({"path": str(p.relative_to(ROOT)), "hit": True})
            except Exception:
                continue
        else:
            out.append({"path": str(p.relative_to(ROOT))})
    return out
