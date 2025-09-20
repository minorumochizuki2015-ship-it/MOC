from __future__ import annotations
import os, io, json, fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional

# ルート固定（ワークスペース外アクセス禁止）
ROOT = Path(os.environ.get("GC_WORKSPACE", ".")).resolve()

def _safe(p: str|Path) -> Path:
    q = (ROOT / p).resolve()
    if not str(q).startswith(str(ROOT)):
        raise PermissionError("path escapes workspace")
    return q

def list_dir(pattern: str="**/*", limit: int=200) -> List[str]:
    hits = []
    for p in ROOT.glob(pattern):
        if len(hits) >= limit: break
        if p.is_file(): hits.append(str(p.relative_to(ROOT)))
    return hits

def read_file(path: str, max_bytes: int=256_000, encoding: str="utf-8") -> Dict[str, Any]:
    q = _safe(path)
    b = q.read_bytes()[:max_bytes]
    try:
        text = b.decode(encoding)
        kind = "text"
    except UnicodeDecodeError:
        text = b.hex()[:32_768]
        kind = "hex"
    return {"path": path, "kind": kind, "content": text}

def write_file(path: str, content: str, encoding: str="utf-8") -> Dict[str, Any]:
    q = _safe(path)
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(content, encoding=encoding, newline="\n")
    return {"path": path, "bytes": q.stat().st_size}

def modify_file(path: str, find: str, replace: str, encoding: str="utf-8", count: int=0) -> Dict[str, Any]:
    q = _safe(path)
    s = q.read_text(encoding=encoding)
    if count and count > 0:
        new, n = s.replace(find, replace, count), s.count(find, 0, len(s))
    else:
        new, n = s.replace(find, replace), s.count(find)
    q.write_text(new, encoding=encoding, newline="\n")
    return {"path": path, "replaced": n}

def search(pattern: str="*.py", text: Optional[str]=None, limit: int=100) -> List[Dict[str, Any]]:
    out = []
    for p in ROOT.rglob(pattern):
        if len(out) >= limit: break
        if not p.is_file(): continue
        if text:
            try:
                if text in p.read_text(encoding="utf-8", errors="ignore"):
                    out.append({"path": str(p.relative_to(ROOT))})
            except Exception:
                continue
        else:
            out.append({"path": str(p.relative_to(ROOT))})
    return out
