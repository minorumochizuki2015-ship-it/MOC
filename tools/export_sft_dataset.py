#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ログ → SFT JSONL へ変換
例) .\.venv\Scripts\python.exe -X utf8 -u tools/export_sft_dataset.py --out data/datasets/sft.jsonl
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from src.common.paths import activate; activate()
except Exception:
    pass

def main():
    out = Path((sys.argv[sys.argv.index("--out")+1]) if "--out" in sys.argv else "data/datasets/sft.jsonl")
    root = Path("data/logs")
    items = []
    
    for p in root.rglob("*.jsonl"):
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                rec = json.loads(line)
                prompt = rec.get("prompt") or rec.get("input") or rec.get("query")
                resp   = rec.get("response") or rec.get("output") or rec.get("answer")
                if prompt and resp:
                    items.append({"prompt": prompt, "response": resp, "meta": {"src": str(p)}})
        except Exception:
            continue
    
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    
    print(json.dumps({"ok": True, "count": len(items), "out": str(out)}))

if __name__ == "__main__":
    main()
