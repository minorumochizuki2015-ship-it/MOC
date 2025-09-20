#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ログ → SFT JSONL へ変換（重複除去・分割・統計付き）
例) .\.venv\Scripts\python.exe -X utf8 -u tools/export_sft_dataset.py --src data/logs/current --out data/sft --min_chars 48 --max_len 2048
"""
import argparse
import glob
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path

try:
    from src.common.paths import activate; activate()
except Exception:
    pass

def _norm(s: str) -> str:
    return (s or "").strip().replace("\r\n","\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", default="data/logs/current")
    p.add_argument("--out", default="data/sft")
    p.add_argument("--split", type=float, default=0.95)
    p.add_argument("--max_len", type=int, default=2048)
    p.add_argument("--min_chars", type=int, default=48)
    args = p.parse_args()

    Path(args.out).mkdir(parents=True, exist_ok=True)
    items, seen = [], set()
    for fp in glob.glob(os.path.join(args.src, "*.jsonl")):
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                inp = _norm(j.get("prompt") or j.get("input") or j.get("instruction") or "")
                out = _norm(j.get("output") or j.get("response") or j.get("answer") or "")
                if not inp or not out:
                    continue
                if len(inp)+len(out) < args.min_chars:
                    continue
                key = hashlib.sha1((inp+"\n###\n"+out).encode("utf-8")).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                if len(inp)+len(out) > args.max_len:
                    continue
                items.append({"instruction": inp, "output": out})

    random.seed(42)
    random.shuffle(items)
    n_train = int(len(items)*args.split)
    train, val = items[:n_train], items[n_train:]
    with open(os.path.join(args.out,"train.jsonl"),"w",encoding="utf-8") as f:
        for r in train: f.write(json.dumps(r, ensure_ascii=False)+"\n")
    with open(os.path.join(args.out,"val.jsonl"),"w",encoding="utf-8") as f:
        for r in val: f.write(json.dumps(r, ensure_ascii=False)+"\n")
    stats = {
        "total": len(items),
        "train": len(train),
        "val": len(val),
        "max_len": args.max_len,
        "min_chars": args.min_chars,
        "src": args.src,
        "ts": int(time.time())
    }
    with open(os.path.join(args.out,"stats.json"),"w",encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    print(json.dumps({"ok": True, "count": len(items), "out": str(args.out), "stats": stats}))

if __name__ == "__main__":
    main()
