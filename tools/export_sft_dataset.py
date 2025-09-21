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
    p.add_argument("--split", type=float, default=0.9)
    p.add_argument("--max_len", type=int, default=2048)
    p.add_argument("--min_chars", type=int, default=16)
    p.add_argument("--buckets", help="bucketsディレクトリから読み込み（ドメイン別）")
    p.add_argument("--domain", help="特定ドメインのみ処理（code/write/patent）")
    args = p.parse_args()

    Path(args.out).mkdir(parents=True, exist_ok=True)
    items, seen = [], set()
    
    # 入力ソースを決定
    if args.buckets:
        # bucketsディレクトリから読み込み（ドメイン別）
        buckets_dir = Path(args.buckets)
        if args.domain:
            # 特定ドメインのみ
            domain_dirs = [buckets_dir / args.domain]
        else:
            # 全ドメイン
            domain_dirs = [d for d in buckets_dir.iterdir() if d.is_dir()]
        
        for domain_dir in domain_dirs:
            for fp in domain_dir.glob("*.jsonl"):
                with open(fp, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            j = json.loads(line)
                        except Exception:
                            continue
                        inp = _norm(j.get("instruction") or "")
                        out = _norm(j.get("output") or "")
                        meta = j.get("meta", {})
                        rationale = _norm(meta.get("rationale_success") or meta.get("rationale_failure") or "")
                        
                        # 失敗タスクもrationaleがあればSFTに含める
                        if not inp:
                            continue
                        if not out and not rationale:
                            continue
                        
                        # 失敗タスクの場合はrationaleをoutputとして使用
                        if not out and rationale:
                            out = f"[FAILED] {rationale}"
                        if len(inp)+len(out) < args.min_chars:
                            continue
                        key = hashlib.sha1((inp+"\n###\n"+out).encode("utf-8")).hexdigest()
                        if key in seen:
                            continue
                        seen.add(key)
                        if len(inp)+len(out) > args.max_len:
                            continue
                        items.append({"instruction": inp, "output": out})
    else:
        # 従来のログディレクトリから読み込み
        for fp in glob.glob(os.path.join(args.src, "*.jsonl")):
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        j = json.loads(line)
                    except Exception:
                        continue
                    inp = _norm(j.get("prompt") or j.get("input") or j.get("instruction") or "")
                    out = _norm(j.get("output") or j.get("response") or j.get("answer") or "")
                    rationale = _norm(j.get("rationale") or j.get("reason") or j.get("error") or "")
                    
                    # 失敗タスクもrationaleがあればSFTに含める
                    if not inp:
                        continue
                    if not out and not rationale:
                        continue
                    
                    # 失敗タスクの場合はrationaleをoutputとして使用
                    if not out and rationale:
                        out = f"[FAILED] {rationale}"
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
    
    # 出力ファイル名を決定
    if args.domain:
        train_file = f"train_{args.domain}.jsonl"
        val_file = f"val_{args.domain}.jsonl"
        stats_file = f"stats_{args.domain}.json"
    else:
        train_file = "train.jsonl"
        val_file = "val.jsonl"
        stats_file = "stats.json"
    
    with open(os.path.join(args.out, train_file), "w", encoding="utf-8") as f:
        for r in train: f.write(json.dumps(r, ensure_ascii=False)+"\n")
    with open(os.path.join(args.out, val_file), "w", encoding="utf-8") as f:
        for r in val: f.write(json.dumps(r, ensure_ascii=False)+"\n")
    
    stats = {
        "total": len(items),
        "train": len(train),
        "val": len(val),
        "max_len": args.max_len,
        "min_chars": args.min_chars,
        "src": args.src if not args.buckets else args.buckets,
        "domain": args.domain,
        "ts": int(time.time())
    }
    with open(os.path.join(args.out, stats_file), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    print(json.dumps({"ok": True, "count": len(items), "out": str(args.out), "stats": stats}))

if __name__ == "__main__":
    main()
