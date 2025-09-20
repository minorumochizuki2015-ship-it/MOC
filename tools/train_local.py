#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ローカル専用学習入口（外部API禁止・環境依存のため計画のみ出力）
例) .\.venv\Scripts\python.exe -X utf8 -u tools/train_local.py --backend llama.cpp --base models/qwen2-7b-instruct-q4_k_m.gguf --epochs 2
"""
import argparse
import json
import os
import sys
from pathlib import Path

try:
    from src.common.paths import activate; activate()
except Exception:
    pass

def fail(msg): 
    print(f"[TRAIN-ERROR] {msg}"); 
    sys.exit(2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["llama.cpp","hf"], default="llama.cpp")
    ap.add_argument("--base", required=True, help="ローカル基底モデルのパス（.gguf もしくは HF ローカルディレクトリ）")
    ap.add_argument("--train", default="data/sft/train.jsonl")
    ap.add_argument("--val", default="data/sft/val.jsonl")
    ap.add_argument("--out", default="dist/lora")
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    # 外部API禁止
    if any(k in os.environ for k in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","GOOGLE_API_KEY")):
        fail("外部API鍵が環境にあります。ローカル専用で実行してください。")

    # 入力検証
    if not Path(args.base).exists(): 
        fail(f"base not found: {args.base}")
    if not Path(args.train).exists(): 
        fail(f"train not found: {args.train}")
    if not Path(args.val).exists(): 
        fail(f"val not found: {args.val}")
    Path(args.out).mkdir(parents=True, exist_ok=True)

    # 実行案内のみ（環境依存のためコマンドは明示せずキー情報を出力）
    plan = {
        "backend": args.backend,
        "base": os.path.abspath(args.base),
        "train": os.path.abspath(args.train),
        "val": os.path.abspath(args.val),
        "out": os.path.abspath(args.out),
        "epochs": args.epochs,
        "notes": args.note,
        "hints": (
            "llama.cpp: examples/finetune のローカル実行で LoRA を生成し、--lora-out を args.out へ。"
            " HF: QLoRA (bitsandbytes 4bit) をオフラインキャッシュで実行。インターネット未使用。"
        )
    }
    with open(Path(args.out)/"train_plan.json","w",encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=2)
    print(json.dumps(plan, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
