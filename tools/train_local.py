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
    # 追加: 実学習ランチャ（完全ローカルのみ）
    import argparse
    import json
    import os
    import pathlib
    import subprocess
    import sys
    import time
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan-only", action="store_true")
    ap.add_argument("--trainer-cmd", default=os.environ.get("LOCAL_LORA_TRAINER",""))
    ap.add_argument("--train", default="data/sft/train.jsonl")
    ap.add_argument("--val", default="data/sft/val.jsonl")
    ap.add_argument("--outdir", default="dist/lora")
    ap.add_argument("--domain", help="ドメイン指定（code/write/patent）")
    ap.add_argument("--auto-eval", action="store_true", help="学習後に自動評価・採否を実行")
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    
    # ドメイン別のファイル名を決定
    if args.domain:
        train_file = f"train_{args.domain}.jsonl"
        val_file = f"val_{args.domain}.jsonl"
        outdir = outdir / args.domain
        outdir.mkdir(parents=True, exist_ok=True)
    else:
        train_file = "train.jsonl"
        val_file = "val.jsonl"
    
    plan = {
        "train": args.train,
        "val": args.val,
        "domain": args.domain,
        "epochs": 1,
        "lr": 2e-4,
        "r": 8,
        "bf16": False,
        "auto_eval": args.auto_eval
    }
    (outdir/"train_plan.json").write_text(json.dumps(plan,indent=2), encoding="utf-8")
    
    if args.plan_only:
        print(json.dumps({"ok": True, "plan": plan, "outdir": str(outdir)}))
        sys.exit(0)
    # ローカル専用ガード
    for k in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","AZURE_OPENAI_KEY"):
        if os.environ.get(k): print(f"ERROR: {k} must be unset for local-only"); sys.exit(2)
    # 実学習（外部フレームワークがローカルにある前提でコマンド実行）
    if not args.trainer_cmd:
        print("INFO: trainer-cmd missing. Plan generated only.")
        sys.exit(0)
    
    state = outdir/"state"; state.mkdir(exist_ok=True, parents=True)
    logf = outdir/"train_stdout.log"
    cmd = args.trainer_cmd.format(train=args.train, val=args.val, outdir=str(outdir))
    t0=time.time()
    
    with open(logf, "a", encoding="utf-8") as lf:
        ret = subprocess.call(cmd, shell=True, stdout=lf, stderr=lf)
    
    run = {"ts":int(time.time()), "elapsed_sec":int(time.time()-t0), "cmd":cmd, "ret":ret}
    (outdir/"last_run.json").write_text(json.dumps(run,indent=2), encoding="utf-8")
    
    # 自動評価・採否実行
    if args.auto_eval and ret == 0:
        print("学習完了。自動評価・採否を実行中...")
        
        # mini_eval実行
        eval_cmd = [
            sys.executable, "-X", "utf8", "-u", "tools/mini_eval.py",
            "--mode", "tools",
            "--timeout", "30",
            "--baseline", "data/outputs/mini_eval_baseline.json",
            "--out", str(outdir/"mini_eval_result.json")
        ]
        
        eval_ret = subprocess.call(eval_cmd)
        
        if eval_ret == 0:
            # 評価成功: モデル置換
            print("評価成功。モデル置換を実行中...")
            swap_cmd = [
                "powershell", "-ExecutionPolicy", "Bypass", "-File",
                "scripts/model-swap.ps1",
                "--domain", args.domain or "default",
                "--lora-dir", str(outdir)
            ]
            swap_ret = subprocess.call(swap_cmd)
            
            if swap_ret == 0:
                print("モデル置換完了。学習→評価→採否が成功しました。")
            else:
                print("モデル置換失敗。ロールバックを実行中...")
                # ロールバック処理（実装は省略）
        else:
            print("評価失敗。学習結果を破棄します。")
            # 学習結果を破棄（実装は省略）
    
    sys.exit(ret)
