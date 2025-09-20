#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ミニ評価（ヘッドレスAgentで回帰テスト）
例) .\.venv\Scripts\python.exe -X utf8 -u tools/mini_eval.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_TIMEOUT = int(os.getenv("MINI_EVAL_TIMEOUT", "15"))
DEFAULT_MODE = os.getenv("MINI_EVAL_MODE", "tools")  # 'tools' or 'agent'

try:
    from src.common.paths import activate; activate()
except Exception:
    pass

CASES = [
  {"tool":"list_dir","args":{"path":"docs","limit":50}},
  {"tool":"read_file","args":{"path":"docs/README.md"}},
  {"tool":"search","args":{"path":"src","keyword":"def ", "limit":20}},
]

PY = os.path.join(".venv","Scripts","python.exe") if os.name=="nt" else sys.executable
CLI = ["-X","utf8","-u","tools/agent_cli.py"]

def run_case(c, timeout=DEFAULT_TIMEOUT):
    t0 = time.perf_counter()
    cmd = [PY,*CLI,"--tool",c["tool"],"--tool-args",json.dumps(c["args"])]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = p.returncode==0
    except subprocess.TimeoutExpired:
        ok = False
        p = type('obj', (object,), {'stdout': '', 'stderr': f'timeout>{timeout}s'})()
    dt = (time.perf_counter()-t0)*1000
    return {"ok":ok,"ms":int(dt),"stdout":p.stdout.strip()[:2000],"stderr":p.stderr.strip()[:1000]}

def main():
    results = [run_case(c) for c in CASES]
    score = sum(1 for r in results if r["ok"])
    out = {"score":score,"total":len(results),"results":results}
    Path("data/outputs").mkdir(parents=True, exist_ok=True)
    with open("data/outputs/mini_eval.json","w",encoding="utf-8") as f:
        json.dump(out,f,ensure_ascii=False,indent=2)
    print(json.dumps(out,ensure_ascii=False,indent=2))
    return score == len(results)

if __name__=="__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["agent","tools"], default=DEFAULT_MODE)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--baseline", default=None)
    p.add_argument("--out", default="data/outputs/mini_eval.json")
    args = p.parse_args()
    
    if args.mode == "tools":
        # tools直呼び（高速・軽量）
        success = main()
        sys.exit(0 if success else 1)
    else:
        # agent経由（重い・pytest実行リスク）
        import pathlib
        cases = [
          {"name":"edit_file", "tool":"write_file", "args":{"path":"data/outputs/mini_eval_edit.txt","content":"OK"}},
          {"name":"search_repo", "tool":"search", "args":{"pattern":"起動方法","limit":5}},
          {"name":"make_diff", "tool":"read_file", "args":{"path":"data/outputs/dummy_old.txt"}},
        ]
        passed = 0; details=[]
        tmp = pathlib.Path("data/outputs"); tmp.mkdir(parents=True, exist_ok=True)
        pathlib.Path("data/outputs/dummy_old.txt").write_text("old\n", encoding="utf-8")
        pathlib.Path("data/outputs/dummy_new.txt").write_text("old\nnew\n", encoding="utf-8")
        for c in cases:
            t0=time.time()
            cmd = [PY,*CLI,"--tool",c["tool"],"--tool-args",json.dumps(c["args"], ensure_ascii=False)]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
                ok = p.returncode==0
            except subprocess.TimeoutExpired:
                ok = False
            passed += 1 if ok else 0
            details.append({"name":c["name"], "ok":bool(ok), "ms":int((time.time()-t0)*1000)})
        score = f"{passed}/{len(cases)}"
        out = {"score":score, "passed":passed, "total":len(cases), "cases":details, "ts":int(time.time())}
        if args.baseline and pathlib.Path(args.baseline).exists():
            base = json.loads(pathlib.Path(args.baseline).read_text(encoding="utf-8"))
            out["baseline"]=base.get("score")
            out["regression"]= (passed < base.get("passed",passed))
        pathlib.Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        sys.exit(0 if passed==len(cases) else 1)

