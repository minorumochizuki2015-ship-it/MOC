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

def run_case(c):
    t0 = time.perf_counter()
    cmd = [PY,*CLI,"--tool",c["tool"],"--tool-args",json.dumps(c["args"])]
    p = subprocess.run(cmd, capture_output=True, text=True)
    dt = (time.perf_counter()-t0)*1000
    ok = p.returncode==0
    return {"ok":ok,"ms":int(dt),"stdout":p.stdout.strip()[:2000],"stderr":p.stderr.strip()[:1000]}

def main():
    results = [run_case(c) for c in CASES]
    score = sum(1 for r in results if r["ok"])
    out = {"score":score,"total":len(results),"results":results}
    Path("data/outputs").mkdir(parents=True, exist_ok=True)
    with open("data/outputs/mini_eval.json","w",encoding="utf-8") as f:
        json.dump(out,f,ensure_ascii=False,indent=2)
    print(json.dumps(out,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
