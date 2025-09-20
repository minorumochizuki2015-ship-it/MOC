#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Headless Agent runner
例:
  .\\.venv\\Scripts\\python.exe -X utf8 -u tools/agent_cli.py --goal "READMEを要約しdocs/summary.mdへ"
  .\\.venv\\Scripts\\python.exe -X utf8 -u tools/agent_cli.py --goal "testsを修復" --apply
"""
import argparse
import json
import os
import sys
from pathlib import Path

try:
    from src.common.paths import activate; activate()
except Exception:
    sys.path.insert(0, os.getcwd())

from src.core.code_executor import CodeExecutor
from src.core.kernel import generate as llm_generate
from src.core.kernel import healthcheck

try:
    from src.core.agent_mode import AgentMode
except Exception as e:
    print(json.dumps({"ok": False, "error": f"AgentMode import failed: {e}"}))
    sys.exit(2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goal", required=False)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--max-steps", type=int, default=8)
    ap.add_argument("--tool", default=None, help="list_dir/read_file/write_file/modify_file/search/run_tests/git_commit")
    ap.add_argument("--tool-args", default="{}", help='JSON args for tool')
    args = ap.parse_args()
    
    if not args.goal and not args.tool:
        ap.error("Either --goal or --tool must be specified")
    
    ok = healthcheck()
    if not ok:
        print(json.dumps({"ok": False, "error": "server_offline"})); sys.exit(2)
    
    agent = AgentMode(kernel_llm=llm_generate,
                      executor=CodeExecutor(workspace_root=os.getcwd()),
                      dry_run=not args.apply,
                      max_steps=args.max_steps)
    
    # 進化アルゴリズムを統合
    agent.integrate_evolution()
    
    run = getattr(agent, "plan_and_execute", getattr(agent, "run", None))
    if not callable(run):
        print(json.dumps({"ok": False, "error": "AgentMode has no runner"})); sys.exit(2)
    
    if args.tool:
        tool_args = json.loads(args.tool_args)
        res = agent.step(json.dumps({"tool": args.tool, "args": tool_args}))
    else:
        res = run(args.goal)
    print(json.dumps({"ok": True, "result": res}, ensure_ascii=False))

if __name__ == "__main__":
    main()
