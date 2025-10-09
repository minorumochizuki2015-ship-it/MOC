"""
Aggregate multi-terminal test outputs into a single summary JSON (cross-platform).
Usage:
  python scripts/ops/aggregate_multi_terminal_results.py

It will execute configured pytest commands and store results in:
  data/test_results/multi_terminal_summary.json
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

CONFIG = {
    "commands": [
        {
            "name": "integration_metrics_rate",
            "pytest_args": [
                "tests/integration/test_full_workflow.py::TestFullWorkflow::test_metrics_endpoint_workflow",
                "tests/integration/test_full_workflow.py::TestFullWorkflow::test_rate_limiting_workflow",
                "-q",
            ],
        },
        {"name": "contract_jwt", "pytest_args": ["tests/contract/test_jwt_contract.py", "-q"]},
        {"name": "unit_security", "pytest_args": ["tests/test_security.py", "-q"]},
        {"name": "unit_orchestrator", "pytest_args": ["tests/test_orchestrator.py", "-q"]},
    ]
}


def run_pytest(pytest_args) -> dict:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    cmd = [sys.executable, "-m", "pytest"] + list(pytest_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


def main():
    os.makedirs("data/test_results", exist_ok=True)
    summary = {"generated_at": datetime.now(timezone.utc).isoformat(), "results": []}

    for item in CONFIG["commands"]:
        res = run_pytest(item["pytest_args"])
        summary["results"].append(
            {
                "name": item["name"],
                "exit_code": res["exit_code"],
                "stdout_tail": res["stdout"].splitlines()[-50:],
                "stderr_tail": res["stderr"].splitlines()[-50:],
            }
        )

    out_path = "data/test_results/multi_terminal_summary.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"Wrote summary: {out_path}")


if __name__ == "__main__":
    main()
