"""
Cross-platform terminal role runner.

Usage:
  python scripts/ops/terminal_role_runner.py --role Auditor
  python scripts/ops/terminal_role_runner.py --role Executor-Contract
  python scripts/ops/terminal_role_runner.py --role Executor-Unit
  python scripts/ops/terminal_role_runner.py --role Executor-Orchestrator

This script disables pytest plugin auto-load to reduce environment variance.
"""

import argparse
import os
import subprocess
import sys

ROLES = {
    "Auditor": [
        [
            "tests/integration/test_full_workflow.py::TestFullWorkflow::test_metrics_endpoint_workflow",
            "-q",
        ],
        [
            "tests/integration/test_full_workflow.py::TestFullWorkflow::test_rate_limiting_workflow",
            "-q",
        ],
    ],
    "Executor-Contract": [["tests/contract/test_jwt_contract.py", "-q"]],
    "Executor-Unit": [["tests/test_security.py", "-q"]],
    "Executor-Orchestrator": [["tests/test_orchestrator.py", "-q"]],
}


def run_pytest(args_list) -> int:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    cmd = [sys.executable, "-m", "pytest"] + list(args_list)
    proc = subprocess.run(cmd, env=env)
    return proc.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=list(ROLES.keys()))
    parsed = parser.parse_args()
    suites = ROLES[parsed.role]
    exit_code = 0
    for suite_args in suites:
        code = run_pytest(suite_args)
        if code != 0:
            exit_code = code
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
