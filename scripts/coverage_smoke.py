#!/usr/bin/env python3
"""
Minimal smoke script to validate coverage tracer collects data.
Imports a few src modules and executes trivial code paths.
"""

import sys
from pathlib import Path

print("[coverage_smoke] start")

# Ensure project root is on sys.path so `import src.*` works when
# running as a standalone script under coverage.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import target modules
import src.security as security
import src.workflows_api as workflows_api

# Exercise trivial code paths
sm = security.SecurityManager(
    {
        "database": {"path": ":memory:"},
        "jwt": {"secret_key": "smoke", "algorithm": "HS256", "expiry_hours": 1},
        "webhook": {"secret": "smoke", "time_tolerance": 60},
        "rate_limits": {"rules": []},
    }
)

# Use a simple function to ensure some lines execute
_rules = sm._load_rate_limits({})
print(f"[coverage_smoke] rules={len(_rules)}")

print("[coverage_smoke] end")
