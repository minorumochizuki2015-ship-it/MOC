#!/usr/bin/env python3
"""
Generate a single canary alert through MonitoringSystem.send_alerts to validate
local notifications (ORCH/REPORTS/notifications.log) and evidence registration
to WORK_TRACKING.md and ORCH/STATE/APPROVALS.md.

This script avoids starting the infinite monitoring loop and instead crafts a
minimal analysis payload with one alert.
"""

import os
import sys
from datetime import datetime

# Ensure project root is on sys.path so that `src` package can be imported
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.monitoring_system import MonitoringSystem


def main():
    ms = MonitoringSystem()

    analysis = {
        "metrics": {
            "timestamp": datetime.now().isoformat(),
            "test_coverage": 0.82,
            "code_complexity": 2.1,
            "error_rate": 0.02,
            "performance_score": 0.9,
            "source": "canary_script",
        },
        "prediction": {
            "prediction": "no_issue",
            "confidence": 0.91,
        },
        "alerts": [
            {
                "type": "canary_test",
                "severity": "warning",
                "message": "監査・テスト用カナリーアラート（fallback通知と証跡登録の検証）",
                "metric": "canary",
                "value": 1,
            }
        ],
        "anomalies": [],
        "analysis_time": datetime.now().isoformat(),
    }

    ms.send_alerts(analysis)
    print("Canary alert dispatched. Check ORCH/REPORTS/notifications.log and evidence files.")


if __name__ == "__main__":
    main()
