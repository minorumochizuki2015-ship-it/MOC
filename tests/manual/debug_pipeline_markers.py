import os
import sys
from datetime import datetime
from pathlib import Path

# リポジトリ直下を import パスへ追加
sys.path.insert(0, os.getcwd())

from app.intake_service.ui import (
    run_auto_training_pipeline_inproc,
    run_data_analysis_inproc,
    run_export_sft_inproc,
    run_filter_inproc,
)

LOG_FILE = Path("data/logs/current/intake_auto.log")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def mark(stage: str) -> None:
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat()}] [TEST] STAGE {stage} START\n")


def run_and_log(stage: str, func, *args, **kwargs):
    mark(stage)
    try:
        res = func(*args, **kwargs)
        if isinstance(res, tuple):
            ok = bool(res[0])
            msg = res[1] if len(res) > 1 else ""
        else:
            ok = True
            msg = str(res)
        print(f"{stage}: ok={ok} msg={msg}")
    except Exception as e:
        print(f"{stage}: EXCEPTION {e}")


def main():
    run_and_log("FILTER", run_filter_inproc)
    run_and_log("EXPORT_SFT", run_export_sft_inproc)
    run_and_log("ANALYZE", run_data_analysis_inproc)
    run_and_log("AUTO_TRAIN", run_auto_training_pipeline_inproc)


if __name__ == "__main__":
    main()
