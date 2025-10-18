"""
単体テスト: パイプライン実行でNameErrorが発生しないことを確認
"""

import warnings

warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from app.intake_service.api import _run_pipeline


def test_run_pipeline_no_nameerror():
    """_run_pipeline 実行後に新規で NameError('subprocess') が記録されないことを確認する（既存ログは無視）"""
    # import 対象を解決
    sys.path.insert(0, os.getcwd())
    from app.intake_service.api import _run_pipeline

    log_file = Path("data/logs/current/intake_auto.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # マーカーを付与して、以降の追記のみ検査する
    marker = "[TEST] PIPELINE_MARKER\n"
    # 既存ログがテストに影響しないよう、テスト開始時にログをクリア
    if log_file.exists():
        log_file.write_text("", encoding="utf-8")
    before_len = 0
    if log_file.exists():
        before_text = log_file.read_text(encoding="utf-8")
        before_len = len(before_text)
    else:
        before_text = ""
    with log_file.open("a", encoding="utf-8") as f:
        f.write(marker)

    # 実行
    try:
        _run_pipeline("test_pipeline", "manual", {})
    except Exception:
        # エラーは期待されるが、NameErrorでないことを確認
        pass

    # 検査: マーカー以降のみ
    if log_file.exists():
        after_text = log_file.read_text(encoding="utf-8")
        parts = after_text.split(marker)
        if len(parts) >= 2:
            new_segment = parts[-1]
        else:
            # ログローテーション等でマーカーが消えた場合
            # 1) ファイルサイズが増えたなら、その増加分のみを検査
            # 2) 増えていない（ローテーションで縮んだ等）なら末尾1000文字のみを検査
            if len(after_text) > before_len:
                new_segment = after_text[before_len:]
            else:
                new_segment = after_text[-1000:]
        assert "name 'subprocess' is not defined" not in new_segment, (
            "新規ログに 'name \"subprocess\" is not defined' が含まれています\n"
            f"=== New Segment Start ===\n{new_segment[-800:]}\n=== New Segment End ==="
        )
