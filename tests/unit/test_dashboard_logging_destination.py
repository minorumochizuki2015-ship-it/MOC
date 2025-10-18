import os
from pathlib import Path

import pytest


def test_dashboard_logging_writes_to_data_logs_current(tmp_path):
    """
    P0受入: dashboard のロギングが data/logs/current/dashboard_app.log へ書き出されることを検証。

    - _setup_logging_for_app(app) を呼び出す
    - app.logger に INFO でマーカー行を書き込む（"app.start" を含む）
    - ログファイルが存在し、内容にマーカー行が含まれることを確認
    """
    # 実体の Flask アプリとロギング初期化をインポート
    from src.dashboard import app, _setup_logging_for_app  # noqa: WPS433

    # ロギング初期化
    _setup_logging_for_app(app)

    # マーカー行を書き込み
    marker = "app.start"
    app.logger.info("%s unit-test marker", marker)

    # 出力先パス
    project_root = Path(__file__).resolve().parents[2]
    log_file = project_root / "data" / "logs" / "current" / "dashboard_app.log"

    # ログファイルが作成されるまで少し待機（I/O 反映猶予）
    import time

    for _ in range(10):
        if log_file.exists():
            break
        time.sleep(0.1)

    assert log_file.exists(), "data/logs/current/dashboard_app.log が作成されていること"

    content = log_file.read_text(encoding="utf-8", errors="ignore")
    assert marker in content, "ログファイルに 'app.start' マーカーが含まれていること"