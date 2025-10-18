"""
Waitress エントリポイント（Windows サービス/常駐向け）

使い方:
  - 依存インストール:  python -m pip install waitress
  - 実行:              python scripts/ops/waitress_entry.py
  - ORCH_PORT でポート指定（既定 5000）

サービス化（例）:
  New-Service -Name ORCHNextDashboard -DisplayName "ORCH-Next Dashboard" \
    -BinaryPathName "`"$(Get-Command python).Source`" `"C:\\Users\\User\\Trae\\ORCH-Next\\scripts\\ops\\waitress_entry.py`"" \
    -StartupType Automatic

注意:
  - Windows サービスは実行ディレクトリが System32 になるため、本スクリプトで sys.path にプロジェクトルートを追加しています。
"""

import os
import sys
from pathlib import Path

try:
    from waitress import serve
except Exception as e:
    raise RuntimeError("waitress が未インストールです。 'python -m pip install waitress' を実行してください") from e

# プロジェクトルートを sys.path に追加（サービス起動時のカレント対策）
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.dashboard import app, _setup_logging_for_app  # noqa: E402
import src.dashboard as dashboard_mod  # noqa: E402


def main():
    # ログ設定（dashboard 側の RotatingFileHandler 設定を利用）
    try:
        _setup_logging_for_app(app)
    except Exception:
        # ログ設定失敗時もサービス起動は継続
        pass
    # 既定はローカルのみ（公開時は ORCH_HOST を明示し、TLS/リバースプロキシ＋IP制限を必須）
    host = os.getenv("ORCH_HOST", "127.0.0.1")
    port_str = os.getenv("ORCH_PORT", "5001")
    try:
        port = int(port_str)
    except ValueError:
        port = 5000

    # インポートモジュールのファイルパスを標準出力に出す（診断用）
    try:
        print(f"[diag] dashboard_mod.__file__={getattr(dashboard_mod, '__file__', 'unknown')}")
    except Exception:
        pass
    # 待受開始（threads は必要に応じて調整）
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()