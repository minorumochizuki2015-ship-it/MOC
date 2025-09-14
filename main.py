import logging
import os
import pathlib
import sys
from logging.handlers import RotatingFileHandler

from src.ui.cursor_ai_interface import CursorAIInterface

# ログ設定
logdir = pathlib.Path.home() / "LocalAI" / "logs"
logdir.mkdir(parents=True, exist_ok=True)

handler = RotatingFileHandler(
    logdir / "app.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
)
logging.basicConfig(
    level=logging.INFO,
    handlers=[handler],
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def main() -> None:
    """
    GoverningCore v5 - 統治核AIシステム (Cursor AI同等版)
    メインエントリーポイント

    起動方法:
    - 直接実行: python main.py
    - バッチ実行: 起動_Cursor版.bat
    - GPU起動: scripts/Start-LocalAI-GPU.ps1
    """
    print("=" * 60)
    print("   GoverningCore v5 - 統治核AIシステム")
    print("   Cursor AI同等インターフェース版")
    print("=" * 60)
    print("起動中...")

    # 環境変数設定
    os.environ.setdefault("PYTHONPATH", os.getcwd())
    os.environ.setdefault("OPENAI_COMPAT_BASE", "http://localhost:8080/v1")
    os.environ.setdefault("OPENAI_API_KEY", "sk-local")

    try:
        print("Cursor AI同等システムを初期化中...")
        app = CursorAIInterface()
        print("Cursor AI同等システム初期化完了")
        print("GUIを起動中...")
        app.parent.mainloop()
        print("GUI終了")
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        import traceback

        traceback.print_exc()
        input("Enterキーを押して終了...")


if __name__ == "__main__":
    main()
