#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統治核AI - モダン版メインアプリケーション
"""

import logging
import os
import pathlib
import sys
from logging.handlers import RotatingFileHandler

# 環境変数設定
os.environ.setdefault("PYTHONPATH", os.getcwd())
os.environ.setdefault("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")
os.environ.setdefault("OPENAI_API_KEY", "sk-local")

# --- force backend to local OpenAI-compatible server ---
try:
    from src.core.kernel import generate as _infer

    def _call_model(prompt: str) -> str:
        return _infer(prompt, max_tokens=128)

except ImportError as e:
    print(f"インポートエラー: {e}")
    print("フォールバック: 従来のインターフェースを使用します...")
    try:
        from src.ui.interface import CursorAIInterface as ModernCursorAIInterface
    except ImportError as e2:
        print(f"フォールバックエラー: {e2}")
        print("Enterキーを押して終了...")
        input()
        sys.exit(1)
# -------------------------------------------------------

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
    統治核AI v5 - モダン版
    メインエントリーポイント
    """
    print("=" * 60)
    print("   統治核AI v5 - モダンインターフェース")
    print("   Cursor AI同等システム（最新UI版）")
    print("=" * 60)
    print("起動中...")

    try:
        print("モダンインターフェースを初期化中...")
        from src.ui.modern_interface import ModernCursorAIInterface

        app = ModernCursorAIInterface()
        print("モダンインターフェース初期化完了")
        print("GUIを起動中...")

        app.run()
        print("GUI終了")

    except ImportError as e:
        print(f"インポートエラー: {e}")
        print("フォールバック: 従来のインターフェースを使用します...")

        try:
            from src.ui.cursor_ai_interface import CursorAIInterface

            app = CursorAIInterface()
            app.run()
        except Exception as fallback_error:
            print(f"フォールバックエラー: {fallback_error}")
            input("Enterキーを押して終了...")

    except Exception as e:
        print(f"エラーが発生しました: {e}")
        import traceback

        traceback.print_exc()
        input("Enterキーを押して終了...")


if __name__ == "__main__":
    main()
