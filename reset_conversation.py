#!/usr/bin/env python3
"""
会話履歴を完全にリセットするスクリプト
"""
import json
import os
from pathlib import Path


def reset_conversation_history():
    """会話履歴を完全にリセット"""
    try:
        # セッションファイルのパス
        session_file = Path("data/session.jsonl")

        # ファイルが存在する場合は削除
        if session_file.exists():
            session_file.unlink()
            print("✅ セッションファイルを削除しました")

        # データディレクトリ内の他のログファイルも削除
        data_dir = Path("data")
        if data_dir.exists():
            for log_file in data_dir.glob("*.jsonl"):
                if log_file.name != "session.jsonl":
                    log_file.unlink()
                    print(f"✅ ログファイルを削除しました: {log_file.name}")

        # 空の会話履歴を作成
        with open(session_file, "w", encoding="utf-8") as f:
            f.write("")

        print("✅ 会話履歴を完全にリセットしました")
        print("これでコンテキスト長エラーが解消されるはずです。")

    except Exception as e:
        print(f"❌ エラー: {e}")


if __name__ == "__main__":
    reset_conversation_history()
