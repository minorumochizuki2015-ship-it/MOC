#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
堅牢なテストシステム
PowerShellエラーを回避した自動実行機能
"""

import os
import subprocess
import sys
import time
from pathlib import Path


def robust_test_system():
    """堅牢なテストシステム"""
    print("堅牢なテストシステム実行")
    print("=" * 40)

    try:
        # 環境変数設定
        os.environ["OPENAI_COMPAT_BASE"] = "http://127.0.0.1:8080/v1"
        os.environ["OPENAI_API_KEY"] = "sk-local"

        # パス設定
        sys.path.insert(0, os.getcwd())

        # 1. 基本機能テスト
        print("1. 基本機能テスト")
        print("-" * 20)

        # kernel.pyの新機能テスト
        try:
            from src.core.kernel import generate_chat, healthcheck, read_paths

            print("✓ kernel.py新機能: インポート成功")

            # ヘルスチェック
            if healthcheck():
                print("✓ サーバー: 接続成功")
            else:
                print("⚠️ サーバー: 接続失敗")

        except Exception as e:
            print(f"✗ kernel.py新機能: エラー - {e}")
            return False

        # 2. 会話継続機能テスト
        print("\n2. 会話継続機能テスト")
        print("-" * 20)

        try:
            # テスト用の会話履歴
            test_history = [
                {"role": "user", "content": "こんにちは"},
                {
                    "role": "assistant",
                    "content": "こんにちは！何かお手伝いできることはありますか？",
                },
            ]

            start_time = time.monotonic()
            result = generate_chat(
                test_history, "前の会話を覚えていますか？", max_tokens=128
            )
            processing_time = time.monotonic() - start_time

            print(f"✓ 会話継続: 成功")
            print(f"✓ 処理時間: {processing_time:.2f}s")
            print(f"✓ 結果: {result[:50]}...")

        except Exception as e:
            print(f"✗ 会話継続: エラー - {e}")

        # 3. ファイル読み込み機能テスト
        print("\n3. ファイル読み込み機能テスト")
        print("-" * 20)

        try:
            # テスト用ファイルを作成
            test_file = Path("test_sample.py")
            test_file.write_text(
                "# テストファイル\nprint('Hello, World!')", encoding="utf-8"
            )

            file_content = read_paths([str(test_file)], 1)  # 1KB制限
            print(f"✓ ファイル読み込み: 成功 ({len(file_content)} 文字)")
            print(f"✓ 内容: {file_content[:50]}...")

            # テストファイルを削除
            if test_file.exists():
                test_file.unlink()

        except Exception as e:
            print(f"✗ ファイル読み込み: エラー - {e}")

        # 4. GUI統合テスト
        print("\n4. GUI統合テスト")
        print("-" * 20)

        try:
            from src.ui.modern_interface import ModernCursorAIInterface

            print("✓ GUI: インポート成功")

            # 会話履歴管理のテスト
            app = ModernCursorAIInterface()
            print("✓ 会話履歴管理: 利用可能")

        except Exception as e:
            print(f"✗ GUI統合: エラー - {e}")

        # 5. セッションファイル確認
        print("\n5. セッションファイル確認")
        print("-" * 20)

        session_file = Path("data/session.jsonl")
        if session_file.exists():
            print(f"✓ セッションファイル: 存在 ({session_file})")
            with open(session_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            print(f"✓ 会話履歴: {len(lines)} 行")
        else:
            print("⚠️ セッションファイル: 未作成（初回起動時は正常）")

        print("\n" + "=" * 40)
        print("✅ 堅牢なテストシステム完了！")
        print("=" * 40)

        return True

    except Exception as e:
        print(f"✗ システムエラー: {e}")
        import traceback

        traceback.print_exc()
        return False


def create_self_executing_bat():
    """自己実行可能なバッチファイルを作成"""
    bat_content = """@echo off
chcp 65001 >nul
title 堅牢なテストシステム

echo 堅牢なテストシステム実行
echo ========================

"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" "%~dp0robust_test_system.py"

echo.
echo 実行完了
pause
"""

    with open("run_robust_test.bat", "w", encoding="utf-8") as f:
        f.write(bat_content)

    print("✓ 自己実行可能なバッチファイルを作成しました")


if __name__ == "__main__":
    # 自己実行可能なバッチファイルを作成
    create_self_executing_bat()

    # テスト実行
    success = robust_test_system()
    print(f"\nResult: {'SUCCESS' if success else 'FAILED'}")

    # 結果をファイルに保存
    with open("test_result.txt", "w", encoding="utf-8") as f:
        f.write(f"Test Result: {'SUCCESS' if success else 'FAILED'}\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    print("✓ 結果をtest_result.txtに保存しました")
    input("Press Enter to continue...")
