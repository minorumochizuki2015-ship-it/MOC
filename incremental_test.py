#!/usr/bin/env python3
"""
段階的検証システム
各修正後に動作確認を行い、問題があれば即座にロールバック
"""

import json
import subprocess
import sys
import time
from pathlib import Path


def run_test(test_name, command, expected_output=None):
    """テストを実行し、結果を返す"""
    print(f"🧪 {test_name} テスト実行中...")
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0

        if expected_output and expected_output not in result.stdout:
            print(f"❌ {test_name}: 期待される出力が見つかりません")
            print(f"   期待: {expected_output}")
            print(f"   実際: {result.stdout[:200]}...")
            success = False
        elif success:
            print(f"✅ {test_name}: 成功")
        else:
            print(f"❌ {test_name}: 失敗 (終了コード: {result.returncode})")
            if result.stderr:
                print(f"   エラー: {result.stderr[:200]}...")

        return success, result
    except subprocess.TimeoutExpired:
        print(f"⏰ {test_name}: タイムアウト")
        return False, None
    except Exception as e:
        print(f"💥 {test_name}: 例外 - {e}")
        return False, None


def test_server_connection():
    """サーバー接続テスト"""
    return run_test(
        "サーバー接続", "curl -s http://127.0.0.1:8080/v1/models", '"object":"list"'
    )


def test_ui_startup():
    """UI起動テスト（短時間）"""
    return run_test(
        "UI起動",
        ".venv\\Scripts\\python.exe -c \"import sys; sys.path.insert(0, '.'); from src.ui.modern_interface import ModernCursorAIInterface; import tkinter as tk; root = tk.Tk(); root.withdraw(); app = ModernCursorAIInterface(root); print('UI初期化成功'); root.destroy()\"",
        "UI初期化成功",
    )


def test_ai_functionality():
    """AI機能テスト"""
    return run_test(
        "AI機能",
        ".venv\\Scripts\\python.exe -c \"import sys; sys.path.insert(0, '.'); from src.core.kernel import Kernel; from src.core.memory import Memory; memory = Memory(); kernel = Kernel(memory); result = kernel.query_local_api('こんにちは'); print('AI応答:', result.get('response_text', '')[:50])\"",
        "AI応答:",
    )


def create_checkpoint():
    """現在の状態をチェックポイントとして保存"""
    try:
        result = subprocess.run(
            'git add -A && git commit -m "checkpoint: 段階的検証" --no-verify',
            shell=True,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("✅ チェックポイント作成成功")
            return True
        else:
            print(f"❌ チェックポイント作成失敗: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ チェックポイント作成例外: {e}")
        return False


def rollback_to_checkpoint():
    """最後のチェックポイントにロールバック"""
    try:
        result = subprocess.run(
            "git reset --hard HEAD~1", shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            print("🔄 ロールバック成功")
            return True
        else:
            print(f"❌ ロールバック失敗: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ ロールバック例外: {e}")
        return False


def main():
    """メイン検証処理"""
    print("🔍 段階的検証システム開始")
    print("=" * 50)

    # 現在の状態をチェックポイントとして保存
    if not create_checkpoint():
        print("❌ チェックポイント作成に失敗しました")
        return False

    # テストスイート
    tests = [
        ("サーバー接続", test_server_connection),
        ("UI起動", test_ui_startup),
        ("AI機能", test_ai_functionality),
    ]

    results = []
    for test_name, test_func in tests:
        success, result = test_func()
        results.append((test_name, success))

        if not success:
            print(f"\n❌ {test_name} テストが失敗しました")
            print("🔄 ロールバックを実行します...")
            if rollback_to_checkpoint():
                print("✅ ロールバック完了")
            else:
                print("❌ ロールバック失敗")
            return False

        print()  # 空行

    # 全テスト成功
    print("=" * 50)
    print("🎉 すべてのテストが成功しました！")
    print("📊 テスト結果サマリー:")
    for test_name, success in results:
        status = "✅ 成功" if success else "❌ 失敗"
        print(f"  {test_name}: {status}")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
