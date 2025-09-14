#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
シンプルなAI機能テスト
"""

import sys

sys.path.append(".")


def simple_ai_test():
    try:
        print("=== シンプルAIテスト開始 ===")

        # 1. 基本的なインポート
        print("1. インポートテスト...")
        from src.core.kernel import generate_chat

        print("✅ インポート成功")

        # 2. 簡単なテスト
        print("2. 簡単なテスト...")
        result = generate_chat([], "Hello, world!", max_tokens=50)
        print(f"✅ 結果: {result}")

        # 3. デバッグテスト
        print("3. デバッグテスト...")
        result = generate_chat(
            [], "このコードをデバッグしてください: print('hello')", max_tokens=100
        )
        print(f"✅ デバッグ結果: {result}")

        # 4. 分析テスト
        print("4. 分析テスト...")
        result = generate_chat(
            [], "このコードを分析してください: def test(): return 1", max_tokens=100
        )
        print(f"✅ 分析結果: {result}")

        return True

    except Exception as e:
        print(f"❌ エラー: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = simple_ai_test()
    if success:
        print("✅ すべてのテスト成功")
    else:
        print("❌ テスト失敗")
