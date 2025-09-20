#!/usr/bin/env python3
"""
サーバー接続診断ツール
段階的にサーバー接続を検証し、問題箇所を特定する
"""

import json
import sys
import time
from pathlib import Path

import requests


def test_basic_connection():
    """基本的なHTTP接続テスト"""
    print("=== 基本接続テスト ===")
    try:
        response = requests.get("http://127.0.0.1:8080/v1/models", timeout=5)
        print(f"✅ HTTP接続成功: {response.status_code}")
        print(f"✅ レスポンス長: {len(response.text)} bytes")
        return True
    except Exception as e:
        print(f"❌ HTTP接続失敗: {e}")
        return False


def test_response_encoding():
    """レスポンスの文字エンコーディングテスト"""
    print("\n=== 文字エンコーディングテスト ===")
    try:
        response = requests.get("http://127.0.0.1:8080/v1/models", timeout=5)
        print(f"✅ レスポンスエンコーディング: {response.encoding}")
        print(f"✅ レスポンス文字列長: {len(response.text)}")

        # JSON解析テスト
        data = response.json()
        print(f"✅ JSON解析成功: {len(data.get('data', []))} モデル")

        return True
    except Exception as e:
        print(f"❌ エンコーディング/JSON解析失敗: {e}")
        return False


def test_ai_request():
    """AIリクエストテスト"""
    print("\n=== AIリクエストテスト ===")
    try:
        url = "http://127.0.0.1:8080/v1/chat/completions"
        headers = {
            "Authorization": "Bearer sk-local",
            "Content-Type": "application/json",
        }
        data = {
            "model": "/models/qwen2-7b-instruct-q4_k_m.gguf",
            "messages": [{"role": "user", "content": "こんにちは"}],
            "max_tokens": 50,
            "stream": False,
        }

        response = requests.post(url, json=data, headers=headers, timeout=30)
        print(f"✅ AIリクエスト成功: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            content = (
                result.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
            print(f"✅ AI応答取得成功: {len(content)} 文字")
            print(f"✅ 応答内容: {content[:100]}...")
            return True
        else:
            print(f"❌ AIリクエスト失敗: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ AIリクエストエラー: {e}")
        return False


def test_ui_connection_method():
    """UIの接続メソッドをテスト"""
    print("\n=== UI接続メソッドテスト ===")
    try:
        # UIの接続メソッドを模擬
        import requests

        response = requests.get("http://127.0.0.1:8080/v1/models", timeout=5)
        if response.status_code == 200:
            print("✅ UI接続メソッド: 成功")
            return True
        else:
            print(f"❌ UI接続メソッド: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ UI接続メソッド: {e}")
        return False


def main():
    """メイン診断処理"""
    print("🔍 サーバー接続診断開始")
    print("=" * 50)

    tests = [
        ("基本接続", test_basic_connection),
        ("文字エンコーディング", test_response_encoding),
        ("AIリクエスト", test_ai_request),
        ("UI接続メソッド", test_ui_connection_method),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ {name}テストで例外: {e}")
            results.append((name, False))

    print("\n" + "=" * 50)
    print("📊 診断結果サマリー")
    print("=" * 50)

    for name, result in results:
        status = "✅ 成功" if result else "❌ 失敗"
        print(f"{name}: {status}")

    success_count = sum(1 for _, result in results if result)
    total_count = len(results)

    print(
        f"\n成功率: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)"
    )

    if success_count == total_count:
        print("🎉 すべてのテストが成功しました！")
        return True
    else:
        print("⚠️ 一部のテストが失敗しました。")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
