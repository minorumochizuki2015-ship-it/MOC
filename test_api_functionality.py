#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
スタイル管理API機能テスト
"""

import json
import time
from datetime import datetime

import requests


class StyleManagerAPITester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.test_results = []

    def test_get_styles(self):
        """スタイル取得APIのテスト"""
        print("\n=== スタイル取得APIテスト ===")

        try:
            response = requests.get(f"{self.base_url}/api/styles")

            if response.status_code == 200:
                data = response.json()
                print(f"✓ スタイル取得成功: {len(data)} 項目")
                print(f"  レスポンス例: {list(data.keys())[:5]}")
                self.test_results.append(
                    {
                        "test": "Get Styles API",
                        "status": "PASS",
                        "message": f"Successfully retrieved {len(data)} style items",
                    }
                )
            else:
                print(f"✗ スタイル取得失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Get Styles API",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}: {response.text}",
                    }
                )

        except Exception as e:
            print(f"✗ スタイル取得エラー: {e}")
            self.test_results.append(
                {"test": "Get Styles API", "status": "FAIL", "message": str(e)}
            )

    def test_update_styles(self):
        """スタイル更新APIのテスト"""
        print("\n=== スタイル更新APIテスト ===")

        test_data = {"key": "test_color", "value": "#ff0000"}

        try:
            response = requests.post(
                f"{self.base_url}/api/styles",
                json=test_data,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    print(f"✓ スタイル更新成功: {test_data['key']} = {test_data['value']}")
                    self.test_results.append(
                        {
                            "test": "Update Styles API",
                            "status": "PASS",
                            "message": "Style update successful",
                        }
                    )
                else:
                    print(f"✗ スタイル更新失敗: {data.get('message', 'Unknown error')}")
                    self.test_results.append(
                        {
                            "test": "Update Styles API",
                            "status": "FAIL",
                            "message": data.get("message", "Unknown error"),
                        }
                    )
            else:
                print(f"✗ スタイル更新失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Update Styles API",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}: {response.text}",
                    }
                )

        except Exception as e:
            print(f"✗ スタイル更新エラー: {e}")
            self.test_results.append(
                {"test": "Update Styles API", "status": "FAIL", "message": str(e)}
            )

    def test_create_patch(self):
        """パッチ作成APIのテスト"""
        print("\n=== パッチ作成APIテスト ===")

        test_data = {
            "changes": [
                {"selector": ".test-element", "property": "color", "value": "#00ff00"},
                {"selector": ".test-element", "property": "background-color", "value": "#000000"},
            ]
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/patch",
                json=test_data,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    print(f"✓ パッチ作成成功")
                    print(f"  パッチ内容: {data.get('patch', '')[:100]}...")
                    self.test_results.append(
                        {
                            "test": "Create Patch API",
                            "status": "PASS",
                            "message": "Patch creation successful",
                        }
                    )
                else:
                    print(f"✗ パッチ作成失敗: {data.get('message', 'Unknown error')}")
                    self.test_results.append(
                        {
                            "test": "Create Patch API",
                            "status": "FAIL",
                            "message": data.get("message", "Unknown error"),
                        }
                    )
            else:
                print(f"✗ パッチ作成失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Create Patch API",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}: {response.text}",
                    }
                )

        except Exception as e:
            print(f"✗ パッチ作成エラー: {e}")
            self.test_results.append(
                {"test": "Create Patch API", "status": "FAIL", "message": str(e)}
            )

    def test_pages_api(self):
        """ページ一覧APIのテスト"""
        print("\n=== ページ一覧APIテスト ===")

        try:
            response = requests.get(f"{self.base_url}/api/pages")

            if response.status_code == 200:
                data = response.json()
                print(f"✓ ページ一覧取得成功: {len(data)} ページ")
                for page in data[:3]:  # 最初の3つを表示
                    print(f"  - {page.get('name', 'Unknown')}: {page.get('url', 'No URL')}")
                self.test_results.append(
                    {
                        "test": "Pages API",
                        "status": "PASS",
                        "message": f"Successfully retrieved {len(data)} pages",
                    }
                )
            else:
                print(f"✗ ページ一覧取得失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Pages API",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}: {response.text}",
                    }
                )

        except Exception as e:
            print(f"✗ ページ一覧取得エラー: {e}")
            self.test_results.append({"test": "Pages API", "status": "FAIL", "message": str(e)})

    def test_invalid_requests(self):
        """不正なリクエストのテスト"""
        print("\n=== 不正リクエストテスト ===")

        # 不正なJSONデータでのテスト
        try:
            response = requests.post(
                f"{self.base_url}/api/styles",
                data="invalid json",
                headers={"Content-Type": "application/json"},
            )

            if response.status_code >= 400:
                print(f"✓ 不正JSON処理正常: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Invalid JSON Handling",
                        "status": "PASS",
                        "message": f"Properly handled invalid JSON with HTTP {response.status_code}",
                    }
                )
            else:
                print(f"✗ 不正JSON処理異常: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Invalid JSON Handling",
                        "status": "FAIL",
                        "message": f"Should have returned error for invalid JSON, got HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ 不正JSON処理エラー: {e}")
            self.test_results.append(
                {"test": "Invalid JSON Handling", "status": "FAIL", "message": str(e)}
            )

    def save_results(self):
        """テスト結果を保存"""
        results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"]),
            },
            "results": self.test_results,
        }

        with open("api_test_results.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    def run_all_tests(self):
        """全てのテストを実行"""
        print("🚀 スタイル管理API機能テスト開始")
        print("=" * 50)

        self.test_get_styles()
        self.test_update_styles()
        self.test_create_patch()
        self.test_pages_api()
        self.test_invalid_requests()

        print("\n📊 テスト結果")
        print("=" * 50)

        passed = len([r for r in self.test_results if r["status"] == "PASS"])
        failed = len([r for r in self.test_results if r["status"] == "FAIL"])
        skipped = len([r for r in self.test_results if r["status"] == "SKIP"])

        for result in self.test_results:
            status_icon = (
                "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
            )
            print(f"{status_icon} {result['test']}: {result['status']}")
            print(f"   {result['message']}")

        print(f"\n📈 サマリー")
        print(f"✅ 成功: {passed}")
        print(f"❌ 失敗: {failed}")
        print(f"⏭️ スキップ: {skipped}")
        print(f"📊 合計: {len(self.test_results)}")

        self.save_results()
        print(f"\n💾 詳細結果を api_test_results.json に保存しました")


if __name__ == "__main__":
    tester = StyleManagerAPITester()
    tester.run_all_tests()
