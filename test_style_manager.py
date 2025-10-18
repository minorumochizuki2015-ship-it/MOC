#!/usr/bin/env python3
"""
スタイル管理機能の実施テストスクリプト
"""

import json
import time

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class StyleManagerTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.driver = None
        self.test_results = []

    def setup_driver(self):
        """WebDriverのセットアップ"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # ヘッドレスモード
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

            try:
                self.driver = webdriver.Chrome(options=chrome_options)
                return True
            except Exception as e:
                print(f"WebDriver setup failed: {e}")
                print("WebDriverテストはスキップします")
                return False
        except Exception as e:
            print(f"WebDriver setup failed: {e}")
            print("WebDriverテストはスキップします")
            return False

    def test_dashboard_access(self):
        """ダッシュボードアクセステスト"""
        test_name = "Dashboard Access Test"
        try:
            response = requests.get(self.base_url, timeout=10)
            if response.status_code == 200:
                self.test_results.append(
                    {"test": test_name, "status": "PASS", "message": "Dashboard accessible"}
                )
                return True
            else:
                self.test_results.append(
                    {
                        "test": test_name,
                        "status": "FAIL",
                        "message": f"Status code: {response.status_code}",
                    }
                )
                return False
        except Exception as e:
            self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})
            return False

    def test_style_manager_page(self):
        """スタイル管理ページアクセステスト"""
        test_name = "Style Manager Page Test"
        try:
            response = requests.get(f"{self.base_url}/style-manager", timeout=10)
            if response.status_code == 200:
                self.test_results.append(
                    {
                        "test": test_name,
                        "status": "PASS",
                        "message": "Style manager page accessible",
                    }
                )
                return True
            else:
                self.test_results.append(
                    {
                        "test": test_name,
                        "status": "FAIL",
                        "message": f"Status code: {response.status_code}",
                    }
                )
                return False
        except Exception as e:
            self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})
            return False

    def test_api_endpoints(self):
        """API エンドポイントテスト"""
        endpoints = ["/api/styles", "/api/pages", "/api/prediction", "/api/trends"]

        for endpoint in endpoints:
            test_name = f"API Endpoint Test: {endpoint}"
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                if response.status_code == 200:
                    self.test_results.append(
                        {"test": test_name, "status": "PASS", "message": "API endpoint accessible"}
                    )
                else:
                    self.test_results.append(
                        {
                            "test": test_name,
                            "status": "FAIL",
                            "message": f"Status code: {response.status_code}",
                        }
                    )
            except Exception as e:
                self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})

    def test_ui_elements(self):
        """UI要素のテスト"""
        print("\n=== UI要素テスト ===")

        if not self.driver:
            print("WebDriverが利用できないため、UI要素テストをスキップします")
            return

        try:
            self.driver.get(f"{self.base_url}/style-manager")
            time.sleep(2)

            # ページタイトルの確認
            title = self.driver.title
            print(f"ページタイトル: {title}")

            # 主要な要素の存在確認
            elements_to_check = [
                ("pageSelect", "ページセレクタ"),
                ("selectModeBtn", "選択モードボタン"),
                ("colorModeBtn", "カラーモードボタン"),
                ("textModeBtn", "テキストモードボタン"),
                ("moveModeBtn", "移動モードボタン"),
                ("previewFrame", "プレビューフレーム"),
                ("selectionInfoPanel", "選択情報パネル"),
            ]

            for element_id, element_name in elements_to_check:
                try:
                    element = self.driver.find_element(By.ID, element_id)
                    print(f"✓ {element_name} が見つかりました")
                except:
                    print(f"✗ {element_name} が見つかりません")

        except Exception as e:
            print(f"UI要素テストでエラー: {e}")

    def run_all_tests(self):
        """全テストの実行"""
        print("🚀 スタイル管理機能実施テスト開始")
        print("=" * 50)

        # 基本テスト
        self.test_dashboard_access()
        self.test_style_manager_page()
        self.test_api_endpoints()

        # WebDriverセットアップ試行
        if self.setup_driver():
            self.test_ui_elements()
            self.cleanup()

    def cleanup(self):
        """リソースのクリーンアップ"""
        if hasattr(self, "driver") and self.driver:
            self.driver.quit()

        # 結果出力
        self.print_results()
        return self.test_results

    def print_results(self):
        """テスト結果の出力"""
        print("\n📊 テスト結果")
        print("=" * 50)

        passed = 0
        failed = 0
        skipped = 0

        for result in self.test_results:
            status_icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}.get(result["status"], "❓")

            print(f"{status_icon} {result['test']}: {result['status']}")
            print(f"   {result['message']}")

            if result["status"] == "PASS":
                passed += 1
            elif result["status"] == "FAIL":
                failed += 1
            else:
                skipped += 1

        print("\n📈 サマリー")
        print(f"✅ 成功: {passed}")
        print(f"❌ 失敗: {failed}")
        print(f"⏭️ スキップ: {skipped}")
        print(f"📊 合計: {len(self.test_results)}")

        # 結果をJSONファイルに保存
        with open("test_results.json", "w", encoding="utf-8") as f:
            json.dump(
                {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "summary": {"passed": passed, "failed": failed, "skipped": skipped},
                    "results": self.test_results,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        print(f"\n💾 詳細結果を test_results.json に保存しました")


if __name__ == "__main__":
    tester = StyleManagerTester()
    tester.run_all_tests()
