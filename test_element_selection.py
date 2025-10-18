#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
スタイル管理の要素選択機能テスト
"""

import json
import time
from datetime import datetime

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class ElementSelectionTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.test_results = []
        self.driver = None

    def setup(self):
        """Seleniumドライバーのセットアップ"""
        print("🔧 ブラウザドライバーを初期化中...")
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # ヘッドレスモードで実行
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_window_size(1366, 768)
            print("✓ ブラウザドライバー初期化成功")
            return True
        except Exception as e:
            print(f"✗ ブラウザドライバー初期化失敗: {e}")
            self.test_results.append({"test": "Browser Setup", "status": "FAIL", "message": str(e)})
            return False

    def teardown(self):
        """ドライバーのクリーンアップ"""
        if self.driver:
            self.driver.quit()
            print("✓ ブラウザドライバーを終了しました")

    def navigate_to_style_manager(self):
        """スタイル管理ページに移動"""
        print("\n=== スタイル管理ページへの移動 ===")
        try:
            self.driver.get(f"{self.base_url}/style-manager")
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "styleManagerApp"))
            )
            print("✓ スタイル管理ページに移動成功")
            self.test_results.append(
                {
                    "test": "Navigate to Style Manager",
                    "status": "PASS",
                    "message": "Successfully navigated to style manager page",
                }
            )
            return True
        except Exception as e:
            print(f"✗ スタイル管理ページへの移動失敗: {e}")
            self.test_results.append(
                {"test": "Navigate to Style Manager", "status": "FAIL", "message": str(e)}
            )
            return False

    def test_select_mode_activation(self):
        """選択モードの有効化テスト"""
        print("\n=== 選択モード有効化テスト ===")
        try:
            # 選択モードボタンをクリック
            select_btn = WebDriverWait(self.driver, 5).until(
                EC.element_to_be_clickable((By.ID, "selectModeBtn"))
            )
            select_btn.click()

            # 選択モードが有効になったか確認
            time.sleep(1)  # UIの更新を待つ
            select_btn_class = select_btn.get_attribute("class")

            if "active" in select_btn_class:
                print("✓ 選択モードが正常に有効化されました")
                self.test_results.append(
                    {
                        "test": "Select Mode Activation",
                        "status": "PASS",
                        "message": "Select mode successfully activated",
                    }
                )
                return True
            else:
                print("✗ 選択モードの有効化に失敗しました")
                self.test_results.append(
                    {
                        "test": "Select Mode Activation",
                        "status": "FAIL",
                        "message": "Select mode button did not become active",
                    }
                )
                return False

        except Exception as e:
            print(f"✗ 選択モードテストエラー: {e}")
            self.test_results.append(
                {"test": "Select Mode Activation", "status": "FAIL", "message": str(e)}
            )
            return False

    def test_preview_frame_loading(self):
        """プレビューフレームの読み込みテスト"""
        print("\n=== プレビューフレーム読み込みテスト ===")
        try:
            # プレビューフレームが存在するか確認
            preview_frame = WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.ID, "previewFrame"))
            )

            # フレームに切り替え
            self.driver.switch_to.frame(preview_frame)

            # フレーム内のコンテンツが読み込まれているか確認
            body = WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # メインフレームに戻る
            self.driver.switch_to.default_content()

            print("✓ プレビューフレームが正常に読み込まれました")
            self.test_results.append(
                {
                    "test": "Preview Frame Loading",
                    "status": "PASS",
                    "message": "Preview frame successfully loaded with content",
                }
            )
            return True

        except Exception as e:
            # エラーが発生した場合、メインフレームに戻る
            try:
                self.driver.switch_to.default_content()
            except:
                pass

            print(f"✗ プレビューフレーム読み込みエラー: {e}")
            self.test_results.append(
                {"test": "Preview Frame Loading", "status": "FAIL", "message": str(e)}
            )
            return False

    def test_element_selection(self):
        """要素選択機能のテスト"""
        print("\n=== 要素選択機能テスト ===")
        try:
            # 選択モードが有効になっていることを確認
            select_btn = self.driver.find_element(By.ID, "selectModeBtn")
            if "active" not in select_btn.get_attribute("class"):
                select_btn.click()
                time.sleep(1)

            # プレビューフレームに切り替え
            preview_frame = self.driver.find_element(By.ID, "previewFrame")
            self.driver.switch_to.frame(preview_frame)

            # フレーム内の要素をクリック (例: 最初の見出し要素)
            try:
                heading = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "h1, h2, h3, h4, h5, h6"))
                )
                heading.click()

                # メインフレームに戻る
                self.driver.switch_to.default_content()

                # 選択情報パネルが表示されているか確認
                selection_panel = WebDriverWait(self.driver, 5).until(
                    EC.visibility_of_element_located((By.ID, "selectionInfoPanel"))
                )

                panel_text = selection_panel.text
                if panel_text and len(panel_text) > 0:
                    print(f"✓ 要素が正常に選択され、情報パネルが表示されました")
                    print(f"  選択情報: {panel_text[:100]}...")
                    self.test_results.append(
                        {
                            "test": "Element Selection",
                            "status": "PASS",
                            "message": "Element successfully selected and info panel displayed",
                        }
                    )
                    return True
                else:
                    print("✗ 要素は選択されましたが、情報パネルが正しく表示されていません")
                    self.test_results.append(
                        {
                            "test": "Element Selection",
                            "status": "FAIL",
                            "message": "Info panel not properly populated after selection",
                        }
                    )
                    return False

            except Exception as e:
                # エラーが発生した場合、メインフレームに戻る
                try:
                    self.driver.switch_to.default_content()
                except:
                    pass

                print(f"✗ 要素選択エラー: {e}")
                self.test_results.append(
                    {
                        "test": "Element Selection",
                        "status": "FAIL",
                        "message": f"Error during element selection: {str(e)}",
                    }
                )
                return False

        except Exception as e:
            # エラーが発生した場合、メインフレームに戻る
            try:
                self.driver.switch_to.default_content()
            except:
                pass

            print(f"✗ 要素選択テストエラー: {e}")
            self.test_results.append(
                {"test": "Element Selection", "status": "FAIL", "message": str(e)}
            )
            return False

    def test_selection_mode_switching(self):
        """選択モードの切り替えテスト"""
        print("\n=== 選択モード切り替えテスト ===")
        try:
            # 色モードに切り替え
            color_btn = WebDriverWait(self.driver, 5).until(
                EC.element_to_be_clickable((By.ID, "colorModeBtn"))
            )
            color_btn.click()
            time.sleep(1)

            # 色モードが有効になったか確認
            if "active" in color_btn.get_attribute("class"):
                print("✓ 色モードに正常に切り替わりました")

                # テキストモードに切り替え
                text_btn = self.driver.find_element(By.ID, "textModeBtn")
                text_btn.click()
                time.sleep(1)

                # テキストモードが有効になったか確認
                if "active" in text_btn.get_attribute("class"):
                    print("✓ テキストモードに正常に切り替わりました")

                    # 移動モードに切り替え
                    move_btn = self.driver.find_element(By.ID, "moveModeBtn")
                    move_btn.click()
                    time.sleep(1)

                    # 移動モードが有効になったか確認
                    if "active" in move_btn.get_attribute("class"):
                        print("✓ 移動モードに正常に切り替わりました")
                        self.test_results.append(
                            {
                                "test": "Selection Mode Switching",
                                "status": "PASS",
                                "message": "Successfully switched between all selection modes",
                            }
                        )
                        return True

            print("✗ 選択モードの切り替えに一部失敗しました")
            self.test_results.append(
                {
                    "test": "Selection Mode Switching",
                    "status": "FAIL",
                    "message": "Failed to switch between some selection modes",
                }
            )
            return False

        except Exception as e:
            print(f"✗ 選択モード切り替えテストエラー: {e}")
            self.test_results.append(
                {"test": "Selection Mode Switching", "status": "FAIL", "message": str(e)}
            )
            return False

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

        with open("element_selection_test_results.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    def run_all_tests(self):
        """全てのテストを実行"""
        print("🚀 スタイル管理要素選択機能テスト開始")
        print("=" * 50)

        if not self.setup():
            print("✗ セットアップに失敗したため、テストを中止します")
            return

        try:
            if self.navigate_to_style_manager():
                self.test_select_mode_activation()
                self.test_preview_frame_loading()
                self.test_element_selection()
                self.test_selection_mode_switching()
        finally:
            self.teardown()

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
        print(f"\n💾 詳細結果を element_selection_test_results.json に保存しました")


if __name__ == "__main__":
    tester = ElementSelectionTester()
    tester.run_all_tests()
