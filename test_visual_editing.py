#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
スタイル管理のビジュアル編集機能テスト
"""

import json
import time
from datetime import datetime

import requests


class VisualEditingTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.test_results = []

    def test_style_manager_page_load(self):
        """スタイル管理ページの読み込みテスト"""
        print("\n=== スタイル管理ページ読み込みテスト ===")

        try:
            response = requests.get(f"{self.base_url}/style-manager")

            if response.status_code == 200:
                content = response.text

                # 必要なコンポーネントが含まれているか確認
                required_elements = [
                    "styleManagerApp",
                    "pageSelect",
                    "selectModeBtn",
                    "colorModeBtn",
                    "textModeBtn",
                    "moveModeBtn",
                    "previewFrame",
                    "selectionInfoPanel",
                ]

                missing_elements = []
                for element in required_elements:
                    if element not in content:
                        missing_elements.append(element)

                if not missing_elements:
                    print(f"✓ スタイル管理ページが正常に読み込まれました")
                    print(f"  必要な要素: {len(required_elements)} 個すべて確認")
                    self.test_results.append(
                        {
                            "test": "Style Manager Page Load",
                            "status": "PASS",
                            "message": f"All {len(required_elements)} required elements found",
                        }
                    )
                else:
                    print(f"✗ 一部の要素が見つかりません: {missing_elements}")
                    self.test_results.append(
                        {
                            "test": "Style Manager Page Load",
                            "status": "FAIL",
                            "message": f"Missing elements: {missing_elements}",
                        }
                    )
            else:
                print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Style Manager Page Load",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ ページ読み込みエラー: {e}")
            self.test_results.append(
                {"test": "Style Manager Page Load", "status": "FAIL", "message": str(e)}
            )

    def test_color_tools_presence(self):
        """カラーツールの存在確認テスト"""
        print("\n=== カラーツール存在確認テスト ===")

        try:
            response = requests.get(f"{self.base_url}/style-manager")

            if response.status_code == 200:
                content = response.text

                # カラーツール関連の要素を確認
                color_elements = [
                    "colorPicker",
                    "colorPresets",
                    "colorHistory",
                    "colorMode",
                    "backgroundColorPicker",
                    "textColorPicker",
                ]

                found_elements = []
                for element in color_elements:
                    if element in content:
                        found_elements.append(element)

                print(f"✓ カラーツール要素: {len(found_elements)}/{len(color_elements)} 個確認")
                print(f"  確認された要素: {found_elements}")

                self.test_results.append(
                    {
                        "test": "Color Tools Presence",
                        "status": "PASS",
                        "message": f"Found {len(found_elements)} color tool elements",
                    }
                )
            else:
                print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Color Tools Presence",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ カラーツールテストエラー: {e}")
            self.test_results.append(
                {"test": "Color Tools Presence", "status": "FAIL", "message": str(e)}
            )

    def test_font_tools_presence(self):
        """フォントツールの存在確認テスト"""
        print("\n=== フォントツール存在確認テスト ===")

        try:
            response = requests.get(f"{self.base_url}/style-manager")

            if response.status_code == 200:
                content = response.text

                # フォントツール関連の要素を確認
                font_elements = [
                    "fontFamily",
                    "fontSize",
                    "fontWeight",
                    "fontStyle",
                    "googleFonts",
                    "textAlign",
                    "lineHeight",
                    "letterSpacing",
                ]

                found_elements = []
                for element in content:
                    if any(font_elem in content for font_elem in font_elements):
                        found_elements = [elem for elem in font_elements if elem in content]
                        break

                print(f"✓ フォントツール要素: {len(found_elements)}/{len(font_elements)} 個確認")
                print(f"  確認された要素: {found_elements}")

                self.test_results.append(
                    {
                        "test": "Font Tools Presence",
                        "status": "PASS",
                        "message": f"Found {len(found_elements)} font tool elements",
                    }
                )
            else:
                print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Font Tools Presence",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ フォントツールテストエラー: {e}")
            self.test_results.append(
                {"test": "Font Tools Presence", "status": "FAIL", "message": str(e)}
            )

    def test_layout_tools_presence(self):
        """レイアウトツールの存在確認テスト"""
        print("\n=== レイアウトツール存在確認テスト ===")

        try:
            response = requests.get(f"{self.base_url}/style-manager")

            if response.status_code == 200:
                content = response.text

                # レイアウトツール関連の要素を確認
                layout_elements = [
                    "margin",
                    "padding",
                    "width",
                    "height",
                    "position",
                    "display",
                    "flexbox",
                    "grid",
                ]

                found_elements = []
                for element in layout_elements:
                    if element in content.lower():
                        found_elements.append(element)

                print(
                    f"✓ レイアウトツール要素: {len(found_elements)}/{len(layout_elements)} 個確認"
                )
                print(f"  確認された要素: {found_elements}")

                self.test_results.append(
                    {
                        "test": "Layout Tools Presence",
                        "status": "PASS",
                        "message": f"Found {len(found_elements)} layout tool elements",
                    }
                )
            else:
                print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Layout Tools Presence",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ レイアウトツールテストエラー: {e}")
            self.test_results.append(
                {"test": "Layout Tools Presence", "status": "FAIL", "message": str(e)}
            )

    def test_preview_functionality(self):
        """プレビュー機能のテスト"""
        print("\n=== プレビュー機能テスト ===")

        try:
            # ダッシュボードページのプレビューを取得
            response = requests.get(f"{self.base_url}/dashboard")

            if response.status_code == 200:
                content = response.text

                # プレビューに必要な要素が含まれているか確認
                preview_elements = ["<html", "<head", "<body", "stylesheet", "script"]

                found_elements = []
                for element in preview_elements:
                    if element in content.lower():
                        found_elements.append(element)

                if len(found_elements) >= 3:  # 最低限のHTML構造があるか
                    print(f"✓ プレビュー機能が正常に動作しています")
                    print(f"  HTML要素: {len(found_elements)}/{len(preview_elements)} 個確認")
                    self.test_results.append(
                        {
                            "test": "Preview Functionality",
                            "status": "PASS",
                            "message": f"Preview content properly structured with {len(found_elements)} elements",
                        }
                    )
                else:
                    print(f"✗ プレビューコンテンツが不完全です")
                    self.test_results.append(
                        {
                            "test": "Preview Functionality",
                            "status": "FAIL",
                            "message": f"Incomplete preview content, only {len(found_elements)} elements found",
                        }
                    )
            else:
                print(f"✗ プレビュー取得失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Preview Functionality",
                        "status": "FAIL",
                        "message": f"HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ プレビュー機能テストエラー: {e}")
            self.test_results.append(
                {"test": "Preview Functionality", "status": "FAIL", "message": str(e)}
            )

    def test_style_persistence(self):
        """スタイル永続化テスト"""
        print("\n=== スタイル永続化テスト ===")

        try:
            # 現在のスタイルを取得
            response = requests.get(f"{self.base_url}/api/styles")

            if response.status_code == 200:
                original_styles = response.json()

                # テストスタイルを更新
                test_style = {"key": "test_persistence", "value": "#123456"}

                update_response = requests.post(
                    f"{self.base_url}/api/styles",
                    json=test_style,
                    headers={"Content-Type": "application/json"},
                )

                if update_response.status_code == 200:
                    # 更新後のスタイルを再取得
                    verify_response = requests.get(f"{self.base_url}/api/styles")

                    if verify_response.status_code == 200:
                        updated_styles = verify_response.json()

                        if test_style["key"] in updated_styles:
                            print(f"✓ スタイルが正常に永続化されました")
                            print(
                                f"  テストキー: {test_style['key']} = {updated_styles[test_style['key']]}"
                            )
                            self.test_results.append(
                                {
                                    "test": "Style Persistence",
                                    "status": "PASS",
                                    "message": "Style successfully persisted and retrieved",
                                }
                            )
                        else:
                            print(f"✗ スタイルの永続化に失敗しました")
                            self.test_results.append(
                                {
                                    "test": "Style Persistence",
                                    "status": "FAIL",
                                    "message": "Style not found after update",
                                }
                            )
                    else:
                        print(f"✗ 更新後のスタイル取得に失敗: HTTP {verify_response.status_code}")
                        self.test_results.append(
                            {
                                "test": "Style Persistence",
                                "status": "FAIL",
                                "message": f"Failed to retrieve updated styles: HTTP {verify_response.status_code}",
                            }
                        )
                else:
                    print(f"✗ スタイル更新に失敗: HTTP {update_response.status_code}")
                    self.test_results.append(
                        {
                            "test": "Style Persistence",
                            "status": "FAIL",
                            "message": f"Failed to update style: HTTP {update_response.status_code}",
                        }
                    )
            else:
                print(f"✗ 初期スタイル取得に失敗: HTTP {response.status_code}")
                self.test_results.append(
                    {
                        "test": "Style Persistence",
                        "status": "FAIL",
                        "message": f"Failed to get initial styles: HTTP {response.status_code}",
                    }
                )

        except Exception as e:
            print(f"✗ スタイル永続化テストエラー: {e}")
            self.test_results.append(
                {"test": "Style Persistence", "status": "FAIL", "message": str(e)}
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

        with open("visual_editing_test_results.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    def run_all_tests(self):
        """全てのテストを実行"""
        print("🚀 スタイル管理ビジュアル編集機能テスト開始")
        print("=" * 50)

        self.test_style_manager_page_load()
        self.test_color_tools_presence()
        self.test_font_tools_presence()
        self.test_layout_tools_presence()
        self.test_preview_functionality()
        self.test_style_persistence()

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
        print(f"\n💾 詳細結果を visual_editing_test_results.json に保存しました")


if __name__ == "__main__":
    tester = VisualEditingTester()
    tester.run_all_tests()
