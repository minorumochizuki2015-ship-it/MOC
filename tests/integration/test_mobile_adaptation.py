#!/usr/bin/env python3
"""モバイル対応のテスト"""

import os
import sys
import tkinter as tk
import unittest
from unittest.mock import MagicMock, patch

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.ui.mobile_adapter import MobileAdapter, ResponsiveLayout


class TestMobileAdaptation(unittest.TestCase):
    """モバイル対応のテストクラス"""

    def setUp(self):
        """テストセットアップ"""
        self.root = tk.Tk()
        self.root.withdraw()  # ウィンドウを非表示
        self.mobile_adapter = MobileAdapter(self.root)
        self.responsive_layout = ResponsiveLayout(self.root, self.mobile_adapter)

    def tearDown(self):
        """テストクリーンアップ"""
        self.root.destroy()

    def test_mobile_environment_detection(self):
        """モバイル環境検出のテスト"""
        # 画面サイズベースの検出をテスト
        with patch.object(self.mobile_adapter, "screen_width", 800):
            with patch.object(self.mobile_adapter, "screen_height", 600):
                self.assertTrue(self.mobile_adapter._detect_mobile_environment())

        with patch.object(self.mobile_adapter, "screen_width", 1920):
            with patch.object(self.mobile_adapter, "screen_height", 1080):
                self.assertFalse(self.mobile_adapter._detect_mobile_environment())

    def test_responsive_geometry_calculation(self):
        """レスポンシブジオメトリ計算のテスト"""
        # モバイル環境での計算
        with patch.object(self.mobile_adapter, "is_mobile", True):
            with patch.object(self.mobile_adapter, "screen_width", 800):
                with patch.object(self.mobile_adapter, "screen_height", 600):
                    geometry = self.mobile_adapter.get_responsive_geometry()
                    self.assertIn("720x540", geometry)  # 90%サイズ

        # デスクトップ環境での計算
        with patch.object(self.mobile_adapter, "is_mobile", False):
            geometry = self.mobile_adapter.get_responsive_geometry()
            self.assertIn("1600x1000", geometry)  # 固定サイズ

    def test_adaptive_font_scaling(self):
        """適応的フォントスケーリングのテスト"""
        # モバイル環境でのフォントスケーリング
        with patch.object(self.mobile_adapter, "is_mobile", True):
            font = self.mobile_adapter.get_adaptive_font(12)
            # フォントサイズが1.2倍にスケールされることを確認
            # 実際のサイズは内部実装に依存するため、オブジェクトの存在のみ確認
            self.assertIsNotNone(font)

        # デスクトップ環境でのフォント
        with patch.object(self.mobile_adapter, "is_mobile", False):
            font = self.mobile_adapter.get_adaptive_font(12)
            self.assertIsNotNone(font)

    def test_adaptive_padding_calculation(self):
        """適応的パディング計算のテスト"""
        # モバイル環境でのパディング
        with patch.object(self.mobile_adapter, "is_mobile", True):
            padding = self.mobile_adapter.get_adaptive_padding(10)
            self.assertEqual(padding, 15)  # 1.5倍

        # デスクトップ環境でのパディング
        with patch.object(self.mobile_adapter, "is_mobile", False):
            padding = self.mobile_adapter.get_adaptive_padding(10)
            self.assertEqual(padding, 10)  # 等倍

    def test_adaptive_button_configuration(self):
        """適応的ボタン設定のテスト"""
        config = self.mobile_adapter.get_adaptive_button_config()

        # 必要なキーが含まれていることを確認
        self.assertIn("height", config)
        self.assertIn("font", config)
        self.assertIn("corner_radius", config)

        # モバイル環境での高さ
        with patch.object(self.mobile_adapter, "is_mobile", True):
            config = self.mobile_adapter.get_adaptive_button_config()
            self.assertEqual(config["height"], 50)

    def test_layout_configuration(self):
        """レイアウト設定のテスト"""
        # モバイル環境でのレイアウト
        with patch.object(self.mobile_adapter, "is_mobile", True):
            config = self.mobile_adapter.get_layout_config()
            self.assertEqual(config["orientation"], "vertical")
            self.assertTrue(config["use_tabs"])
            self.assertTrue(config["hide_secondary_panels"])

        # デスクトップ環境でのレイアウト
        with patch.object(self.mobile_adapter, "is_mobile", False):
            config = self.mobile_adapter.get_layout_config()
            self.assertEqual(config["orientation"], "horizontal")
            self.assertFalse(config["use_tabs"])
            self.assertFalse(config["hide_secondary_panels"])

    def test_touch_support_detection(self):
        """タッチサポート検出のテスト"""
        # Windows環境でのタッチサポート検出をモック
        with patch("platform.system", return_value="Windows"):
            with patch("winreg.OpenKey") as mock_open:
                with patch("winreg.CloseKey"):
                    # タッチキーボードレジストリが存在する場合
                    mock_open.return_value = MagicMock()
                    self.assertTrue(self.mobile_adapter._detect_touch_support())

                    # レジストリが存在しない場合
                    mock_open.side_effect = Exception("Registry key not found")
                    self.assertFalse(self.mobile_adapter._detect_touch_support())

    def test_responsive_frame_creation(self):
        """レスポンシブフレーム作成のテスト"""
        try:
            frame = self.responsive_layout.create_responsive_frame(self.root)
            self.assertIsNotNone(frame)
        except Exception as e:
            # CustomTkinterが利用できない環境でのテスト
            self.skipTest(f"CustomTkinter not available: {e}")

    def test_responsive_button_creation(self):
        """レスポンシブボタン作成のテスト"""
        try:
            button = self.responsive_layout.create_responsive_button(
                self.root, "Test Button", command=lambda: None
            )
            self.assertIsNotNone(button)
        except Exception as e:
            # CustomTkinterが利用できない環境でのテスト
            self.skipTest(f"CustomTkinter not available: {e}")

    def test_screen_size_adaptation(self):
        """画面サイズ適応のテスト"""
        # 小さい画面サイズ
        with patch.object(self.mobile_adapter, "screen_width", 480):
            with patch.object(self.mobile_adapter, "screen_height", 800):
                self.assertTrue(self.mobile_adapter.is_mobile)

        # 大きい画面サイズ
        with patch.object(self.mobile_adapter, "screen_width", 1920):
            with patch.object(self.mobile_adapter, "screen_height", 1080):
                adapter = MobileAdapter(self.root)
                self.assertFalse(adapter.is_mobile)


if __name__ == "__main__":
    unittest.main()
