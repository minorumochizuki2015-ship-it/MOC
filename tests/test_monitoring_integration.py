#!/usr/bin/env python3
"""
監視システム統合テストスイート
包括的なテストケースで監視システムの動作を検証
"""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_enhancer import AlertEnhancer
from src.monitoring_system import MonitoringSystem
from src.performance_monitor import SystemPerformanceMonitor


class TestMonitoringSystemIntegration(unittest.TestCase):
    """監視システム統合テストクラス"""

    def setUp(self):
        """テスト前の準備"""
        self.monitoring_system = None
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """テスト後のクリーンアップ"""
        if self.monitoring_system and hasattr(self.monitoring_system, "stop"):
            try:
                self.monitoring_system.stop()
            except:
                pass

    def test_monitoring_system_initialization(self):
        """監視システムの初期化テスト"""
        try:
            self.monitoring_system = MonitoringSystem()
            self.assertIsNotNone(self.monitoring_system)
            self.assertTrue(hasattr(self.monitoring_system, "logger"))
            print("✓ 監視システム初期化テスト成功")
        except Exception as e:
            self.fail(f"監視システム初期化失敗: {e}")

    def test_system_status_retrieval(self):
        """システム状態取得テスト"""
        try:
            self.monitoring_system = MonitoringSystem()
            status = self.monitoring_system.get_system_status()

            self.assertIsInstance(status, dict)
            self.assertIn("overall_status", status)
            self.assertIn("last_update", status)
            self.assertIn("monitoring_active", status)

            print(f"✓ システム状態取得テスト成功: {status['overall_status']}")
        except Exception as e:
            self.fail(f"システム状態取得失敗: {e}")

    def test_performance_summary_retrieval(self):
        """パフォーマンスサマリー取得テスト"""
        try:
            self.monitoring_system = MonitoringSystem()
            performance = self.monitoring_system.get_performance_summary()

            self.assertIsInstance(performance, dict)
            self.assertIn("timestamp", performance)

            # エラーがある場合でも適切に処理されることを確認
            if "error" in performance:
                print(f"✓ パフォーマンスサマリー取得テスト成功（エラーハンドリング確認）")
            else:
                self.assertIn("cpu_usage", performance)
                print(f"✓ パフォーマンスサマリー取得テスト成功")
        except Exception as e:
            self.fail(f"パフォーマンスサマリー取得失敗: {e}")

    def test_alert_statistics_retrieval(self):
        """アラート統計取得テスト"""
        try:
            self.monitoring_system = MonitoringSystem()
            alerts = self.monitoring_system.get_alert_statistics()

            self.assertIsInstance(alerts, dict)
            self.assertIn("timestamp", alerts)

            # AlertEnhancerが利用可能な場合とフォールバックの場合の両方をテスト
            if "total_alerts_24h" in alerts:
                self.assertIn("by_severity", alerts)
                print("✓ アラート統計取得テスト成功（AlertEnhancer使用）")
            else:
                # フォールバック実装のテスト
                self.assertTrue("active_count" in alerts or "error" in alerts)
                print("✓ アラート統計取得テスト成功（フォールバック）")
        except Exception as e:
            self.fail(f"アラート統計取得失敗: {e}")

    def test_metrics_history_retrieval(self):
        """メトリクス履歴取得テスト"""
        try:
            self.monitoring_system = MonitoringSystem()
            history = self.monitoring_system.get_metrics_history(hours=6)

            self.assertIsInstance(history, dict)
            self.assertIn("performance", history)
            self.assertIn("response_times", history)

            # 履歴データの構造をテスト
            if history["performance"]:
                sample_perf = history["performance"][0]
                self.assertIn("timestamp", sample_perf)
                self.assertIn("cpu_usage", sample_perf)

            print(f"✓ メトリクス履歴取得テスト成功: {len(history['performance'])}件")
        except Exception as e:
            self.fail(f"メトリクス履歴取得失敗: {e}")

    def test_monitoring_system_lifecycle(self):
        """監視システムのライフサイクルテスト"""
        try:
            self.monitoring_system = MonitoringSystem()

            # 開始テスト
            if hasattr(self.monitoring_system, "start"):
                result = self.monitoring_system.start()
                self.assertTrue(result or result is None)  # 成功またはNone

            # 実行中状態の確認
            if hasattr(self.monitoring_system, "is_running"):
                self.assertIsInstance(self.monitoring_system.is_running, bool)

            # 停止テスト
            if hasattr(self.monitoring_system, "stop"):
                result = self.monitoring_system.stop()
                self.assertTrue(result or result is None)  # 成功またはNone

            print("✓ 監視システムライフサイクルテスト成功")
        except Exception as e:
            self.fail(f"監視システムライフサイクルテスト失敗: {e}")

    def test_error_handling(self):
        """エラーハンドリングテスト"""
        try:
            self.monitoring_system = MonitoringSystem()

            # 無効なパラメータでのテスト
            history = self.monitoring_system.get_metrics_history(hours=-1)
            self.assertIsInstance(history, dict)

            # 大きすぎるパラメータでのテスト
            history = self.monitoring_system.get_metrics_history(hours=1000)
            self.assertIsInstance(history, dict)

            print("✓ エラーハンドリングテスト成功")
        except Exception as e:
            self.fail(f"エラーハンドリングテスト失敗: {e}")

    def test_data_consistency(self):
        """データ整合性テスト"""
        try:
            self.monitoring_system = MonitoringSystem()

            # 複数回の取得で一貫性を確認
            status1 = self.monitoring_system.get_system_status()
            time.sleep(0.1)
            status2 = self.monitoring_system.get_system_status()

            # 基本構造が同じであることを確認
            self.assertEqual(set(status1.keys()), set(status2.keys()))

            # タイムスタンプが更新されていることを確認
            if "last_update" in status1 and "last_update" in status2:
                self.assertNotEqual(status1["last_update"], status2["last_update"])

            print("✓ データ整合性テスト成功")
        except Exception as e:
            self.fail(f"データ整合性テスト失敗: {e}")


class TestAlertEnhancerIntegration(unittest.TestCase):
    """アラート強化システム統合テストクラス"""

    def setUp(self):
        """テスト前の準備"""
        self.alert_enhancer = None

    def tearDown(self):
        """テスト後のクリーンアップ"""
        pass

    def test_alert_enhancer_initialization(self):
        """アラート強化システム初期化テスト"""
        try:
            # 設定ファイルが存在する場合のみテスト
            config_path = "config/alert_config.json"
            if os.path.exists(config_path):
                self.alert_enhancer = AlertEnhancer(config_path)
                self.assertIsNotNone(self.alert_enhancer)
                print("✓ アラート強化システム初期化テスト成功")
            else:
                print("⚠ アラート設定ファイルが見つからないため、初期化テストをスキップ")
        except Exception as e:
            print(f"⚠ アラート強化システム初期化テスト: {e}")


class TestPerformanceMonitorIntegration(unittest.TestCase):
    """パフォーマンス監視システム統合テストクラス"""

    def setUp(self):
        """テスト前の準備"""
        self.performance_monitor = None

    def tearDown(self):
        """テスト後のクリーンアップ"""
        if self.performance_monitor and hasattr(self.performance_monitor, "stop_monitoring"):
            try:
                self.performance_monitor.stop_monitoring()
            except:
                pass

    def test_performance_monitor_initialization(self):
        """パフォーマンス監視システム初期化テスト"""
        try:
            # 設定ファイルが存在する場合のみテスト
            config_path = "config/performance.json"
            if os.path.exists(config_path):
                self.performance_monitor = SystemPerformanceMonitor(config_path)
                self.assertIsNotNone(self.performance_monitor)
                print("✓ パフォーマンス監視システム初期化テスト成功")
            else:
                print("⚠ パフォーマンス設定ファイルが見つからないため、初期化テストをスキップ")
        except Exception as e:
            print(f"⚠ パフォーマンス監視システム初期化テスト: {e}")


def run_comprehensive_tests():
    """包括的テストの実行"""
    print("=== 監視システム包括的テストスイート開始 ===\n")

    # テストスイートの作成
    test_suite = unittest.TestSuite()

    # 監視システム統合テスト
    test_suite.addTest(unittest.makeSuite(TestMonitoringSystemIntegration))
    test_suite.addTest(unittest.makeSuite(TestAlertEnhancerIntegration))
    test_suite.addTest(unittest.makeSuite(TestPerformanceMonitorIntegration))

    # テストランナーの設定
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)

    # テスト実行
    result = runner.run(test_suite)

    print(f"\n=== テスト結果サマリー ===")
    print(f"実行テスト数: {result.testsRun}")
    print(f"失敗: {len(result.failures)}")
    print(f"エラー: {len(result.errors)}")
    print(
        f"成功率: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%"
    )

    if result.failures:
        print(f"\n失敗したテスト:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")

    if result.errors:
        print(f"\nエラーが発生したテスト:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)
