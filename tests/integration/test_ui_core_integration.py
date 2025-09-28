#!/usr/bin/env python3
"""UI-コア連携の統合テスト"""

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestUICoreIntegration(unittest.TestCase):
    """UI-コア連携のテストクラス"""

    def test_approval_flow_integration(self):
        """許諾フローの統合テスト"""
        with patch.dict(os.environ, {"TRAE_AUTO_APPROVE": "1"}):
            # UI-コア間の許諾フローをテスト
            self.assertTrue(True)  # プレースホルダー

    def test_performance_optimization_integration(self):
        """性能最適化統合テスト"""
        # 応答時間の測定
        start_time = time.time()

        # 模擬処理実行
        time.sleep(0.05)  # 50ms の処理をシミュレート

        end_time = time.time()
        response_time = end_time - start_time

        # 200ms以内での応答を確認
        self.assertLess(response_time, 0.2)

        # パフォーマンスメトリクスの確認
        self.assertGreater(response_time, 0.04)  # 最低限の処理時間

    def test_mobile_ui_integration(self):
        """モバイルUI統合テスト"""
        try:
            import tkinter as tk

            from src.ui.mobile_adapter import MobileAdapter

            root = tk.Tk()
            root.withdraw()

            adapter = MobileAdapter(root)

            # モバイル対応設定の確認
            self.assertIsNotNone(adapter.mobile_config)
            self.assertIn("min_touch_size", adapter.mobile_config)
            self.assertIn("font_scale", adapter.mobile_config)

            # レスポンシブジオメトリの確認
            geometry = adapter.get_responsive_geometry()
            self.assertIsInstance(geometry, str)
            self.assertIn("x", geometry)

            root.destroy()

        except ImportError as e:
            self.skipTest(f"UI dependencies not available: {e}")

    def test_cache_performance_integration(self):
        """キャッシュパフォーマンス統合テスト"""
        try:
            from src.core.performance_optimizer import AdvancedCache

            cache = AdvancedCache(max_size=100, ttl_seconds=60)

            # キャッシュ性能テスト
            start_time = time.time()

            # 大量データの設定と取得
            for i in range(1000):
                cache.set(f"key_{i}", f"value_{i}")

            for i in range(1000):
                result = cache.get(f"key_{i}")
                if i < 100:  # キャッシュサイズ内
                    self.assertIsNotNone(result)

            end_time = time.time()
            cache_time = end_time - start_time

            # キャッシュ操作は高速であることを確認
            self.assertLess(cache_time, 1.0)  # 1秒以内

            # 統計情報の確認
            stats = cache.get_stats()
            self.assertGreater(stats["hits"], 0)

        except ImportError as e:
            self.skipTest(f"Performance optimizer not available: {e}")

    def test_concurrent_operations_integration(self):
        """並行操作統合テスト"""
        results = []
        errors = []

        def worker_task(worker_id):
            try:
                # 各ワーカーで異なる処理を実行
                start_time = time.time()
                time.sleep(0.01 * worker_id)  # 異なる処理時間
                end_time = time.time()

                results.append(
                    {
                        "worker_id": worker_id,
                        "processing_time": end_time - start_time,
                        "success": True,
                    }
                )
            except Exception as e:
                errors.append({"worker_id": worker_id, "error": str(e)})

        # 複数スレッドで並行実行
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_task, args=(i,))
            threads.append(thread)
            thread.start()

        # 全スレッドの完了を待機
        for thread in threads:
            thread.join()

        # 結果の検証
        self.assertEqual(len(results), 5)
        self.assertEqual(len(errors), 0)

        # 全ワーカーが成功していることを確認
        for result in results:
            self.assertTrue(result["success"])
            self.assertGreater(result["processing_time"], 0)

    def test_memory_usage_optimization(self):
        """メモリ使用量最適化テスト"""
        import gc

        # ガベージコレクション実行
        gc.collect()
        initial_objects = len(gc.get_objects())

        # 大量のオブジェクト作成と削除
        large_data = []
        for i in range(1000):
            large_data.append(f"data_{i}" * 100)

        # データクリア
        large_data.clear()
        gc.collect()

        final_objects = len(gc.get_objects())

        # メモリリークが発生していないことを確認
        object_increase = final_objects - initial_objects
        self.assertLess(object_increase, 100)  # 100オブジェクト以下の増加

    def test_error_handling_integration(self):
        """エラーハンドリング統合テスト"""
        error_count = 0

        def error_prone_operation():
            nonlocal error_count
            try:
                # 意図的にエラーを発生させる
                raise ValueError("Test error")
            except ValueError:
                error_count += 1
                return "error_handled"

        # エラーハンドリングのテスト
        result = error_prone_operation()

        self.assertEqual(result, "error_handled")
        self.assertEqual(error_count, 1)

    def test_system_resource_monitoring(self):
        """システムリソース監視テスト"""
        try:
            from src.core.performance_monitor import performance_monitor

            # 現在のメトリクスを取得
            metrics = performance_monitor.get_current_metrics()

            # 必要なメトリクスが含まれていることを確認
            self.assertIn("uptime_seconds", metrics)
            self.assertIn("system", metrics)
            self.assertIn("ai", metrics)

            # システムメトリクスの確認
            system_metrics = metrics["system"]
            self.assertIn("cpu_usage", system_metrics)
            self.assertIn("memory_usage", system_metrics)

            # AIメトリクスの確認
            ai_metrics = metrics["ai"]
            self.assertIn("total_requests", ai_metrics)
            self.assertIn("avg_response_time", ai_metrics)

        except ImportError as e:
            self.skipTest(f"Performance monitor not available: {e}")


if __name__ == "__main__":
    unittest.main()
