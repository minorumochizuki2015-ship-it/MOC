#!/usr/bin/env python3
"""パフォーマンス最適化のテスト"""

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.core.performance_optimizer import (
    AdvancedCache,
    AsyncProcessor,
    PerformanceOptimizer,
)


class TestPerformanceOptimization(unittest.TestCase):
    """パフォーマンス最適化のテストクラス"""

    def setUp(self):
        """テストセットアップ"""
        self.cache = AdvancedCache(max_size=100, ttl_seconds=60)
        self.async_processor = AsyncProcessor(max_workers=2)
        self.optimizer = PerformanceOptimizer()

    def test_cache_basic_operations(self):
        """キャッシュの基本操作テスト"""
        # 設定と取得
        self.cache.set("test_key", "test_value")
        self.assertEqual(self.cache.get("test_key"), "test_value")

        # 存在しないキー
        self.assertIsNone(self.cache.get("nonexistent_key"))

    def test_cache_lru_eviction(self):
        """LRU削除のテスト"""
        # キャッシュサイズを超えて設定
        for i in range(150):  # max_size=100を超える
            self.cache.set(f"key_{i}", f"value_{i}")

        # 古いエントリが削除されていることを確認
        self.assertIsNone(self.cache.get("key_0"))
        self.assertEqual(self.cache.get("key_149"), "value_149")

    def test_cache_ttl_expiration(self):
        """TTL期限切れのテスト"""
        # 短いTTLでキャッシュを作成
        short_cache = AdvancedCache(max_size=10, ttl_seconds=0.1)
        short_cache.set("expire_key", "expire_value")

        # すぐに取得できることを確認
        self.assertEqual(short_cache.get("expire_key"), "expire_value")

        # TTL期限切れ後は取得できないことを確認
        time.sleep(0.2)
        self.assertIsNone(short_cache.get("expire_key"))

    def test_cache_statistics(self):
        """キャッシュ統計のテスト"""
        # ヒットとミスを発生させる
        self.cache.set("hit_key", "hit_value")
        self.cache.get("hit_key")  # ヒット
        self.cache.get("miss_key")  # ミス

        stats = self.cache.get_stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)
        self.assertEqual(stats["hit_rate"], 0.5)

    def test_async_processor_background_task(self):
        """非同期処理のバックグラウンドタスクテスト"""

        def slow_task():
            time.sleep(0.1)
            return "task_result"

        # バックグラウンドタスクを投入
        self.async_processor.submit_background_task("test_task", slow_task)

        # すぐには結果が取得できない
        self.assertIsNone(
            self.async_processor.get_task_result("test_task", timeout=0.01)
        )

        # 十分待てば結果が取得できる
        time.sleep(0.2)
        result = self.async_processor.get_task_result("test_task", timeout=1.0)
        self.assertEqual(result, "task_result")

    def test_performance_optimizer_caching(self):
        """パフォーマンス最適化のキャッシュテスト"""
        call_count = 0

        def mock_request(value):
            nonlocal call_count
            call_count += 1
            return f"result_{value}"

        # 同じキーで複数回呼び出し
        result1 = self.optimizer.optimize_request(mock_request, "cache_key_1", "test")
        result2 = self.optimizer.optimize_request(mock_request, "cache_key_1", "test")

        # 結果は同じだが、関数は1回だけ呼ばれる
        self.assertEqual(result1, result2)
        self.assertEqual(call_count, 1)

    def test_performance_metrics_collection(self):
        """パフォーマンスメトリクス収集のテスト"""

        def mock_request():
            time.sleep(0.01)  # 10ms の処理時間をシミュレート
            return "result"

        # 複数回リクエストを実行
        for i in range(5):
            self.optimizer.optimize_request(mock_request, f"key_{i}")

        report = self.optimizer.get_performance_report()

        # メトリクスが正しく収集されていることを確認
        self.assertEqual(report["performance"]["total_requests"], 5)
        self.assertGreater(
            float(report["performance"]["avg_response_time"].replace("s", "")), 0
        )

    def test_concurrent_cache_access(self):
        """並行キャッシュアクセスのテスト"""

        def cache_worker(worker_id):
            for i in range(100):
                key = f"worker_{worker_id}_key_{i}"
                value = f"worker_{worker_id}_value_{i}"
                self.cache.set(key, value)
                retrieved = self.cache.get(key)
                self.assertEqual(retrieved, value)

        # 複数スレッドで並行アクセス
        threads = []
        for worker_id in range(3):
            thread = threading.Thread(target=cache_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()

        # 全スレッドの完了を待機
        for thread in threads:
            thread.join()

        # データ競合が発生していないことを確認
        stats = self.cache.get_stats()
        self.assertGreater(stats["size"], 0)

    def test_response_time_threshold(self):
        """応答時間閾値のテスト"""

        def fast_request():
            return "fast_result"

        def slow_request():
            time.sleep(0.3)  # 300ms
            return "slow_result"

        # 高速リクエスト
        start_time = time.time()
        self.optimizer.optimize_request(fast_request, "fast_key")
        fast_time = time.time() - start_time

        # 低速リクエスト
        start_time = time.time()
        self.optimizer.optimize_request(slow_request, "slow_key")
        slow_time = time.time() - start_time

        # 高速リクエストは200ms以内
        self.assertLess(fast_time, 0.2)
        # 低速リクエストは200ms超
        self.assertGreater(slow_time, 0.2)


if __name__ == "__main__":
    unittest.main()
