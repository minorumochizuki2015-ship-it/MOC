#!/usr/bin/env python3
"""
包括的なパフォーマンステストスイート

システム全体のパフォーマンス測定、ベンチマーク、負荷テストを実行します。
"""

import asyncio
import gc
import json
import os
import statistics
import sys
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import psutil
import pytest
import requests

# テスト対象のエンドポイント
ENDPOINTS = [
    ("http://127.0.0.1:5000/", "GET"),
    ("http://127.0.0.1:5000/api/status", "GET"),
    ("http://127.0.0.1:5000/api/metrics", "GET"),
    ("http://127.0.0.1:5000/api/system-health", "GET"),
    ("http://127.0.0.1:5000/security", "GET"),
    ("http://127.0.0.1:5000/api/security/status", "GET"),
]

# パフォーマンス基準値
PERFORMANCE_THRESHOLDS = {
    "response_time_p95": 0.5,  # 500ms
    "response_time_p99": 1.0,  # 1s
    "error_rate_max": 0.01,  # 1%
    "cpu_usage_max": 80.0,  # 80%
    "memory_usage_max": 85.0,  # 85%
    "throughput_min": 100,  # 100 req/s
}


class PerformanceMetrics:
    """パフォーマンスメトリクス収集クラス"""

    def __init__(self):
        self.response_times = []
        self.error_count = 0
        self.total_requests = 0
        self.start_time = None
        self.end_time = None
        self.cpu_usage = []
        self.memory_usage = []
        self.memory_peak = 0

    def start_monitoring(self):
        """監視開始"""
        self.start_time = time.perf_counter()
        tracemalloc.start()

    def stop_monitoring(self):
        """監視終了"""
        self.end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.memory_peak = peak / 1024 / 1024  # MB

    def record_request(self, response_time: float, success: bool):
        """リクエスト結果を記録"""
        self.response_times.append(response_time)
        self.total_requests += 1
        if not success:
            self.error_count += 1

    def record_system_metrics(self):
        """システムメトリクスを記録"""
        self.cpu_usage.append(psutil.cpu_percent())
        self.memory_usage.append(psutil.virtual_memory().percent)

    def get_summary(self) -> Dict[str, Any]:
        """メトリクスサマリーを取得"""
        if not self.response_times:
            return {"error": "No data collected"}

        duration = self.end_time - self.start_time if self.end_time else 0

        return {
            "duration_seconds": duration,
            "total_requests": self.total_requests,
            "error_count": self.error_count,
            "error_rate": self.error_count / self.total_requests if self.total_requests > 0 else 0,
            "response_time": {
                "min": min(self.response_times),
                "max": max(self.response_times),
                "mean": statistics.mean(self.response_times),
                "median": statistics.median(self.response_times),
                "p95": (
                    statistics.quantiles(self.response_times, n=100)[94]
                    if len(self.response_times) >= 20
                    else max(self.response_times)
                ),
                "p99": (
                    statistics.quantiles(self.response_times, n=100)[98]
                    if len(self.response_times) >= 20
                    else max(self.response_times)
                ),
            },
            "throughput_rps": self.total_requests / duration if duration > 0 else 0,
            "cpu_usage": {
                "mean": statistics.mean(self.cpu_usage) if self.cpu_usage else 0,
                "max": max(self.cpu_usage) if self.cpu_usage else 0,
            },
            "memory_usage": {
                "mean": statistics.mean(self.memory_usage) if self.memory_usage else 0,
                "max": max(self.memory_usage) if self.memory_usage else 0,
                "peak_mb": self.memory_peak,
            },
        }


class PerformanceTestSuite:
    """パフォーマンステストスイート"""

    def __init__(self):
        self.metrics = PerformanceMetrics()
        self.monitoring_active = False

    def system_monitor_thread(self):
        """システム監視スレッド"""
        while self.monitoring_active:
            self.metrics.record_system_metrics()
            time.sleep(0.1)  # 100ms間隔

    def make_request(
        self, endpoint: str, method: str = "GET", timeout: int = 5
    ) -> Tuple[float, bool]:
        """HTTPリクエストを実行"""
        start_time = time.perf_counter()
        success = False

        try:
            if method.upper() == "GET":
                response = requests.get(endpoint, timeout=timeout)
            else:
                response = requests.request(method, endpoint, timeout=timeout)

            success = 200 <= response.status_code < 300
        except Exception as e:
            print(f"Request failed for {endpoint}: {e}")

        response_time = time.perf_counter() - start_time
        return response_time, success

    def run_single_endpoint_test(
        self, endpoint: str, method: str, iterations: int = 100
    ) -> Dict[str, Any]:
        """単一エンドポイントのテスト"""
        print(f"Testing {endpoint} ({method}) - {iterations} iterations")

        local_metrics = PerformanceMetrics()
        local_metrics.start_monitoring()

        for i in range(iterations):
            response_time, success = self.make_request(endpoint, method)
            local_metrics.record_request(response_time, success)

            if i % 10 == 0:  # 10回ごとにシステムメトリクス記録
                local_metrics.record_system_metrics()

        local_metrics.stop_monitoring()
        return local_metrics.get_summary()

    def run_concurrent_test(
        self, max_workers: int = 10, duration_seconds: int = 30
    ) -> Dict[str, Any]:
        """並行負荷テスト"""
        print(f"Running concurrent test - {max_workers} workers for {duration_seconds}s")

        self.metrics = PerformanceMetrics()
        self.metrics.start_monitoring()
        self.monitoring_active = True

        # システム監視スレッド開始
        monitor_thread = threading.Thread(target=self.system_monitor_thread)
        monitor_thread.start()

        end_time = time.time() + duration_seconds

        def worker():
            while time.time() < end_time:
                endpoint, method = ENDPOINTS[0]  # メインエンドポイントをテスト
                response_time, success = self.make_request(endpoint, method)
                self.metrics.record_request(response_time, success)

        # ワーカースレッド実行
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(worker) for _ in range(max_workers)]

            # 全ワーカー完了まで待機
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Worker error: {e}")

        self.monitoring_active = False
        monitor_thread.join()
        self.metrics.stop_monitoring()

        return self.metrics.get_summary()

    def run_stress_test(
        self, start_workers: int = 1, max_workers: int = 50, step: int = 5
    ) -> List[Dict[str, Any]]:
        """ストレステスト - 段階的に負荷を増加"""
        print(f"Running stress test - {start_workers} to {max_workers} workers")

        results = []

        for workers in range(start_workers, max_workers + 1, step):
            print(f"Testing with {workers} concurrent workers...")
            result = self.run_concurrent_test(max_workers=workers, duration_seconds=10)
            result["concurrent_workers"] = workers
            results.append(result)

            # 短い休憩
            time.sleep(2)

        return results


@pytest.fixture
def performance_suite():
    """パフォーマンステストスイートのフィクスチャ"""
    return PerformanceTestSuite()


class TestPerformanceSuite:
    """パフォーマンステストクラス"""

    def test_single_endpoint_performance(self, performance_suite):
        """単一エンドポイントのパフォーマンステスト"""
        print("\n=== 単一エンドポイントパフォーマンステスト ===")

        results = {}
        for endpoint, method in ENDPOINTS:
            try:
                result = performance_suite.run_single_endpoint_test(endpoint, method, iterations=50)
                results[endpoint] = result

                # 結果表示
                print(f"\n{endpoint}:")
                print(f"  応答時間 P95: {result['response_time']['p95']:.3f}s")
                print(f"  エラー率: {result['error_rate']*100:.2f}%")
                print(f"  スループット: {result['throughput_rps']:.1f} req/s")

                # アサーション
                assert (
                    result["response_time"]["p95"] < PERFORMANCE_THRESHOLDS["response_time_p95"]
                ), f"P95応答時間が基準値を超過: {result['response_time']['p95']:.3f}s > {PERFORMANCE_THRESHOLDS['response_time_p95']}s"

                assert (
                    result["error_rate"] < PERFORMANCE_THRESHOLDS["error_rate_max"]
                ), f"エラー率が基準値を超過: {result['error_rate']*100:.2f}% > {PERFORMANCE_THRESHOLDS['error_rate_max']*100:.2f}%"

            except Exception as e:
                print(f"エンドポイント {endpoint} のテストでエラー: {e}")
                results[endpoint] = {"error": str(e)}

        # 結果をファイルに保存
        self._save_results("single_endpoint_performance", results)
        print("✓ 単一エンドポイントパフォーマンステスト完了")

    def test_concurrent_load(self, performance_suite):
        """並行負荷テスト"""
        print("\n=== 並行負荷テスト ===")

        result = performance_suite.run_concurrent_test(max_workers=20, duration_seconds=30)

        print(f"総リクエスト数: {result['total_requests']}")
        print(f"エラー数: {result['error_count']}")
        print(f"エラー率: {result['error_rate']*100:.2f}%")
        print(f"平均応答時間: {result['response_time']['mean']:.3f}s")
        print(f"P95応答時間: {result['response_time']['p95']:.3f}s")
        print(f"スループット: {result['throughput_rps']:.1f} req/s")
        print(f"平均CPU使用率: {result['cpu_usage']['mean']:.1f}%")
        print(f"平均メモリ使用率: {result['memory_usage']['mean']:.1f}%")

        # アサーション
        assert (
            result["error_rate"] < PERFORMANCE_THRESHOLDS["error_rate_max"]
        ), f"エラー率が基準値を超過: {result['error_rate']*100:.2f}%"

        assert (
            result["throughput_rps"] > PERFORMANCE_THRESHOLDS["throughput_min"]
        ), f"スループットが基準値を下回る: {result['throughput_rps']:.1f} req/s"

        self._save_results("concurrent_load", result)
        print("✓ 並行負荷テスト完了")

    def test_stress_test(self, performance_suite):
        """ストレステスト"""
        print("\n=== ストレステスト ===")

        results = performance_suite.run_stress_test(start_workers=5, max_workers=30, step=5)

        print("\nストレステスト結果:")
        for result in results:
            workers = result["concurrent_workers"]
            throughput = result["throughput_rps"]
            error_rate = result["error_rate"] * 100
            p95 = result["response_time"]["p95"]

            print(
                f"  {workers:2d} workers: {throughput:6.1f} req/s, {error_rate:5.2f}% errors, P95: {p95:.3f}s"
            )

        # 最大スループットを見つける
        max_throughput = max(r["throughput_rps"] for r in results)
        optimal_workers = next(
            r["concurrent_workers"] for r in results if r["throughput_rps"] == max_throughput
        )

        print(
            f"\n最適並行数: {optimal_workers} workers (最大スループット: {max_throughput:.1f} req/s)"
        )

        self._save_results(
            "stress_test",
            {
                "results": results,
                "optimal_workers": optimal_workers,
                "max_throughput": max_throughput,
            },
        )
        print("✓ ストレステスト完了")

    def test_memory_usage_analysis(self):
        """メモリ使用量分析"""
        print("\n=== メモリ使用量分析 ===")

        # ガベージコレクション前のメモリ状況
        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB

        # メモリ集約的な処理をシミュレート
        tracemalloc.start()

        # 大量のリクエストを実行
        suite = PerformanceTestSuite()
        result = suite.run_concurrent_test(max_workers=10, duration_seconds=15)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        peak_memory_mb = peak / 1024 / 1024

        print(f"初期メモリ使用量: {initial_memory:.1f} MB")
        print(f"最終メモリ使用量: {final_memory:.1f} MB")
        print(f"メモリ増加量: {memory_growth:.1f} MB")
        print(f"ピークメモリ使用量: {peak_memory_mb:.1f} MB")

        memory_analysis = {
            "initial_memory_mb": initial_memory,
            "final_memory_mb": final_memory,
            "memory_growth_mb": memory_growth,
            "peak_memory_mb": peak_memory_mb,
            "performance_result": result,
        }

        # メモリリークの検出
        assert memory_growth < 100, f"メモリ使用量の増加が大きすぎます: {memory_growth:.1f} MB"

        self._save_results("memory_analysis", memory_analysis)
        print("✓ メモリ使用量分析完了")

    def _save_results(self, test_name: str, results: Dict[str, Any]):
        """テスト結果をファイルに保存"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"performance_{test_name}_{timestamp}.json"
        filepath = f"C:/Users/User/Trae/ORCH-Next/data/test_results/{filename}"

        # ディレクトリが存在しない場合は作成
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "timestamp": timestamp,
                    "test_name": test_name,
                    "results": results,
                    "thresholds": PERFORMANCE_THRESHOLDS,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        print(f"結果を保存: {filepath}")


if __name__ == "__main__":
    # 直接実行時のテスト
    suite = PerformanceTestSuite()

    print("パフォーマンステストスイート実行開始")
    print("=" * 50)

    # 基本的なパフォーマンステスト
    test_suite = TestPerformanceSuite()

    try:
        test_suite.test_single_endpoint_performance(suite)
        test_suite.test_concurrent_load(suite)
        test_suite.test_stress_test(suite)
        test_suite.test_memory_usage_analysis()

        print("\n" + "=" * 50)
        print("✓ 全パフォーマンステスト完了")

    except Exception as e:
        print(f"\nテスト実行中にエラーが発生: {e}")
        import traceback

        traceback.print_exc()
