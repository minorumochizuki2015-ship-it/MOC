#!/usr/bin/env python3
"""
負荷テストとストレステストツール

Webアプリケーションの負荷テストとストレステストを実行します。
"""

import asyncio
import json
import logging
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import matplotlib.pyplot as plt
import numpy as np
import psutil


class LoadTestResult:
    """負荷テスト結果クラス"""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.error_details = []
        self.throughput_history = []
        self.resource_usage = []

    def add_response(self, response_time: float, success: bool, error: str = None):
        """レスポンス結果を追加"""
        self.total_requests += 1
        self.response_times.append(response_time)

        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error:
                self.error_details.append(
                    {"timestamp": datetime.now(timezone.utc).isoformat(), "error": error}
                )

    def calculate_statistics(self) -> Dict[str, Any]:
        """統計情報を計算"""
        if not self.response_times:
            return {"error": "レスポンスデータがありません"}

        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.end_time and self.start_time
            else 0
        )

        return {
            "duration_seconds": duration,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                (self.successful_requests / self.total_requests) * 100
                if self.total_requests > 0
                else 0
            ),
            "requests_per_second": self.total_requests / duration if duration > 0 else 0,
            "response_time_stats": {
                "min": min(self.response_times),
                "max": max(self.response_times),
                "mean": statistics.mean(self.response_times),
                "median": statistics.median(self.response_times),
                "p95": np.percentile(self.response_times, 95),
                "p99": np.percentile(self.response_times, 99),
            },
            "error_rate": (
                (self.failed_requests / self.total_requests) * 100 if self.total_requests > 0 else 0
            ),
            "unique_errors": len(set(error["error"] for error in self.error_details)),
        }


class LoadTester:
    """負荷テスタークラス"""

    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = None
        self.monitoring = False
        self.monitor_thread = None

        # ログ設定
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # デフォルトエンドポイント
        self.default_endpoints = [
            {"path": "/", "method": "GET", "weight": 40},
            {"path": "/api/status", "method": "GET", "weight": 30},
            {"path": "/security", "method": "GET", "weight": 20},
            {"path": "/api/health", "method": "GET", "weight": 10},
        ]

    async def _make_request(
        self, endpoint: Dict[str, Any], session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        """単一リクエストを実行"""
        start_time = time.time()

        try:
            url = f"{self.base_url}{endpoint['path']}"
            method = endpoint.get("method", "GET")
            headers = endpoint.get("headers", {})
            data = endpoint.get("data")

            async with session.request(method, url, headers=headers, json=data) as response:
                await response.text()  # レスポンスボディを読み込み

                response_time = time.time() - start_time

                return {
                    "success": response.status < 400,
                    "response_time": response_time,
                    "status_code": response.status,
                    "error": None if response.status < 400 else f"HTTP {response.status}",
                }

        except Exception as e:
            response_time = time.time() - start_time
            return {
                "success": False,
                "response_time": response_time,
                "status_code": 0,
                "error": str(e),
            }

    async def run_load_test(
        self,
        concurrent_users: int = 10,
        duration_seconds: int = 60,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        ramp_up_seconds: int = 0,
    ) -> LoadTestResult:
        """負荷テストを実行"""

        endpoints = endpoints or self.default_endpoints
        result = LoadTestResult()
        result.start_time = datetime.now(timezone.utc)

        # リソース監視開始
        self._start_resource_monitoring(result)

        self.logger.info(
            f"負荷テスト開始: {concurrent_users} 同時ユーザー, {duration_seconds} 秒間"
        )

        # セマフォで同時接続数を制御
        semaphore = asyncio.Semaphore(concurrent_users)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=concurrent_users * 2),
        ) as session:

            tasks = []
            end_time = time.time() + duration_seconds

            # ランプアップ処理
            if ramp_up_seconds > 0:
                ramp_up_interval = ramp_up_seconds / concurrent_users
                current_users = 0
            else:
                current_users = concurrent_users

            while time.time() < end_time:
                # ランプアップ中の場合、徐々にユーザー数を増加
                if ramp_up_seconds > 0 and current_users < concurrent_users:
                    if (
                        time.time() - result.start_time.timestamp()
                        >= current_users * ramp_up_interval
                    ):
                        current_users += 1

                # エンドポイントを重みに基づいて選択
                endpoint = self._select_weighted_endpoint(endpoints)

                # タスク作成
                task = asyncio.create_task(
                    self._execute_request_with_semaphore(semaphore, endpoint, session, result)
                )
                tasks.append(task)

                # 適度な間隔を空ける
                await asyncio.sleep(0.1)

                # 完了したタスクをクリーンアップ
                tasks = [task for task in tasks if not task.done()]

            # 残りのタスクを待機
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        result.end_time = datetime.now(timezone.utc)
        self._stop_resource_monitoring()

        self.logger.info("負荷テスト完了")
        return result

    async def _execute_request_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        endpoint: Dict[str, Any],
        session: aiohttp.ClientSession,
        result: LoadTestResult,
    ):
        """セマフォ制御付きリクエスト実行"""
        async with semaphore:
            response_data = await self._make_request(endpoint, session)
            result.add_response(
                response_data["response_time"], response_data["success"], response_data["error"]
            )

    def _select_weighted_endpoint(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """重みに基づいてエンドポイントを選択"""
        total_weight = sum(ep.get("weight", 1) for ep in endpoints)
        random_value = np.random.randint(0, total_weight)

        current_weight = 0
        for endpoint in endpoints:
            current_weight += endpoint.get("weight", 1)
            if random_value < current_weight:
                return endpoint

        return endpoints[0]  # フォールバック

    def _start_resource_monitoring(self, result: LoadTestResult):
        """リソース監視開始"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_resources, args=(result,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def _stop_resource_monitoring(self):
        """リソース監視停止"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_resources(self, result: LoadTestResult):
        """リソース監視ループ"""
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()

                result.resource_usage.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "memory_used_mb": memory.used / 1024 / 1024,
                    }
                )

                time.sleep(1)

            except Exception as e:
                self.logger.error(f"リソース監視エラー: {e}")

    async def run_stress_test(
        self,
        max_users: int = 100,
        step_size: int = 10,
        step_duration: int = 30,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> List[LoadTestResult]:
        """ストレステストを実行"""

        endpoints = endpoints or self.default_endpoints
        results = []

        self.logger.info(f"ストレステスト開始: 最大 {max_users} ユーザー, {step_size} ずつ増加")

        for users in range(step_size, max_users + 1, step_size):
            self.logger.info(f"ステップ {users}/{max_users} ユーザーでテスト実行")

            result = await self.run_load_test(
                concurrent_users=users, duration_seconds=step_duration, endpoints=endpoints
            )

            results.append(result)

            # 統計情報をログ出力
            stats = result.calculate_statistics()
            self.logger.info(
                f"ユーザー数 {users}: RPS={stats['requests_per_second']:.1f}, "
                f"平均応答時間={stats['response_time_stats']['mean']:.3f}s, "
                f"成功率={stats['success_rate']:.1f}%"
            )

            # 失敗率が高い場合は停止
            if stats["success_rate"] < 50:
                self.logger.warning(f"成功率が50%を下回ったため、ストレステストを停止します")
                break

            # 次のステップまで少し待機
            await asyncio.sleep(5)

        self.logger.info("ストレステスト完了")
        return results

    def generate_report(self, results: List[LoadTestResult], output_dir: str):
        """テスト結果レポートを生成"""
        os.makedirs(output_dir, exist_ok=True)

        # JSON レポート
        json_report = {"timestamp": datetime.now(timezone.utc).isoformat(), "test_results": []}

        for i, result in enumerate(results):
            stats = result.calculate_statistics()
            json_report["test_results"].append(
                {
                    "test_index": i,
                    "statistics": stats,
                    "resource_usage_summary": self._summarize_resource_usage(result.resource_usage),
                }
            )

        json_path = os.path.join(output_dir, "load_test_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)

        # グラフ生成
        self._generate_charts(results, output_dir)

        self.logger.info(f"レポートを生成: {output_dir}")

    def _summarize_resource_usage(self, resource_usage: List[Dict[str, Any]]) -> Dict[str, Any]:
        """リソース使用量を要約"""
        if not resource_usage:
            return {}

        cpu_values = [r["cpu_percent"] for r in resource_usage]
        memory_values = [r["memory_percent"] for r in resource_usage]

        return {
            "cpu": {
                "min": min(cpu_values),
                "max": max(cpu_values),
                "mean": statistics.mean(cpu_values),
            },
            "memory": {
                "min": min(memory_values),
                "max": max(memory_values),
                "mean": statistics.mean(memory_values),
            },
        }

    def _generate_charts(self, results: List[LoadTestResult], output_dir: str):
        """パフォーマンスチャートを生成"""
        try:
            # 結果データの準備
            user_counts = list(range(len(results)))
            rps_values = []
            avg_response_times = []
            success_rates = []

            for result in results:
                stats = result.calculate_statistics()
                rps_values.append(stats["requests_per_second"])
                avg_response_times.append(stats["response_time_stats"]["mean"])
                success_rates.append(stats["success_rate"])

            # チャート作成
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))

            # RPS チャート
            ax1.plot(user_counts, rps_values, "b-o")
            ax1.set_title("Requests per Second")
            ax1.set_xlabel("Test Step")
            ax1.set_ylabel("RPS")
            ax1.grid(True)

            # 応答時間チャート
            ax2.plot(user_counts, avg_response_times, "r-o")
            ax2.set_title("Average Response Time")
            ax2.set_xlabel("Test Step")
            ax2.set_ylabel("Response Time (s)")
            ax2.grid(True)

            # 成功率チャート
            ax3.plot(user_counts, success_rates, "g-o")
            ax3.set_title("Success Rate")
            ax3.set_xlabel("Test Step")
            ax3.set_ylabel("Success Rate (%)")
            ax3.grid(True)

            # 応答時間分布（最後のテスト結果）
            if results:
                last_result = results[-1]
                ax4.hist(last_result.response_times, bins=50, alpha=0.7)
                ax4.set_title("Response Time Distribution (Last Test)")
                ax4.set_xlabel("Response Time (s)")
                ax4.set_ylabel("Frequency")
                ax4.grid(True)

            plt.tight_layout()
            chart_path = os.path.join(output_dir, "performance_charts.png")
            plt.savefig(chart_path, dpi=300, bbox_inches="tight")
            plt.close()

            self.logger.info(f"チャートを生成: {chart_path}")

        except Exception as e:
            self.logger.error(f"チャート生成エラー: {e}")


class PerformanceBenchmark:
    """パフォーマンスベンチマーククラス"""

    def __init__(self, base_url: str = "http://localhost:5001"):
        self.load_tester = LoadTester(base_url)

    async def run_comprehensive_test(self, output_dir: str = None) -> Dict[str, Any]:
        """包括的なパフォーマンステストを実行"""
        output_dir = (
            output_dir
            or f"C:/Users/User/Trae/ORCH-Next/data/test_results/perf_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        test_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_test": None,
            "load_test": None,
            "stress_test": None,
            "spike_test": None,
        }

        # 1. ベースラインテスト（軽負荷）
        print("1. ベースラインテスト実行中...")
        baseline_result = await self.load_tester.run_load_test(
            concurrent_users=1, duration_seconds=30
        )
        test_results["baseline_test"] = baseline_result.calculate_statistics()

        # 2. 負荷テスト（通常負荷）
        print("2. 負荷テスト実行中...")
        load_result = await self.load_tester.run_load_test(
            concurrent_users=20, duration_seconds=120, ramp_up_seconds=30
        )
        test_results["load_test"] = load_result.calculate_statistics()

        # 3. ストレステスト（段階的負荷増加）
        print("3. ストレステスト実行中...")
        stress_results = await self.load_tester.run_stress_test(
            max_users=50, step_size=10, step_duration=30
        )
        test_results["stress_test"] = [r.calculate_statistics() for r in stress_results]

        # 4. スパイクテスト（急激な負荷増加）
        print("4. スパイクテスト実行中...")
        spike_result = await self.load_tester.run_load_test(
            concurrent_users=50, duration_seconds=60, ramp_up_seconds=5  # 急激な増加
        )
        test_results["spike_test"] = spike_result.calculate_statistics()

        # レポート生成
        all_results = [baseline_result, load_result] + stress_results + [spike_result]
        self.load_tester.generate_report(all_results, output_dir)

        # 総合結果をJSONで保存
        summary_path = os.path.join(output_dir, "comprehensive_test_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(test_results, f, indent=2, ensure_ascii=False)

        return test_results


# 使用例とテスト
if __name__ == "__main__":

    async def main():
        print("負荷テストツールテスト開始")

        # 基本的な負荷テスト
        tester = LoadTester("http://localhost:5001")

        print("\n基本負荷テスト実行...")
        result = await tester.run_load_test(concurrent_users=5, duration_seconds=30)

        stats = result.calculate_statistics()
        print(f"総リクエスト数: {stats['total_requests']}")
        print(f"成功率: {stats['success_rate']:.1f}%")
        print(f"RPS: {stats['requests_per_second']:.1f}")
        print(f"平均応答時間: {stats['response_time_stats']['mean']:.3f}秒")
        print(f"P95応答時間: {stats['response_time_stats']['p95']:.3f}秒")

        # 包括的テスト
        print("\n包括的パフォーマンステスト実行...")
        benchmark = PerformanceBenchmark("http://localhost:5001")
        comprehensive_results = await benchmark.run_comprehensive_test()

        print("✓ 負荷テストツールテスト完了")

    # イベントループ実行
    asyncio.run(main())
