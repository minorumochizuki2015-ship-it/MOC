#!/usr/bin/env python3
"""
深層パフォーマンス分析ツール
"""

import asyncio
import cProfile
import io
import json
import os
import pstats
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List

import aiohttp
import psutil
import requests


class DeepPerformanceAnalyzer:
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.results = {}

    def profile_endpoint(self, endpoint: str, duration: int = 10) -> Dict[str, Any]:
        """エンドポイントの詳細プロファイリング"""
        print(f"\n=== {endpoint} の詳細分析 ===")

        # プロファイラーの設定
        profiler = cProfile.Profile()

        response_times = []
        errors = 0
        start_time = time.time()

        def make_request():
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                return response.elapsed.total_seconds(), response.status_code
            except Exception as e:
                return None, 500

        # プロファイリング開始
        profiler.enable()

        while time.time() - start_time < duration:
            elapsed, status = make_request()
            if elapsed is not None and status == 200:
                response_times.append(elapsed)
            else:
                errors += 1
            time.sleep(0.1)

        profiler.disable()

        # プロファイル結果の分析
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s)
        ps.sort_stats("cumulative")
        ps.print_stats(20)
        profile_output = s.getvalue()

        if response_times:
            result = {
                "endpoint": endpoint,
                "total_requests": len(response_times),
                "errors": errors,
                "avg_response_time": statistics.mean(response_times),
                "median_response_time": statistics.median(response_times),
                "p95_response_time": (
                    statistics.quantiles(response_times, n=20)[18]
                    if len(response_times) > 20
                    else max(response_times)
                ),
                "min_response_time": min(response_times),
                "max_response_time": max(response_times),
                "profile_data": profile_output[:1000],  # 最初の1000文字のみ
            }
        else:
            result = {
                "endpoint": endpoint,
                "total_requests": 0,
                "errors": errors,
                "error_message": "すべてのリクエストが失敗",
            }

        return result

    def analyze_system_resources(self, duration: int = 30) -> Dict[str, Any]:
        """システムリソースの詳細分析"""
        print(f"\n=== システムリソース分析 ({duration}秒) ===")

        cpu_samples = []
        memory_samples = []
        disk_samples = []
        network_samples = []

        start_time = time.time()

        while time.time() - start_time < duration:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_samples.append(cpu_percent)

            # メモリ使用率
            memory = psutil.virtual_memory()
            memory_samples.append(memory.percent)

            # ディスクI/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                disk_samples.append(
                    {"read_bytes": disk_io.read_bytes, "write_bytes": disk_io.write_bytes}
                )

            # ネットワークI/O
            network_io = psutil.net_io_counters()
            if network_io:
                network_samples.append(
                    {"bytes_sent": network_io.bytes_sent, "bytes_recv": network_io.bytes_recv}
                )

        return {
            "cpu": {
                "avg": statistics.mean(cpu_samples),
                "max": max(cpu_samples),
                "min": min(cpu_samples),
                "samples": cpu_samples,
            },
            "memory": {
                "avg": statistics.mean(memory_samples),
                "max": max(memory_samples),
                "min": min(memory_samples),
                "samples": memory_samples,
            },
            "disk_io_samples": len(disk_samples),
            "network_io_samples": len(network_samples),
        }

    def concurrent_load_analysis(
        self, endpoint: str, workers: int = 10, duration: int = 30
    ) -> Dict[str, Any]:
        """並行負荷での詳細分析"""
        print(f"\n=== 並行負荷分析: {endpoint} ({workers}ワーカー, {duration}秒) ===")

        response_times = []
        errors = 0
        lock = threading.Lock()

        def worker():
            nonlocal errors
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                    with lock:
                        response_times.append(response.elapsed.total_seconds())
                except Exception:
                    with lock:
                        errors += 1
                time.sleep(0.01)  # 短い間隔

        # ワーカースレッドの開始
        threads = []
        start_time = time.time()

        for _ in range(workers):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        # すべてのスレッドの完了を待機
        for thread in threads:
            thread.join()

        total_time = time.time() - start_time

        if response_times:
            return {
                "endpoint": endpoint,
                "workers": workers,
                "duration": total_time,
                "total_requests": len(response_times),
                "errors": errors,
                "throughput_rps": len(response_times) / total_time,
                "avg_response_time": statistics.mean(response_times),
                "p95_response_time": (
                    statistics.quantiles(response_times, n=20)[18]
                    if len(response_times) > 20
                    else max(response_times)
                ),
                "error_rate": errors / (len(response_times) + errors) * 100,
            }
        else:
            return {
                "endpoint": endpoint,
                "workers": workers,
                "total_requests": 0,
                "errors": errors,
                "error_message": "すべてのリクエストが失敗",
            }

    def memory_leak_detection(self, endpoint: str, iterations: int = 100) -> Dict[str, Any]:
        """メモリリーク検出"""
        print(f"\n=== メモリリーク検出: {endpoint} ===")

        memory_usage = []

        for i in range(iterations):
            # リクエスト前のメモリ使用量
            memory_before = psutil.virtual_memory().percent

            try:
                requests.get(f"{self.base_url}{endpoint}", timeout=5)
            except Exception:
                pass

            # リクエスト後のメモリ使用量
            memory_after = psutil.virtual_memory().percent
            memory_usage.append(memory_after)

            if i % 10 == 0:
                print(f"  反復 {i}: メモリ使用率 {memory_after:.1f}%")

        # メモリ使用量の傾向分析
        if len(memory_usage) > 10:
            first_half = memory_usage[: len(memory_usage) // 2]
            second_half = memory_usage[len(memory_usage) // 2 :]

            avg_first = statistics.mean(first_half)
            avg_second = statistics.mean(second_half)

            memory_increase = avg_second - avg_first

            return {
                "endpoint": endpoint,
                "iterations": iterations,
                "memory_increase": memory_increase,
                "avg_memory_first_half": avg_first,
                "avg_memory_second_half": avg_second,
                "potential_leak": memory_increase > 1.0,  # 1%以上の増加でリーク疑い
                "memory_samples": memory_usage,
            }
        else:
            return {"error": "サンプル数が不足"}

    def generate_comprehensive_report(self) -> str:
        """包括的なレポート生成"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"deep_performance_report_{timestamp}.json"

        print("\n=== 包括的パフォーマンス分析開始 ===")

        # 主要エンドポイントの分析
        endpoints = ["/", "/api/status", "/tasks", "/approvals"]

        analysis_results = {
            "timestamp": timestamp,
            "endpoint_analysis": {},
            "system_resources": {},
            "concurrent_load": {},
            "memory_leak_detection": {},
        }

        # エンドポイント別詳細分析
        for endpoint in endpoints:
            print(f"\n--- {endpoint} の分析中 ---")
            analysis_results["endpoint_analysis"][endpoint] = self.profile_endpoint(endpoint, 15)

        # システムリソース分析
        analysis_results["system_resources"] = self.analyze_system_resources(30)

        # 並行負荷分析
        for endpoint in ["/", "/api/status"]:
            analysis_results["concurrent_load"][endpoint] = self.concurrent_load_analysis(
                endpoint, 15, 20
            )

        # メモリリーク検出
        for endpoint in ["/", "/api/status"]:
            analysis_results["memory_leak_detection"][endpoint] = self.memory_leak_detection(
                endpoint, 50
            )

        # レポート保存
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(analysis_results, f, indent=2, ensure_ascii=False)

        print(f"\n=== 分析完了: {report_file} ===")
        return report_file


def main():
    analyzer = DeepPerformanceAnalyzer()

    # ダッシュボードの稼働確認
    try:
        response = requests.get("http://localhost:5000/", timeout=5)
        print(f"ダッシュボード接続確認: {response.status_code}")
    except Exception as e:
        print(f"ダッシュボードに接続できません: {e}")
        return

    # 包括的分析の実行
    report_file = analyzer.generate_comprehensive_report()

    print(f"\n詳細分析レポートが生成されました: {report_file}")


if __name__ == "__main__":
    main()
