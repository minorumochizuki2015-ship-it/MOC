#!/usr/bin/env python3
"""
アプリケーションパフォーマンスプロファイリングスクリプト
"""

import cProfile
import io
import os
import pstats
import sys
import time
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.performance_profiler import PerformanceProfiler, ResourceMonitor


def profile_dashboard():
    """ダッシュボードアプリケーションをプロファイリング"""
    print("=== ダッシュボードアプリケーションプロファイリング ===")

    # プロファイラーを初期化
    profiler = PerformanceProfiler()

    # リソースモニターを開始
    monitor = ResourceMonitor()
    monitor.start_monitoring()

    try:
        # ダッシュボードアプリケーションをインポート
        import orch_dashboard

        # プロファイリング開始
        profiler.start_profiling()

        # 短時間実行してプロファイリング
        print("プロファイリング中... (10秒)")
        time.sleep(10)

        # プロファイリング終了
        profile_stats = profiler.stop_profiling()
        memory_stats = profiler.get_memory_stats()

        # 結果を保存
        results_dir = project_root / "data" / "profiling"
        results_dir.mkdir(parents=True, exist_ok=True)

        # プロファイル結果を保存
        with open(results_dir / "dashboard_profile.txt", "w", encoding="utf-8") as f:
            f.write("=== CPU プロファイリング結果 ===\n")
            f.write(f"総実行時間: {profile_stats['total_time']:.4f}秒\n")
            f.write(f"関数呼び出し数: {profile_stats['function_calls']}\n")
            f.write(f"プリミティブ呼び出し数: {profile_stats['primitive_calls']}\n\n")

            f.write("=== トップ関数 (累積時間順) ===\n")
            for func_info in profile_stats["top_functions"]:
                f.write(f"{func_info}\n")

            f.write("\n=== メモリ使用量統計 ===\n")
            f.write(f"現在のメモリ使用量: {memory_stats['current_memory']:.2f} MB\n")
            f.write(f"ピークメモリ使用量: {memory_stats['peak_memory']:.2f} MB\n")

            f.write("\n=== トップメモリ使用箇所 ===\n")
            for mem_info in memory_stats["top_memory"]:
                f.write(f"{mem_info}\n")

        print(f"プロファイリング結果を保存: {results_dir / 'dashboard_profile.txt'}")

    except Exception as e:
        print(f"プロファイリングエラー: {e}")
    finally:
        monitor.stop_monitoring()

        # リソース使用量レポート
        resource_stats = monitor.get_stats()
        print("\n=== リソース使用量統計 ===")
        print(f"平均CPU使用率: {resource_stats['avg_cpu']:.1f}%")
        print(f"平均メモリ使用率: {resource_stats['avg_memory']:.1f}%")
        print(f"ピークメモリ使用量: {resource_stats['peak_memory']:.1f} MB")


def analyze_slow_endpoints():
    """遅いエンドポイントを分析"""
    print("\n=== エンドポイント応答時間分析 ===")

    import statistics

    import requests

    endpoints = [
        "http://127.0.0.1:5001/",
        "http://127.0.0.1:5001/api/status",
        "http://127.0.0.1:5001/security",
        "http://127.0.0.1:5001/api/security/users",
    ]

    results = {}

    for endpoint in endpoints:
        print(f"分析中: {endpoint}")
        times = []

        for i in range(20):
            try:
                start_time = time.time()
                response = requests.get(endpoint, timeout=5)
                end_time = time.time()

                if response.status_code == 200:
                    times.append(end_time - start_time)
                else:
                    print(f"  エラー応答: {response.status_code}")

            except Exception as e:
                print(f"  リクエストエラー: {e}")

        if times:
            results[endpoint] = {
                "avg": statistics.mean(times),
                "median": statistics.median(times),
                "p95": statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times),
                "min": min(times),
                "max": max(times),
            }

    # 結果を表示
    print("\n=== エンドポイント応答時間結果 ===")
    for endpoint, stats in results.items():
        print(f"\n{endpoint}:")
        print(f"  平均: {stats['avg']*1000:.1f}ms")
        print(f"  中央値: {stats['median']*1000:.1f}ms")
        print(f"  P95: {stats['p95']*1000:.1f}ms")
        print(f"  最小: {stats['min']*1000:.1f}ms")
        print(f"  最大: {stats['max']*1000:.1f}ms")

    # 遅いエンドポイントを特定
    slow_endpoints = []
    for endpoint, stats in results.items():
        if stats["p95"] > 0.5:  # 500ms以上
            slow_endpoints.append((endpoint, stats["p95"]))

    if slow_endpoints:
        print("\n=== 最適化が必要なエンドポイント ===")
        for endpoint, p95_time in sorted(slow_endpoints, key=lambda x: x[1], reverse=True):
            print(f"{endpoint}: P95 = {p95_time*1000:.1f}ms")
    else:
        print("\n全エンドポイントが良好なパフォーマンスです。")


def main():
    """メイン実行関数"""
    print("アプリケーションパフォーマンス分析を開始...")

    # ダッシュボードが実行中かチェック
    try:
        import requests

        response = requests.get("http://127.0.0.1:5001/api/status", timeout=2)
        if response.status_code == 200:
            print("ダッシュボードが実行中です。分析を開始します。")

            # エンドポイント分析
            analyze_slow_endpoints()

            # プロファイリング（注意：これは実際のアプリケーションには影響しません）
            print("\n注意: 詳細なプロファイリングには別途設定が必要です。")

        else:
            print("ダッシュボードが応答しません。先にダッシュボードを起動してください。")

    except Exception as e:
        print(f"ダッシュボード接続エラー: {e}")
        print("先にダッシュボードを起動してください: python orch_dashboard.py")


if __name__ == "__main__":
    main()
