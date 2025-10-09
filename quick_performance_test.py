#!/usr/bin/env python3
"""
クイックパフォーマンステスト: 最適なタイムアウト値の導出（短縮版）

効率的に最適なタイムアウト時間を統計的に分析します。
"""

import json
import os
import statistics
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple

# プロジェクトのsrcディレクトリをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import threading

from lock_manager import LockManager, LockPriority, LockRequest


def run_single_test(timeout_seconds: int, worker_count: int = 5) -> Dict:
    """単一のテストを実行"""
    lock_manager = LockManager(":memory:")
    results = []
    execution_times = []

    def acquire_lock_worker(worker_id):
        worker_start = time.time()
        try:
            request = LockRequest(
                resource="perf_test_resource",
                owner=f"worker_{worker_id}",
                priority=LockPriority.MEDIUM,
                ttl_seconds=60,
            )

            lock_info = lock_manager.acquire_lock(request, timeout=timeout_seconds)
            worker_end = time.time()
            worker_time = worker_end - worker_start

            if lock_info:
                results.append({"worker_id": worker_id, "status": "acquired", "time": worker_time})
                time.sleep(0.01)  # 短時間ロック保持
                lock_manager.release_lock(lock_info.resource, lock_info.owner)
            else:
                results.append({"worker_id": worker_id, "status": "timeout", "time": worker_time})

            execution_times.append(worker_time)

        except Exception as e:
            worker_end = time.time()
            worker_time = worker_end - worker_start
            results.append({"worker_id": worker_id, "status": "error", "time": worker_time})
            execution_times.append(worker_time)

    # テスト開始
    test_start = time.time()
    threads = []

    for i in range(worker_count):
        thread = threading.Thread(target=acquire_lock_worker, args=(i,))
        threads.append(thread)
        thread.start()

    # 全スレッド完了を待機
    for thread in threads:
        thread.join()

    test_end = time.time()
    total_time = test_end - test_start

    # 統計計算
    acquired_count = len([r for r in results if r["status"] == "acquired"])
    timeout_count = len([r for r in results if r["status"] == "timeout"])

    return {
        "timeout_seconds": timeout_seconds,
        "total_time": total_time,
        "acquired_count": acquired_count,
        "timeout_count": timeout_count,
        "success_rate": acquired_count / worker_count * 100,
        "avg_execution_time": statistics.mean(execution_times) if execution_times else 0,
        "efficiency_score": (
            (acquired_count / worker_count * 100) / total_time if total_time > 0 else 0
        ),
    }


def main():
    """メイン実行関数"""
    print("🎯 ORCH-Next クイックパフォーマンステスト")
    print(f"開始時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # テスト設定（効率的な範囲に絞る）
    timeout_values = [3, 5, 8, 10, 15, 20, 25, 30]
    iterations = 5  # 各値で5回実行

    print(f"🚀 テスト開始")
    print(f"   タイムアウト値: {timeout_values}")
    print(f"   各値での実行回数: {iterations}")
    print(f"   総テスト回数: {len(timeout_values) * iterations}")
    print()

    all_results = {}

    try:
        for timeout in timeout_values:
            print(f"⏱️  タイムアウト {timeout}秒 でテスト実行中...")
            timeout_results = []

            for i in range(iterations):
                result = run_single_test(timeout)
                timeout_results.append(result)
                print(
                    f"   {i+1}/{iterations}: {result['total_time']:.2f}秒, 効率: {result['efficiency_score']:.2f}"
                )
                time.sleep(0.01)  # 短い間隔

            # 統計計算
            total_times = [r["total_time"] for r in timeout_results]
            efficiency_scores = [r["efficiency_score"] for r in timeout_results]
            success_rates = [r["success_rate"] for r in timeout_results]

            all_results[timeout] = {
                "avg_total_time": statistics.mean(total_times),
                "avg_efficiency_score": statistics.mean(efficiency_scores),
                "avg_success_rate": statistics.mean(success_rates),
                "min_time": min(total_times),
                "max_time": max(total_times),
                "stdev_time": statistics.stdev(total_times) if len(total_times) > 1 else 0,
            }

            print(
                f"   ✅ 完了 - 平均: {all_results[timeout]['avg_total_time']:.2f}秒, "
                f"効率: {all_results[timeout]['avg_efficiency_score']:.2f}"
            )
            print()

        # 結果分析
        print("📊 結果分析中...")

        # 最適値の推奨
        best_efficiency = max(all_results.items(), key=lambda x: x[1]["avg_efficiency_score"])
        fastest = min(all_results.items(), key=lambda x: x[1]["avg_total_time"])
        most_stable = min(all_results.items(), key=lambda x: x[1]["stdev_time"])

        # 結果表示
        print("\n" + "=" * 60)
        print("📈 クイックパフォーマンステスト結果")
        print("=" * 60)

        print(f"\n🏆 推奨タイムアウト値:")
        print(
            f"  最高効率: {best_efficiency[0]}秒 (効率スコア: {best_efficiency[1]['avg_efficiency_score']:.2f})"
        )
        print(f"  最速実行: {fastest[0]}秒 (平均時間: {fastest[1]['avg_total_time']:.2f}秒)")
        print(f"  最安定: {most_stable[0]}秒 (標準偏差: {most_stable[1]['stdev_time']:.3f})")

        print(f"\n📊 詳細統計:")
        print(
            f"{'タイムアウト':<8} {'平均時間':<10} {'効率スコア':<10} {'成功率':<8} {'安定性':<8}"
        )
        print("-" * 50)

        for timeout, data in all_results.items():
            stability = (
                100 - (data["stdev_time"] / data["avg_total_time"] * 100)
                if data["avg_total_time"] > 0
                else 0
            )
            print(
                f"{timeout:<8} {data['avg_total_time']:<10.2f} "
                f"{data['avg_efficiency_score']:<10.2f} {data['avg_success_rate']:<8.1f} "
                f"{stability:<8.1f}"
            )

        # 推奨値の決定
        print(f"\n🎯 総合推奨:")

        # 効率と安定性のバランスを考慮
        balanced_scores = {}
        for timeout, data in all_results.items():
            stability = (
                100 - (data["stdev_time"] / data["avg_total_time"] * 100)
                if data["avg_total_time"] > 0
                else 0
            )
            # 効率スコア * 0.6 + 安定性 * 0.4 でバランススコア計算
            balanced_score = data["avg_efficiency_score"] * 0.6 + stability * 0.4
            balanced_scores[timeout] = balanced_score

        best_balanced = max(balanced_scores.items(), key=lambda x: x[1])

        print(f"  バランス最適: {best_balanced[0]}秒 (バランススコア: {best_balanced[1]:.2f})")
        print(f"  → 効率性と安定性を総合的に考慮した推奨値")

        # 結果保存
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"quick_performance_results_{timestamp}.json"

        output = {
            "timestamp": datetime.now().isoformat(),
            "test_results": all_results,
            "recommendations": {
                "best_efficiency": {
                    "timeout": best_efficiency[0],
                    "score": best_efficiency[1]["avg_efficiency_score"],
                },
                "fastest": {"timeout": fastest[0], "time": fastest[1]["avg_total_time"]},
                "most_stable": {"timeout": most_stable[0], "stdev": most_stable[1]["stdev_time"]},
                "best_balanced": {"timeout": best_balanced[0], "score": best_balanced[1]},
            },
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"\n📁 結果を保存しました: {filename}")
        print(f"\n✅ テスト完了!")

    except KeyboardInterrupt:
        print("\n⚠️  テストが中断されました")
    except Exception as e:
        print(f"\n❌ エラーが発生しました: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
