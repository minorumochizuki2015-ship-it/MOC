#!/usr/bin/env python3
"""
最終パフォーマンステスト
修正後のダッシュボードの性能を評価
"""

import json
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests


class FinalPerformanceTest:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.results = {}

    def test_endpoint(self, endpoint, num_requests=10):
        """エンドポイントのパフォーマンステスト"""
        url = f"{self.base_url}{endpoint}"
        response_times = []
        errors = 0

        print(f"Testing {endpoint}...")

        for i in range(num_requests):
            try:
                start_time = time.time()
                response = requests.get(url, timeout=10)
                end_time = time.time()

                response_time = (end_time - start_time) * 1000  # ms
                response_times.append(response_time)

                if response.status_code != 200:
                    errors += 1
                    print(f"  Request {i+1}: {response.status_code} - {response_time:.1f}ms")
                else:
                    print(f"  Request {i+1}: OK - {response_time:.1f}ms")

            except Exception as e:
                errors += 1
                print(f"  Request {i+1}: ERROR - {str(e)}")

            time.sleep(0.1)  # 短い間隔

        if response_times:
            avg_time = statistics.mean(response_times)
            p95_time = (
                statistics.quantiles(response_times, n=20)[18]
                if len(response_times) >= 20
                else max(response_times)
            )
            min_time = min(response_times)
            max_time = max(response_times)
        else:
            avg_time = p95_time = min_time = max_time = 0

        return {
            "endpoint": endpoint,
            "total_requests": num_requests,
            "successful_requests": num_requests - errors,
            "errors": errors,
            "avg_response_time_ms": round(avg_time, 2),
            "p95_response_time_ms": round(p95_time, 2),
            "min_response_time_ms": round(min_time, 2),
            "max_response_time_ms": round(max_time, 2),
            "error_rate": round((errors / num_requests) * 100, 2),
        }

    def concurrent_test(self, endpoint, concurrent_users=5, requests_per_user=5):
        """並行負荷テスト"""
        print(
            f"\nConcurrent test for {endpoint} ({concurrent_users} users, {requests_per_user} requests each)..."
        )

        def user_requests(user_id):
            user_times = []
            user_errors = 0

            for i in range(requests_per_user):
                try:
                    start_time = time.time()
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                    end_time = time.time()

                    response_time = (end_time - start_time) * 1000
                    user_times.append(response_time)

                    if response.status_code != 200:
                        user_errors += 1

                except Exception:
                    user_errors += 1

            return user_times, user_errors

        all_times = []
        total_errors = 0

        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(user_requests, i) for i in range(concurrent_users)]

            for future in as_completed(futures):
                times, errors = future.result()
                all_times.extend(times)
                total_errors += errors

        total_requests = concurrent_users * requests_per_user

        if all_times:
            avg_time = statistics.mean(all_times)
            p95_time = (
                statistics.quantiles(all_times, n=20)[18]
                if len(all_times) >= 20
                else max(all_times)
            )
        else:
            avg_time = p95_time = 0

        return {
            "endpoint": endpoint,
            "concurrent_users": concurrent_users,
            "total_requests": total_requests,
            "successful_requests": total_requests - total_errors,
            "errors": total_errors,
            "avg_response_time_ms": round(avg_time, 2),
            "p95_response_time_ms": round(p95_time, 2),
            "error_rate": round((total_errors / total_requests) * 100, 2),
        }

    def run_full_test(self):
        """完全なパフォーマンステストを実行"""
        print("=== 最終パフォーマンステスト開始 ===")
        print(f"テスト対象: {self.base_url}")
        print(f"開始時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # テスト対象エンドポイント
        endpoints = ["/", "/api/status", "/tasks", "/approvals"]

        # 単一リクエストテスト
        print("\n--- 単一リクエストテスト ---")
        sequential_results = []
        for endpoint in endpoints:
            result = self.test_endpoint(endpoint, num_requests=10)
            sequential_results.append(result)
            print(
                f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95"
            )

        # 並行負荷テスト
        print("\n--- 並行負荷テスト ---")
        concurrent_results = []
        for endpoint in ["/", "/api/status"]:  # 主要エンドポイントのみ
            result = self.concurrent_test(endpoint, concurrent_users=5, requests_per_user=5)
            concurrent_results.append(result)
            print(
                f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95"
            )

        # 結果の保存
        final_results = {
            "test_timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "sequential_tests": sequential_results,
            "concurrent_tests": concurrent_results,
            "summary": self.generate_summary(sequential_results, concurrent_results),
        }

        # レポート保存
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"final_performance_report_{timestamp}.json"

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)

        print(f"\n=== テスト完了 ===")
        print(f"レポート保存: {report_file}")

        # サマリー表示
        self.print_summary(final_results["summary"])

        return final_results

    def generate_summary(self, sequential_results, concurrent_results):
        """テスト結果のサマリーを生成"""
        # 最も遅いエンドポイント
        slowest_seq = max(sequential_results, key=lambda x: x["avg_response_time_ms"])
        fastest_seq = min(sequential_results, key=lambda x: x["avg_response_time_ms"])

        # エラー率
        total_errors = sum(r["errors"] for r in sequential_results)
        total_requests = sum(r["total_requests"] for r in sequential_results)
        overall_error_rate = (total_errors / total_requests) * 100 if total_requests > 0 else 0

        # P95の評価
        high_p95_endpoints = [r for r in sequential_results if r["p95_response_time_ms"] > 1000]

        return {
            "overall_error_rate": round(overall_error_rate, 2),
            "slowest_endpoint": {
                "endpoint": slowest_seq["endpoint"],
                "avg_time_ms": slowest_seq["avg_response_time_ms"],
                "p95_time_ms": slowest_seq["p95_response_time_ms"],
            },
            "fastest_endpoint": {
                "endpoint": fastest_seq["endpoint"],
                "avg_time_ms": fastest_seq["avg_response_time_ms"],
                "p95_time_ms": fastest_seq["p95_response_time_ms"],
            },
            "high_p95_endpoints": len(high_p95_endpoints),
            "performance_grade": self.calculate_grade(sequential_results),
            "recommendations": self.generate_recommendations(sequential_results),
        }

    def calculate_grade(self, results):
        """パフォーマンスグレードを計算"""
        avg_p95 = statistics.mean([r["p95_response_time_ms"] for r in results])

        if avg_p95 < 200:
            return "A"
        elif avg_p95 < 500:
            return "B"
        elif avg_p95 < 1000:
            return "C"
        elif avg_p95 < 2000:
            return "D"
        else:
            return "F"

    def generate_recommendations(self, results):
        """改善提案を生成"""
        recommendations = []

        for result in results:
            if result["p95_response_time_ms"] > 2000:
                recommendations.append(
                    f"{result['endpoint']}: 重大なパフォーマンス問題 (P95: {result['p95_response_time_ms']}ms)"
                )
            elif result["p95_response_time_ms"] > 1000:
                recommendations.append(
                    f"{result['endpoint']}: パフォーマンス改善が必要 (P95: {result['p95_response_time_ms']}ms)"
                )

            if result["error_rate"] > 5:
                recommendations.append(
                    f"{result['endpoint']}: エラー率が高い ({result['error_rate']}%)"
                )

        if not recommendations:
            recommendations.append("パフォーマンスは良好です")

        return recommendations

    def print_summary(self, summary):
        """サマリーを表示"""
        print(f"\n=== パフォーマンスサマリー ===")
        print(f"総合エラー率: {summary['overall_error_rate']}%")
        print(f"パフォーマンスグレード: {summary['performance_grade']}")
        print(
            f"最も遅いエンドポイント: {summary['slowest_endpoint']['endpoint']} ({summary['slowest_endpoint']['p95_time_ms']}ms P95)"
        )
        print(
            f"最も速いエンドポイント: {summary['fastest_endpoint']['endpoint']} ({summary['fastest_endpoint']['p95_time_ms']}ms P95)"
        )
        print(f"P95 > 1秒のエンドポイント数: {summary['high_p95_endpoints']}")

        print(f"\n=== 改善提案 ===")
        for rec in summary["recommendations"]:
            print(f"- {rec}")


def main():
    """メイン実行"""
    tester = FinalPerformanceTest()

    # サーバーの生存確認
    try:
        response = requests.get(f"{tester.base_url}/api/status", timeout=5)
        print(f"サーバー接続確認: {response.status_code}")
    except Exception as e:
        print(f"サーバーに接続できません: {e}")
        return

    # テスト実行
    results = tester.run_full_test()

    return results


if __name__ == "__main__":
    main()
