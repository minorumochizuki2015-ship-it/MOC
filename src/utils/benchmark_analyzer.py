#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ベンチマークデータ分析ツール
ファインチューニング用データの分析・可視化
"""

import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
import pandas as pd


class BenchmarkAnalyzer:
    """ベンチマークデータを分析するクラス"""

    def __init__(self, data_dir: str = "data/logs/benchmarks"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def load_benchmark_data(self, days: int = 7) -> List[Dict[str, Any]]:
        """指定日数分のベンチマークデータを読み込み"""
        cutoff_date = datetime.now() - timedelta(days=days)
        all_data = []

        # 日別ファイルを読み込み
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            file_path = (
                self.data_dir / f"benchmark_data_{date.strftime('%Y%m%d')}.jsonl"
            )

            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            # 日付フィルタリング
                            if datetime.fromisoformat(data["timestamp"]) >= cutoff_date:
                                all_data.append(data)
                        except (json.JSONDecodeError, KeyError):
                            continue

        return all_data

    def analyze_performance_trends(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """パフォーマンストレンドを分析"""
        if not data:
            return {"error": "No data available"}

        # データを時系列でソート
        data.sort(key=lambda x: x["timestamp"])

        # 基本統計
        durations = [d["duration"] for d in data if d.get("status") == "completed"]
        tokens_per_second = [
            d["tokens_per_second"] for d in data if d.get("status") == "completed"
        ]
        tokens_generated = [
            d["tokens_generated"] for d in data if d.get("status") == "completed"
        ]

        if not durations:
            return {"error": "No completed requests found"}

        # 時系列分析
        hourly_stats = {}
        for item in data:
            if item.get("status") != "completed":
                continue

            hour = datetime.fromisoformat(item["timestamp"]).strftime("%Y-%m-%d %H:00")
            if hour not in hourly_stats:
                hourly_stats[hour] = {
                    "count": 0,
                    "durations": [],
                    "tokens_per_second": [],
                    "tokens_generated": [],
                }

            hourly_stats[hour]["count"] += 1
            hourly_stats[hour]["durations"].append(item["duration"])
            hourly_stats[hour]["tokens_per_second"].append(item["tokens_per_second"])
            hourly_stats[hour]["tokens_generated"].append(item["tokens_generated"])

        # 時間別平均計算
        hourly_averages = {}
        for hour, stats in hourly_stats.items():
            hourly_averages[hour] = {
                "avg_duration": statistics.mean(stats["durations"]),
                "avg_tokens_per_second": statistics.mean(stats["tokens_per_second"]),
                "avg_tokens_generated": statistics.mean(stats["tokens_generated"]),
                "request_count": stats["count"],
            }

        return {
            "total_requests": len(data),
            "completed_requests": len(durations),
            "error_rate": (len(data) - len(durations)) / len(data) if data else 0,
            "overall_stats": {
                "avg_duration": statistics.mean(durations),
                "median_duration": statistics.median(durations),
                "min_duration": min(durations),
                "max_duration": max(durations),
                "avg_tokens_per_second": statistics.mean(tokens_per_second),
                "median_tokens_per_second": statistics.median(tokens_per_second),
                "avg_tokens_generated": statistics.mean(tokens_generated),
                "total_tokens_generated": sum(tokens_generated),
            },
            "hourly_trends": hourly_averages,
        }

    def analyze_model_performance(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """モデル別パフォーマンスを分析"""
        model_stats = {}

        for item in data:
            if item.get("status") != "completed":
                continue

            model_id = item.get("model_id", "unknown")
            if model_id not in model_stats:
                model_stats[model_id] = {
                    "count": 0,
                    "durations": [],
                    "tokens_per_second": [],
                    "tokens_generated": [],
                    "task_types": set(),
                }

            model_stats[model_id]["count"] += 1
            model_stats[model_id]["durations"].append(item["duration"])
            model_stats[model_id]["tokens_per_second"].append(item["tokens_per_second"])
            model_stats[model_id]["tokens_generated"].append(item["tokens_generated"])
            if item.get("task_type"):
                model_stats[model_id]["task_types"].add(item["task_type"])

        # 統計計算
        model_analysis = {}
        for model_id, stats in model_stats.items():
            model_analysis[model_id] = {
                "request_count": stats["count"],
                "avg_duration": statistics.mean(stats["durations"]),
                "avg_tokens_per_second": statistics.mean(stats["tokens_per_second"]),
                "avg_tokens_generated": statistics.mean(stats["tokens_generated"]),
                "task_types": list(stats["task_types"]),
                "efficiency_score": statistics.mean(stats["tokens_per_second"])
                / statistics.mean(stats["durations"]),
            }

        return model_analysis

    def generate_performance_report(self, days: int = 7) -> str:
        """パフォーマンスレポートを生成"""
        data = self.load_benchmark_data(days)

        if not data:
            return "データが見つかりません。"

        # 分析実行
        trends = self.analyze_performance_trends(data)
        model_perf = self.analyze_model_performance(data)

        # レポート生成
        report = []
        report.append("=" * 60)
        report.append(f"ベンチマーク分析レポート ({days}日間)")
        report.append("=" * 60)
        report.append("")

        # 基本統計
        if "error" not in trends:
            overall = trends["overall_stats"]
            report.append("📊 基本統計")
            report.append(f"  総リクエスト数: {trends['total_requests']}")
            report.append(f"  完了リクエスト数: {trends['completed_requests']}")
            report.append(f"  エラー率: {trends['error_rate']:.2%}")
            report.append(f"  平均応答時間: {overall['avg_duration']:.3f}秒")
            report.append(f"  中央値応答時間: {overall['median_duration']:.3f}秒")
            report.append(
                f"  平均推論速度: {overall['avg_tokens_per_second']:.2f} tok/s"
            )
            report.append(f"  総生成トークン数: {overall['total_tokens_generated']:,}")
            report.append("")

        # モデル別分析
        if model_perf:
            report.append("🤖 モデル別パフォーマンス")
            for model_id, stats in model_perf.items():
                report.append(f"  {model_id}:")
                report.append(f"    リクエスト数: {stats['request_count']}")
                report.append(f"    平均応答時間: {stats['avg_duration']:.3f}秒")
                report.append(
                    f"    平均推論速度: {stats['avg_tokens_per_second']:.2f} tok/s"
                )
                report.append(f"    効率スコア: {stats['efficiency_score']:.2f}")
                report.append(f"    タスクタイプ: {', '.join(stats['task_types'])}")
                report.append("")

        # 推奨事項
        report.append("💡 推奨事項")
        if "error" not in trends:
            avg_speed = trends["overall_stats"]["avg_tokens_per_second"]
            if avg_speed < 5:
                report.append(
                    "  - 推論速度が遅いです。GPU設定の最適化を検討してください。"
                )
            elif avg_speed < 10:
                report.append(
                    "  - 推論速度は中程度です。さらなる最適化の余地があります。"
                )
            else:
                report.append("  - 推論速度は良好です。")

        if trends.get("error_rate", 0) > 0.1:
            report.append(
                "  - エラー率が高いです。サーバー設定の見直しを検討してください。"
            )

        report.append(
            "  - 定期的なベンチマーク実行でパフォーマンスを監視してください。"
        )
        report.append("")

        return "\n".join(report)

    def export_training_dataset(
        self, output_file: str = "data/training_dataset.jsonl"
    ) -> int:
        """ファインチューニング用データセットをエクスポート"""
        data = self.load_benchmark_data(days=30)  # 30日分

        training_data = []
        for item in data:
            if item.get("status") == "completed" and not item.get("error"):
                training_data.append(
                    {
                        "prompt": item["prompt"],
                        "response": item["response"],
                        "model_id": item["model_id"],
                        "task_type": item.get("task_type"),
                        "performance_metrics": {
                            "duration": item["duration"],
                            "tokens_generated": item["tokens_generated"],
                            "tokens_per_second": item["tokens_per_second"],
                        },
                    }
                )

        # ファイル保存
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            for item in training_data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

        return len(training_data)


# 便利関数
def generate_performance_report(days: int = 7) -> str:
    """パフォーマンスレポートを生成する便利関数"""
    analyzer = BenchmarkAnalyzer()
    return analyzer.generate_performance_report(days)


def export_training_data(output_file: str = "data/training_dataset.jsonl") -> int:
    """ファインチューニング用データをエクスポートする便利関数"""
    analyzer = BenchmarkAnalyzer()
    return analyzer.export_training_dataset(output_file)
