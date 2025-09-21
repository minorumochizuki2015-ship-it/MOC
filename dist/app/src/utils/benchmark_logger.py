#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
推論ベンチマーク記録システム
ファインチューニング用データ収集とログ記録
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil


class BenchmarkLogger:
    """推論実行時のベンチマークデータを記録・分析するクラス"""

    def __init__(self, log_dir: str = "data/logs/benchmarks"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # ログ設定
        self.logger = logging.getLogger("benchmark")
        self.logger.setLevel(logging.INFO)

        # ファイルハンドラー
        log_file = self.log_dir / f"benchmark_{datetime.now().strftime('%Y%m%d')}.log"
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

        # ベンチマークデータ
        self.benchmark_data: List[Dict[str, Any]] = []

    def start_benchmark(
        self, prompt: str, model_id: str, task_type: Optional[str] = None
    ) -> str:
        """ベンチマーク開始"""
        benchmark_id = f"bench_{int(time.time() * 1000)}"

        # システムリソース取得
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()

        self.benchmark_data.append(
            {
                "benchmark_id": benchmark_id,
                "timestamp": datetime.now().isoformat(),
                "prompt": prompt[:500],  # 最初の500文字のみ
                "prompt_length": len(prompt),
                "model_id": model_id,
                "task_type": task_type,
                "start_time": time.time(),
                "system_resources": {
                    "cpu_percent": cpu_percent,
                    "memory_total": memory.total,
                    "memory_available": memory.available,
                    "memory_percent": memory.percent,
                },
                "status": "started",
            }
        )

        self.logger.info(
            f"BENCHMARK_START: {benchmark_id} - Model: {model_id}, Task: {task_type}"
        )
        return benchmark_id

    def end_benchmark(
        self,
        benchmark_id: str,
        response: str,
        tokens_generated: int,
        finish_reason: str = "stop",
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """ベンチマーク終了"""
        end_time = time.time()

        # ベンチマークデータを検索
        benchmark = None
        for b in self.benchmark_data:
            if b["benchmark_id"] == benchmark_id:
                benchmark = b
                break

        if not benchmark:
            self.logger.error(f"BENCHMARK_NOT_FOUND: {benchmark_id}")
            return {}

        # 計算
        duration = end_time - benchmark["start_time"]
        tokens_per_second = tokens_generated / duration if duration > 0 else 0

        # システムリソース（終了時）
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()

        # ベンチマークデータ更新
        benchmark.update(
            {
                "end_time": end_time,
                "duration": duration,
                "response": response[:1000],  # 最初の1000文字のみ
                "response_length": len(response),
                "tokens_generated": tokens_generated,
                "tokens_per_second": tokens_per_second,
                "finish_reason": finish_reason,
                "error": error,
                "status": "completed" if not error else "error",
                "system_resources_end": {
                    "cpu_percent": cpu_percent,
                    "memory_total": memory.total,
                    "memory_available": memory.available,
                    "memory_percent": memory.percent,
                },
            }
        )

        # ログ記録
        self.logger.info(
            f"BENCHMARK_END: {benchmark_id} - "
            f"Duration: {duration:.3f}s, "
            f"Tokens: {tokens_generated}, "
            f"Speed: {tokens_per_second:.2f} tok/s, "
            f"Status: {benchmark['status']}"
        )

        # JSONファイルに保存
        self._save_benchmark_data(benchmark)

        return benchmark

    def _save_benchmark_data(self, benchmark: Dict[str, Any]):
        """ベンチマークデータをJSONファイルに保存"""
        json_file = (
            self.log_dir / f"benchmark_data_{datetime.now().strftime('%Y%m%d')}.jsonl"
        )

        with open(json_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(benchmark, ensure_ascii=False) + "\n")

    def get_performance_summary(self, hours: int = 24) -> Dict[str, Any]:
        """指定時間内のパフォーマンスサマリーを取得"""
        cutoff_time = time.time() - (hours * 3600)

        recent_benchmarks = [
            b
            for b in self.benchmark_data
            if b.get("end_time", 0) > cutoff_time and b.get("status") == "completed"
        ]

        if not recent_benchmarks:
            return {"error": "No recent benchmark data found"}

        # 統計計算
        durations = [b["duration"] for b in recent_benchmarks]
        tokens_per_second = [b["tokens_per_second"] for b in recent_benchmarks]
        tokens_generated = [b["tokens_generated"] for b in recent_benchmarks]

        return {
            "total_requests": len(recent_benchmarks),
            "time_range_hours": hours,
            "avg_duration": sum(durations) / len(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "avg_tokens_per_second": sum(tokens_per_second) / len(tokens_per_second),
            "min_tokens_per_second": min(tokens_per_second),
            "max_tokens_per_second": max(tokens_per_second),
            "total_tokens_generated": sum(tokens_generated),
            "avg_tokens_per_request": sum(tokens_generated) / len(tokens_generated),
            "error_rate": len([b for b in recent_benchmarks if b.get("error")])
            / len(recent_benchmarks),
        }

    def export_training_data(self, output_file: str = "data/training_data.jsonl"):
        """ファインチューニング用データをエクスポート"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        training_data = []
        for benchmark in self.benchmark_data:
            if benchmark.get("status") == "completed" and not benchmark.get("error"):
                training_data.append(
                    {
                        "prompt": benchmark["prompt"],
                        "response": benchmark["response"],
                        "model_id": benchmark["model_id"],
                        "task_type": benchmark["task_type"],
                        "tokens_generated": benchmark["tokens_generated"],
                        "tokens_per_second": benchmark["tokens_per_second"],
                        "duration": benchmark["duration"],
                    }
                )

        with open(output_path, "w", encoding="utf-8") as f:
            for item in training_data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

        self.logger.info(
            f"TRAINING_DATA_EXPORTED: {len(training_data)} records to {output_file}"
        )
        return len(training_data)


# グローバルインスタンス
benchmark_logger = BenchmarkLogger()


def log_inference_benchmark(
    prompt: str,
    model_id: str,
    response: str,
    tokens_generated: int,
    task_type: Optional[str] = None,
    finish_reason: str = "stop",
    error: Optional[str] = None,
) -> str:
    """推論ベンチマークを記録する便利関数"""
    benchmark_id = benchmark_logger.start_benchmark(prompt, model_id, task_type)
    benchmark_logger.end_benchmark(
        benchmark_id, response, tokens_generated, finish_reason, error
    )
    return benchmark_id
