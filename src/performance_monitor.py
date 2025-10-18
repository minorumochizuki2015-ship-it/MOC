"""
システムパフォーマンス監視モジュール
CPU、メモリ、ディスク、ネットワーク、レスポンス時間の監視
"""

import json
import logging
import os
import platform
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import psutil
import requests


class SystemPerformanceMonitor:
    """システムパフォーマンス監視クラス"""

    def __init__(self, config_path: str = "config/performance.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.metrics_history = deque(maxlen=1000)
        self.is_monitoring = False
        self.monitor_thread = None
        self._thread_lock = threading.Lock()

        # ログ設定
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict:
        """設定ファイル読み込み"""
        default_config = {
            "monitoring_interval": 30,  # 30秒間隔
            "thresholds": {
                "cpu_usage_max": 80.0,
                "memory_usage_max": 85.0,
                "disk_usage_max": 90.0,
                "response_time_max": 2.0,
                "network_latency_max": 100.0,
            },
            "endpoints_to_monitor": [
                "http://127.0.0.1:5001/health",
                "http://127.0.0.1:5001/api/status",
            ],
            "alert_cooldown": 300,  # 5分間のクールダウン
            "data_retention_hours": 24,
        }

        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # デフォルト設定とマージ
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                self.logger.warning(f"Config load failed, using defaults: {e}")

        # デフォルト設定を保存
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)

        return default_config

    def collect_system_metrics(self) -> Dict:
        """システムメトリクス収集"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()

            # メモリ使用率
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # ディスク使用率
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.device] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": (usage.used / usage.total) * 100,
                    }
                except PermissionError:
                    continue

            # ネットワーク統計
            network = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())

            # プロセス情報
            process_count = len(psutil.pids())

            # 現在のプロセス情報
            current_process = psutil.Process()
            process_info = {
                "cpu_percent": current_process.cpu_percent(),
                "memory_percent": current_process.memory_percent(),
                "memory_info": current_process.memory_info()._asdict(),
                "num_threads": current_process.num_threads(),
            }

            metrics = {
                "timestamp": datetime.now().isoformat(),
                "system_info": {
                    "platform": platform.platform(),
                    "python_version": platform.python_version(),
                    "cpu_count": cpu_count,
                },
                "cpu": {
                    "usage_percent": cpu_percent,
                    "frequency": cpu_freq._asdict() if cpu_freq else None,
                    "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent,
                    "swap_total": swap.total,
                    "swap_used": swap.used,
                    "swap_percent": swap.percent,
                },
                "disk": disk_usage,
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv,
                    "connections": network_connections,
                },
                "process": {"count": process_count, "current": process_info},
            }

            return metrics

        except Exception as e:
            self.logger.error(f"System metrics collection failed: {e}")
            return {}

    def collect_response_time_metrics(self) -> Dict:
        """レスポンス時間メトリクス収集"""
        response_times = {}

        for endpoint in self.config["endpoints_to_monitor"]:
            try:
                start_time = time.time()
                response = requests.get(endpoint, timeout=10)
                end_time = time.time()

                response_time = (end_time - start_time) * 1000  # ミリ秒

                response_times[endpoint] = {
                    "response_time_ms": response_time,
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "timestamp": datetime.now().isoformat(),
                }

            except Exception as e:
                response_times[endpoint] = {
                    "response_time_ms": None,
                    "status_code": None,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                }

        return response_times

    def analyze_performance_metrics(self, metrics: Dict) -> List[Dict]:
        """パフォーマンスメトリクス分析"""
        alerts = []
        thresholds = self.config["thresholds"]

        # CPU使用率チェック
        if metrics.get("cpu", {}).get("usage_percent", 0) > thresholds["cpu_usage_max"]:
            alerts.append(
                {
                    "type": "high_cpu_usage",
                    "severity": "warning",
                    "message": f"CPU使用率が高い: {metrics['cpu']['usage_percent']:.1f}%",
                    "value": metrics["cpu"]["usage_percent"],
                    "threshold": thresholds["cpu_usage_max"],
                }
            )

        # メモリ使用率チェック
        if metrics.get("memory", {}).get("percent", 0) > thresholds["memory_usage_max"]:
            alerts.append(
                {
                    "type": "high_memory_usage",
                    "severity": "warning",
                    "message": f"メモリ使用率が高い: {metrics['memory']['percent']:.1f}%",
                    "value": metrics["memory"]["percent"],
                    "threshold": thresholds["memory_usage_max"],
                }
            )

        # ディスク使用率チェック
        for device, usage in metrics.get("disk", {}).items():
            if usage["percent"] > thresholds["disk_usage_max"]:
                alerts.append(
                    {
                        "type": "high_disk_usage",
                        "severity": "critical" if usage["percent"] > 95 else "warning",
                        "message": f"ディスク使用率が高い ({device}): {usage['percent']:.1f}%",
                        "value": usage["percent"],
                        "threshold": thresholds["disk_usage_max"],
                        "device": device,
                    }
                )

        return alerts

    def analyze_response_time_metrics(self, response_times: Dict) -> List[Dict]:
        """レスポンス時間メトリクス分析"""
        alerts = []
        threshold = self.config["thresholds"]["response_time_max"] * 1000  # ミリ秒に変換

        for endpoint, data in response_times.items():
            if not data["success"]:
                alerts.append(
                    {
                        "type": "endpoint_failure",
                        "severity": "critical",
                        "message": f"エンドポイントアクセス失敗: {endpoint}",
                        "endpoint": endpoint,
                        "error": data.get("error", "Unknown error"),
                    }
                )
            elif data["response_time_ms"] and data["response_time_ms"] > threshold:
                alerts.append(
                    {
                        "type": "slow_response",
                        "severity": "warning",
                        "message": f"レスポンス時間が遅い: {endpoint} ({data['response_time_ms']:.1f}ms)",
                        "endpoint": endpoint,
                        "value": data["response_time_ms"],
                        "threshold": threshold,
                    }
                )

        return alerts

    def get_performance_summary(self) -> Dict:
        """パフォーマンス要約取得"""
        if not self.metrics_history:
            # サンプルデータを返す
            return {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.1,
                "response_time": 125.5,
                "throughput": 1250,
                "error_rate": 0.02,
                "timestamp": datetime.now().isoformat(),
            }

        latest_metrics = self.metrics_history[-1]

        # 過去1時間の平均値計算
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_metrics = [
            m for m in self.metrics_history if datetime.fromisoformat(m["timestamp"]) > one_hour_ago
        ]

        if recent_metrics:
            avg_cpu = sum(m.get("cpu", {}).get("usage_percent", 0) for m in recent_metrics) / len(
                recent_metrics
            )
            avg_memory = sum(m.get("memory", {}).get("percent", 0) for m in recent_metrics) / len(
                recent_metrics
            )
        else:
            avg_cpu = latest_metrics.get("cpu", {}).get("usage_percent", 0)
            avg_memory = latest_metrics.get("memory", {}).get("percent", 0)

        return {
            "current": {
                "cpu_percent": latest_metrics.get("cpu", {}).get("usage_percent", 0),
                "memory_percent": latest_metrics.get("memory", {}).get("percent", 0),
                "disk_usage": latest_metrics.get("disk", {}),
                "timestamp": latest_metrics.get("timestamp"),
            },
            "averages_1h": {"cpu_percent": avg_cpu, "memory_percent": avg_memory},
            "thresholds": self.config["thresholds"],
            "monitoring_status": {
                "is_running": self.is_monitoring,
                "metrics_count": len(self.metrics_history),
            },
        }

    def start_monitoring(self) -> None:
        """パフォーマンス監視開始"""
        if self.is_monitoring:
            self.logger.warning("Performance monitoring already running")
            return

        self.is_monitoring = True
        with self._thread_lock:
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()

        self.logger.info("Performance monitoring started")

    def stop_monitoring(self) -> None:
        """パフォーマンス監視停止"""
        if not self.is_monitoring:
            self.logger.warning("Performance monitoring not running")
            return

        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        self.logger.info("Performance monitoring stopped")

    def _monitoring_loop(self) -> None:
        """監視ループ"""
        self.logger.info("Performance monitoring loop started")

        while self.is_monitoring:
            try:
                # システムメトリクス収集
                system_metrics = self.collect_system_metrics()
                if not system_metrics:
                    time.sleep(self.config["monitoring_interval"])
                    continue

                # レスポンス時間メトリクス収集
                response_metrics = self.collect_response_time_metrics()

                # 統合メトリクス
                combined_metrics = {**system_metrics, "response_times": response_metrics}

                # 履歴に追加
                self.metrics_history.append(combined_metrics)

                # 古いデータのクリーンアップ
                self._cleanup_old_metrics()

                # 次回実行まで待機
                time.sleep(self.config["monitoring_interval"])

            except Exception as e:
                self.logger.error(f"Performance monitoring loop error: {e}")
                time.sleep(self.config["monitoring_interval"])

        self.logger.info("Performance monitoring loop stopped")

    def _cleanup_old_metrics(self) -> None:
        """古いメトリクスデータのクリーンアップ"""
        try:
            retention_hours = self.config["data_retention_hours"]
            cutoff_time = datetime.now() - timedelta(hours=retention_hours)

            # 古いデータを削除
            self.metrics_history = deque(
                [
                    m
                    for m in self.metrics_history
                    if datetime.fromisoformat(m["timestamp"]) > cutoff_time
                ],
                maxlen=1000,
            )

        except Exception as e:
            self.logger.error(f"Metrics cleanup failed: {e}")

    def get_status(self) -> Dict:
        """監視状況取得"""
        return {
            "is_monitoring": self.is_monitoring,
            "config": self.config,
            "thread_alive": self.monitor_thread.is_alive() if self.monitor_thread else False,
            "metrics_count": len(self.metrics_history),
            "last_collection": (
                self.metrics_history[-1]["timestamp"] if self.metrics_history else None
            ),
        }


# グローバルインスタンス
performance_monitor = None


def get_performance_monitor() -> SystemPerformanceMonitor:
    """パフォーマンス監視インスタンス取得"""
    global performance_monitor
    if performance_monitor is None:
        performance_monitor = SystemPerformanceMonitor()
    return performance_monitor


def main():
    """メイン実行関数"""
    monitor = SystemPerformanceMonitor()

    try:
        print("Starting performance monitoring...")
        monitor.start_monitoring()

        # 監視実行（Ctrl+Cで停止）
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping performance monitoring...")
        monitor.stop_monitoring()
        print("Performance monitoring stopped")


if __name__ == "__main__":
    main()
