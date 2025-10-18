#!/usr/bin/env python3
"""
システムパフォーマンスプロファイラー

リアルタイムでシステムリソースを監視し、パフォーマンスボトルネックを特定します。
"""

import asyncio
import cProfile
import io
import json
import logging
import os
import pstats
import threading
import time
import tracemalloc
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import psutil


class ResourceMonitor:
    """システムリソース監視クラス"""

    def __init__(self, interval: float = 1.0, history_size: int = 1000):
        self.interval = interval
        self.history_size = history_size
        self.monitoring = False
        self.monitor_thread = None

        # メトリクス履歴
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        self.network_history = deque(maxlen=history_size)
        self.process_history = deque(maxlen=history_size)

        # アラートコールバック
        self.alert_callbacks: List[Callable] = []

        # 閾値設定
        self.thresholds = {
            "cpu_warning": 70.0,
            "cpu_critical": 85.0,
            "memory_warning": 75.0,
            "memory_critical": 90.0,
            "disk_warning": 80.0,
            "disk_critical": 95.0,
        }

        # ログ設定
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def add_alert_callback(self, callback: Callable):
        """アラートコールバックを追加"""
        self.alert_callbacks.append(callback)

    def start_monitoring(self):
        """監視開始"""
        if self.monitoring:
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info("リソース監視を開始しました")

    def stop_monitoring(self):
        """監視停止"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        self.logger.info("リソース監視を停止しました")

    def _monitor_loop(self):
        """監視ループ"""
        while self.monitoring:
            try:
                timestamp = datetime.now(timezone.utc)

                # CPU使用率
                cpu_percent = psutil.cpu_percent(interval=None)
                cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)

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

                # プロセス情報
                current_process = psutil.Process()
                process_info = {
                    "pid": current_process.pid,
                    "cpu_percent": current_process.cpu_percent(),
                    "memory_info": current_process.memory_info()._asdict(),
                    "memory_percent": current_process.memory_percent(),
                    "num_threads": current_process.num_threads(),
                    "open_files": len(current_process.open_files()),
                    "connections": len(current_process.connections()),
                }

                # データ記録
                self.cpu_history.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "total": cpu_percent,
                        "per_core": cpu_per_core,
                    }
                )

                self.memory_history.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "virtual": memory._asdict(),
                        "swap": swap._asdict(),
                    }
                )

                self.disk_history.append({"timestamp": timestamp.isoformat(), "usage": disk_usage})

                self.network_history.append(
                    {"timestamp": timestamp.isoformat(), "stats": network._asdict()}
                )

                self.process_history.append(
                    {"timestamp": timestamp.isoformat(), "process": process_info}
                )

                # アラートチェック
                self._check_alerts(cpu_percent, memory.percent, disk_usage)

            except Exception as e:
                self.logger.error(f"監視中にエラーが発生: {e}")

            time.sleep(self.interval)

    def _check_alerts(self, cpu_percent: float, memory_percent: float, disk_usage: Dict):
        """アラートチェック"""
        alerts = []

        # CPU アラート
        if cpu_percent >= self.thresholds["cpu_critical"]:
            alerts.append({"type": "cpu", "level": "critical", "value": cpu_percent})
        elif cpu_percent >= self.thresholds["cpu_warning"]:
            alerts.append({"type": "cpu", "level": "warning", "value": cpu_percent})

        # メモリ アラート
        if memory_percent >= self.thresholds["memory_critical"]:
            alerts.append({"type": "memory", "level": "critical", "value": memory_percent})
        elif memory_percent >= self.thresholds["memory_warning"]:
            alerts.append({"type": "memory", "level": "warning", "value": memory_percent})

        # ディスク アラート
        for device, usage in disk_usage.items():
            percent = usage["percent"]
            if percent >= self.thresholds["disk_critical"]:
                alerts.append(
                    {"type": "disk", "level": "critical", "device": device, "value": percent}
                )
            elif percent >= self.thresholds["disk_warning"]:
                alerts.append(
                    {"type": "disk", "level": "warning", "device": device, "value": percent}
                )

        # アラートコールバック実行
        for alert in alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"アラートコールバック実行エラー: {e}")

    def get_current_stats(self) -> Dict[str, Any]:
        """現在の統計情報を取得"""
        if not self.cpu_history:
            return {"error": "監視データがありません"}

        latest_cpu = self.cpu_history[-1]
        latest_memory = self.memory_history[-1]
        latest_disk = self.disk_history[-1]
        latest_network = self.network_history[-1]
        latest_process = self.process_history[-1]

        return {
            "timestamp": latest_cpu["timestamp"],
            "cpu": latest_cpu,
            "memory": latest_memory,
            "disk": latest_disk,
            "network": latest_network,
            "process": latest_process,
        }

    def get_historical_stats(self, minutes: int = 10) -> Dict[str, List]:
        """過去の統計情報を取得"""
        cutoff_time = datetime.now(timezone.utc).timestamp() - (minutes * 60)

        def filter_by_time(history):
            return [
                item
                for item in history
                if datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).timestamp()
                >= cutoff_time
            ]

        return {
            "cpu": filter_by_time(self.cpu_history),
            "memory": filter_by_time(self.memory_history),
            "disk": filter_by_time(self.disk_history),
            "network": filter_by_time(self.network_history),
            "process": filter_by_time(self.process_history),
        }

    def export_stats(self, filepath: str):
        """統計情報をファイルにエクスポート"""
        stats = {
            "export_time": datetime.now(timezone.utc).isoformat(),
            "thresholds": self.thresholds,
            "cpu_history": list(self.cpu_history),
            "memory_history": list(self.memory_history),
            "disk_history": list(self.disk_history),
            "network_history": list(self.network_history),
            "process_history": list(self.process_history),
        }

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)

        self.logger.info(f"統計情報をエクスポート: {filepath}")


class PerformanceProfiler:
    """パフォーマンスプロファイラー"""

    def __init__(self):
        self.profiler = None
        self.profiling_active = False
        self.resource_monitor = ResourceMonitor()

    @contextmanager
    def profile_context(self, output_file: Optional[str] = None):
        """プロファイリングコンテキストマネージャー"""
        self.start_profiling()
        try:
            yield self
        finally:
            self.stop_profiling(output_file)

    def start_profiling(self):
        """プロファイリング開始"""
        if self.profiling_active:
            return

        self.profiler = cProfile.Profile()
        self.profiler.enable()
        self.profiling_active = True

        # リソース監視も開始
        self.resource_monitor.start_monitoring()

        # メモリトレース開始
        tracemalloc.start()

    def stop_profiling(self, output_file: Optional[str] = None):
        """プロファイリング停止"""
        if not self.profiling_active:
            return

        self.profiler.disable()
        self.profiling_active = False

        # リソース監視停止
        self.resource_monitor.stop_monitoring()

        # メモリトレース停止
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # 結果出力
        if output_file:
            self._save_profile_results(output_file, current, peak)

    def _save_profile_results(self, output_file: str, memory_current: int, memory_peak: int):
        """プロファイル結果を保存"""
        # プロファイル統計
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s)
        ps.sort_stats("cumulative")
        ps.print_stats(50)  # 上位50関数

        # 結果をまとめる
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory_usage": {
                "current_bytes": memory_current,
                "peak_bytes": memory_peak,
                "current_mb": memory_current / 1024 / 1024,
                "peak_mb": memory_peak / 1024 / 1024,
            },
            "profile_stats": s.getvalue(),
            "resource_stats": self.resource_monitor.get_current_stats(),
        }

        # ファイル保存
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # JSON形式で保存
        json_file = output_file.replace(".prof", ".json")
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # バイナリプロファイルも保存
        self.profiler.dump_stats(output_file)

        print(f"プロファイル結果を保存: {json_file}")
        print(f"バイナリプロファイル: {output_file}")

    def analyze_hotspots(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """ホットスポット分析"""
        if not self.profiler:
            return []

        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s)
        ps.sort_stats("cumulative")

        hotspots = []
        for func, (cc, nc, tt, ct, callers) in ps.stats.items():
            filename, line, func_name = func
            hotspots.append(
                {
                    "function": func_name,
                    "filename": filename,
                    "line": line,
                    "call_count": cc,
                    "total_time": tt,
                    "cumulative_time": ct,
                    "time_per_call": tt / cc if cc > 0 else 0,
                }
            )

        return sorted(hotspots, key=lambda x: x["cumulative_time"], reverse=True)[:top_n]

    def get_memory_profile(self) -> Dict[str, Any]:
        """メモリプロファイル取得"""
        if not tracemalloc.is_tracing():
            return {"error": "メモリトレースが無効です"}

        current, peak = tracemalloc.get_traced_memory()
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics("lineno")

        memory_hotspots = []
        for stat in top_stats[:20]:
            memory_hotspots.append(
                {
                    "filename": stat.traceback.format()[0],
                    "size_bytes": stat.size,
                    "size_mb": stat.size / 1024 / 1024,
                    "count": stat.count,
                }
            )

        return {
            "current_usage": {"bytes": current, "mb": current / 1024 / 1024},
            "peak_usage": {"bytes": peak, "mb": peak / 1024 / 1024},
            "hotspots": memory_hotspots,
        }


# グローバルプロファイラーインスタンス
global_profiler = PerformanceProfiler()


def profile_function(func):
    """関数デコレーター：関数のプロファイリング"""

    def wrapper(*args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_file = f"C:/Users/User/Trae/ORCH-Next/data/profiles/{func.__name__}_{timestamp}.prof"

        with global_profiler.profile_context(output_file):
            return func(*args, **kwargs)

    return wrapper


def alert_handler(alert: Dict[str, Any]):
    """デフォルトアラートハンドラー"""
    level = alert.get("level", "info")
    alert_type = alert.get("type", "unknown")
    value = alert.get("value", 0)

    message = f"[{level.upper()}] {alert_type} アラート: {value:.1f}%"

    if level == "critical":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
    else:
        logging.info(message)


# デフォルトアラートハンドラーを設定
global_profiler.resource_monitor.add_alert_callback(alert_handler)

if __name__ == "__main__":
    # テスト実行
    print("パフォーマンスプロファイラーテスト開始")

    # リソース監視テスト
    monitor = ResourceMonitor(interval=0.5)
    monitor.start_monitoring()

    print("5秒間のリソース監視...")
    time.sleep(5)

    stats = monitor.get_current_stats()
    print(f"現在のCPU使用率: {stats['cpu']['total']:.1f}%")
    print(f"現在のメモリ使用率: {stats['memory']['virtual']['percent']:.1f}%")

    monitor.stop_monitoring()

    # プロファイリングテスト
    @profile_function
    def test_function():
        # CPU集約的な処理をシミュレート
        total = 0
        for i in range(1000000):
            total += i * i
        return total

    print("\nプロファイリングテスト実行...")
    result = test_function()
    print(f"計算結果: {result}")

    print("✓ パフォーマンスプロファイラーテスト完了")
