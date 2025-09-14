# performance_monitor.py
# 統治核AIシステムの性能監視とメトリクス収集

import json
import os
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

# psutilの代替実装
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

    # psutilの代替実装
    class MockPsutil:
        @staticmethod
        def cpu_percent(interval=0.1):
            return 0.0

        @staticmethod
        def virtual_memory():
            class Memory:
                percent = 0.0

            return Memory()

        @staticmethod
        def disk_usage(path):
            class Disk:
                used = 0
                total = 1000000000

            return Disk()

        @staticmethod
        def net_io_counters():
            class NetIO:
                bytes_sent = 0
                bytes_recv = 0

            return NetIO()

    psutil = MockPsutil()


class PerformanceMonitor:
    """システム性能を監視し、メトリクスを収集するクラス"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._metrics_history = deque(maxlen=max_history)
        self._lock = threading.Lock()
        self._start_time = time.time()

        # システムメトリクス
        self._system_metrics = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "network_io": {"bytes_sent": 0, "bytes_recv": 0},
        }

        # AI性能メトリクス
        self._ai_metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "avg_response_time": 0.0,
            "cache_hit_rate": 0.0,
            "governance_violations": 0,
            "memory_blocks": 0,
        }

        # バックグラウンド監視開始
        self._start_monitoring()

    def _start_monitoring(self):
        """バックグラウンドでシステム監視を開始"""

        def monitor_worker():
            while True:
                self._update_system_metrics()
                time.sleep(1)  # 1秒ごとに更新

        monitor_thread = threading.Thread(target=monitor_worker, daemon=True)
        monitor_thread.start()

    def _update_system_metrics(self):
        """システムメトリクスを更新"""
        try:
            if PSUTIL_AVAILABLE:
                # CPU使用率
                self._system_metrics["cpu_usage"] = psutil.cpu_percent(interval=0.1)

                # メモリ使用率
                memory = psutil.virtual_memory()
                self._system_metrics["memory_usage"] = memory.percent

                # ディスク使用率
                disk = psutil.disk_usage("/")
                self._system_metrics["disk_usage"] = (disk.used / disk.total) * 100

                # ネットワークI/O
                net_io = psutil.net_io_counters()
                self._system_metrics["network_io"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                }
            else:
                # psutilが利用できない場合の代替値
                self._system_metrics["cpu_usage"] = 0.0
                self._system_metrics["memory_usage"] = 0.0
                self._system_metrics["disk_usage"] = 0.0
                self._system_metrics["network_io"] = {"bytes_sent": 0, "bytes_recv": 0}

        except Exception as e:
            print(f"System metrics update error: {e}")

    def record_request(
        self,
        response_time: float,
        success: bool = True,
        cache_hit: bool = False,
        governance_violation: bool = False,
    ):
        """リクエストのメトリクスを記録"""
        with self._lock:
            self._ai_metrics["total_requests"] += 1

            if success:
                self._ai_metrics["successful_requests"] += 1
            else:
                self._ai_metrics["failed_requests"] += 1

            if cache_hit:
                # キャッシュヒット率の計算
                total = self._ai_metrics["total_requests"]
                cache_hits = self._ai_metrics.get("cache_hits", 0) + 1
                self._ai_metrics["cache_hits"] = cache_hits
                self._ai_metrics["cache_hit_rate"] = (
                    cache_hits / total if total > 0 else 0.0
                )

            if governance_violation:
                self._ai_metrics["governance_violations"] += 1

            # 平均応答時間の更新（指数移動平均）
            alpha = 0.1
            current_avg = self._ai_metrics["avg_response_time"]
            self._ai_metrics["avg_response_time"] = (
                alpha * response_time + (1 - alpha) * current_avg
            )

            # メトリクス履歴に追加
            self._add_to_history(
                {
                    "timestamp": datetime.now().isoformat(),
                    "response_time": response_time,
                    "success": success,
                    "cache_hit": cache_hit,
                    "governance_violation": governance_violation,
                }
            )

    def _add_to_history(self, metrics: Dict[str, Any]):
        """メトリクス履歴に追加"""
        with self._lock:
            self._metrics_history.append(metrics)

    def get_current_metrics(self) -> Dict[str, Any]:
        """現在のメトリクスを取得"""
        with self._lock:
            uptime = time.time() - self._start_time
            return {
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "system": self._system_metrics.copy(),
                "ai": self._ai_metrics.copy(),
                "timestamp": datetime.now().isoformat(),
            }

    def get_performance_summary(self) -> Dict[str, Any]:
        """性能サマリーを取得"""
        metrics = self.get_current_metrics()

        # 成功率の計算
        total_requests = metrics["ai"]["total_requests"]
        successful_requests = metrics["ai"]["successful_requests"]
        success_rate = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0
        )

        # エラー率の計算
        failed_requests = metrics["ai"]["failed_requests"]
        error_rate = (
            (failed_requests / total_requests * 100) if total_requests > 0 else 0
        )

        # 統治違反率の計算
        governance_violations = metrics["ai"]["governance_violations"]
        violation_rate = (
            (governance_violations / total_requests * 100) if total_requests > 0 else 0
        )

        return {
            "performance_score": self._calculate_performance_score(metrics),
            "success_rate": f"{success_rate:.1f}%",
            "error_rate": f"{error_rate:.1f}%",
            "violation_rate": f"{violation_rate:.1f}%",
            "avg_response_time": f"{metrics['ai']['avg_response_time']:.3f}s",
            "cache_hit_rate": f"{metrics['ai']['cache_hit_rate']:.1%}",
            "system_health": self._assess_system_health(metrics),
            "recommendations": self._generate_recommendations(metrics),
        }

    def _calculate_performance_score(self, metrics: Dict[str, Any]) -> float:
        """総合性能スコアを計算（0-100）"""
        ai_metrics = metrics["ai"]
        system_metrics = metrics["system"]

        # 基本スコア（50点満点）
        base_score = 50.0

        # 成功率による加点（30点満点）
        success_rate = (
            (ai_metrics["successful_requests"] / ai_metrics["total_requests"])
            if ai_metrics["total_requests"] > 0
            else 0
        )
        success_bonus = success_rate * 30

        # 応答時間による加点（10点満点）
        response_time = ai_metrics["avg_response_time"]
        response_bonus = max(0, 10 - (response_time * 10))  # 1秒で10点減点

        # システムリソースによる減点
        cpu_penalty = max(0, (system_metrics["cpu_usage"] - 80) * 0.5)  # 80%超で減点
        memory_penalty = max(
            0, (system_metrics["memory_usage"] - 80) * 0.5
        )  # 80%超で減点

        total_score = (
            base_score + success_bonus + response_bonus - cpu_penalty - memory_penalty
        )
        return max(0, min(100, total_score))

    def _assess_system_health(self, metrics: Dict[str, Any]) -> str:
        """システムヘルスを評価"""
        cpu = metrics["system"]["cpu_usage"]
        memory = metrics["system"]["memory_usage"]
        error_rate = (
            (metrics["ai"]["failed_requests"] / metrics["ai"]["total_requests"])
            if metrics["ai"]["total_requests"] > 0
            else 0
        )

        if cpu > 90 or memory > 90 or error_rate > 0.1:
            return "CRITICAL"
        elif cpu > 70 or memory > 70 or error_rate > 0.05:
            return "WARNING"
        else:
            return "HEALTHY"

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """改善推奨事項を生成"""
        recommendations = []

        cpu = metrics["system"]["cpu_usage"]
        memory = metrics["system"]["memory_usage"]
        response_time = metrics["ai"]["avg_response_time"]
        cache_hit_rate = metrics["ai"]["cache_hit_rate"]

        if cpu > 80:
            recommendations.append(
                "CPU使用率が高いです。処理の最適化を検討してください。"
            )

        if memory > 80:
            recommendations.append(
                "メモリ使用率が高いです。メモリリークの確認をお勧めします。"
            )

        if response_time > 2.0:
            recommendations.append(
                "応答時間が長いです。キャッシュ機能の活用を検討してください。"
            )

        if cache_hit_rate < 0.3:
            recommendations.append(
                "キャッシュヒット率が低いです。キャッシュ戦略の見直しをお勧めします。"
            )

        if not recommendations:
            recommendations.append("システムは良好な状態です。")

        return recommendations

    def _format_uptime(self, seconds: float) -> str:
        """稼働時間をフォーマット"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def export_metrics(self, filepath: str) -> bool:
        """メトリクスをファイルにエクスポート"""
        try:
            with self._lock:
                data = {
                    "export_timestamp": datetime.now().isoformat(),
                    "current_metrics": self.get_current_metrics(),
                    "performance_summary": self.get_performance_summary(),
                    "history": list(self._metrics_history),
                }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            return True
        except Exception as e:
            print(f"Metrics export error: {e}")
            return False


# グローバルインスタンス
performance_monitor = PerformanceMonitor()
