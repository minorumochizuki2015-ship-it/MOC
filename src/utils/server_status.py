#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
サーバー状態監視システム
リアルタイムでサーバー接続状態を監視・表示
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

import psutil
import requests


class ServerStatusMonitor:
    """サーバー状態を監視・表示するクラス"""

    def __init__(self, server_url: str = "http://127.0.0.1:8080"):
        self.server_url = server_url
        self.status_cache: Dict[str, any] = {}
        self.last_check = 0
        self.check_interval = 2  # 2秒間隔（リアルタイム更新）

    def check_server_status(self) -> Tuple[bool, Dict[str, any]]:
        """サーバー状態をチェック（リアルタイム更新）"""
        current_time = time.time()

        # キャッシュチェック（より短い間隔で更新）
        if current_time - self.last_check < 2:  # 2秒間隔に短縮
            return self.status_cache.get("is_online", False), self.status_cache

        try:
            # ヘルスチェック
            response = requests.get(f"{self.server_url}/v1/models", timeout=5)
            is_online = response.status_code == 200

            if is_online:
                # モデル情報取得
                models_data = response.json()
                model_id = models_data.get("data", [{}])[0].get("id", "unknown")

                # システムリソース取得
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()

                # プロセス情報取得
                python_processes = [
                    p
                    for p in psutil.process_iter(
                        ["pid", "name", "cpu_percent", "memory_percent"]
                    )
                    if p.info["name"] == "python.exe"
                ]

                status = {
                    "is_online": True,
                    "model_id": model_id,
                    "server_url": self.server_url,
                    "last_check": datetime.now().isoformat(),
                    "system_resources": {
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "memory_available_gb": round(memory.available / (1024**3), 2),
                    },
                    "python_processes": len(python_processes),
                    "status_icon": self._get_status_icon(
                        True, cpu_percent, memory.percent
                    ),
                }
            else:
                status = {
                    "is_online": False,
                    "server_url": self.server_url,
                    "last_check": datetime.now().isoformat(),
                    "error": f"HTTP {response.status_code}",
                    "status_icon": self._get_status_icon(False),
                }

        except requests.exceptions.ConnectionError:
            status = {
                "is_online": False,
                "server_url": self.server_url,
                "last_check": datetime.now().isoformat(),
                "error": "Connection refused",
                "status_icon": self._get_status_icon(False),
            }
        except requests.exceptions.Timeout:
            status = {
                "is_online": False,
                "server_url": self.server_url,
                "last_check": datetime.now().isoformat(),
                "error": "Timeout",
                "status_icon": self._get_status_icon(False),
            }
        except Exception as e:
            status = {
                "is_online": False,
                "server_url": self.server_url,
                "last_check": datetime.now().isoformat(),
                "error": str(e),
                "status_icon": self._get_status_icon(False),
            }

        # キャッシュ更新
        self.status_cache = status
        self.last_check = current_time

        return status["is_online"], status

    def _get_status_icon(
        self, is_online: bool, cpu_percent: float = 0, memory_percent: float = 0
    ) -> str:
        """状態に応じたアイコンを返す"""
        if not is_online:
            return "🔴"  # オフライン

        # オンライン時の状態判定
        if cpu_percent > 80 or memory_percent > 90:
            return "🟡"  # 高負荷
        elif cpu_percent > 60 or memory_percent > 70:
            return "🟠"  # 中負荷
        else:
            return "🟢"  # 正常

    def get_status_display(self) -> str:
        """状態表示用の文字列を取得（統合・リアルタイム）"""
        is_online, status = self.check_server_status()

        if is_online:
            icon = status["status_icon"]
            model = status.get("model_id", "unknown")
            cpu = status["system_resources"]["cpu_percent"]
            memory = status["system_resources"]["memory_percent"]
            processes = status["python_processes"]

            # 統合表示（重複排除）
            return f"{icon} サーバー稼働中 | モデル: {model} | CPU: {cpu:.1f}% | メモリ: {memory:.1f}% | プロセス: {processes}"
        else:
            icon = status["status_icon"]
            error = status.get("error", "Unknown error")
            # 再接続試行中の表示を追加
            if "Connection refused" in error:
                return f"{icon} サーバー停止中 | 再接続試行中..."
            elif "Timeout" in error:
                return f"{icon} サーバー停止中 | タイムアウト - 再試行中..."
            else:
                return f"{icon} サーバー停止中 | エラー: {error}"

    def get_detailed_status(self) -> Dict[str, any]:
        """詳細な状態情報を取得"""
        is_online, status = self.check_server_status()
        return status


# グローバルインスタンス
server_monitor = ServerStatusMonitor()


def get_server_status() -> Tuple[bool, str]:
    """サーバー状態を取得する便利関数"""
    is_online, status = server_monitor.check_server_status()
    display_text = server_monitor.get_status_display()
    return is_online, display_text


def get_server_icon() -> str:
    """サーバー状態アイコンを取得する便利関数"""
    is_online, status = server_monitor.check_server_status()
    return status["status_icon"]
