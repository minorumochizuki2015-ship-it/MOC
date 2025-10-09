#!/usr/bin/env python3
"""
通知スパム対策フィルター
重複通知の検出と抑制機能
"""

import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class NotificationSpamFilter:
    """通知スパム対策フィルター"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.notification_history: Dict[str, Dict] = {}
        self.silent_mode = False
        self.lock = threading.Lock()

        # 設定値
        self.duplicate_threshold_hours = self.config.get("duplicate_threshold_hours", 24)
        self.max_notifications_per_hour = self.config.get("max_notifications_per_hour", 10)
        self.silent_autopilot_mode = self.config.get("silent_autopilot_mode", False)

        # 履歴ファイル
        self.history_file = Path(
            self.config.get("history_file", "data/logs/current/notification_history.json")
        )
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        # 履歴読み込み
        self._load_history()

    def _default_config(self) -> Dict:
        """デフォルト設定"""
        return {
            "duplicate_threshold_hours": 24,
            "max_notifications_per_hour": 10,
            "silent_autopilot_mode": False,  # テスト用にデフォルトはFalse
            "history_file": "data/logs/current/notification_history.json",
            "todo_write_enabled": False,
            "critical_only_mode": True,
        }

    def _load_history(self) -> None:
        """通知履歴読み込み"""
        try:
            if self.history_file.exists():
                with open(self.history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.notification_history = data.get("notifications", {})
                    self.silent_mode = data.get("silent_mode", False)
        except Exception as e:
            logger.warning(f"Failed to load notification history: {e}")
            self.notification_history = {}

    def _save_history(self) -> None:
        """通知履歴保存"""
        try:
            data = {
                "notifications": self.notification_history,
                "silent_mode": self.silent_mode,
                "last_updated": datetime.now().isoformat(),
            }
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save notification history: {e}")

    def _generate_content_hash(self, content: str) -> str:
        """コンテンツハッシュ生成"""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def _cleanup_old_entries(self) -> None:
        """古いエントリのクリーンアップ"""
        cutoff_time = datetime.now() - timedelta(hours=self.duplicate_threshold_hours * 2)
        cutoff_timestamp = cutoff_time.timestamp()

        to_remove = []
        for content_hash, entry in self.notification_history.items():
            if entry.get("last_sent", 0) < cutoff_timestamp:
                to_remove.append(content_hash)

        for content_hash in to_remove:
            del self.notification_history[content_hash]

    def should_allow_notification(
        self, notification_type: str, content: str, priority: str = "medium"
    ) -> bool:
        """通知許可判定"""
        with self.lock:
            # サイレントモード中は重要な通知のみ
            if self.silent_mode or self.silent_autopilot_mode:
                if priority not in ["high", "critical"]:
                    logger.debug(f"Notification blocked (silent mode): {notification_type}")
                    return False

            # todo_write通知の特別処理
            if notification_type == "todo_write" and not self.config.get(
                "todo_write_enabled", False
            ):
                logger.debug("todo_write notifications disabled")
                return False

            # コンテンツハッシュ生成
            content_hash = self._generate_content_hash(content)
            current_time = datetime.now()
            current_timestamp = current_time.timestamp()

            # 重複チェック
            if content_hash in self.notification_history:
                entry = self.notification_history[content_hash]
                last_sent = entry.get("last_sent", 0)

                # 重複期間内かチェック
                if current_timestamp - last_sent < (self.duplicate_threshold_hours * 3600):
                    entry["blocked_count"] = entry.get("blocked_count", 0) + 1
                    logger.info(
                        f"Duplicate notification blocked: {notification_type} (hash: {content_hash})"
                    )
                    self._save_history()
                    return False

            # 時間あたりの通知数チェック
            hour_ago = current_timestamp - 3600
            recent_notifications = sum(
                1
                for entry in self.notification_history.values()
                if entry.get("last_sent", 0) > hour_ago
            )

            if recent_notifications >= self.max_notifications_per_hour:
                logger.warning(f"Notification rate limit exceeded: {recent_notifications}/hour")
                return False

            # 通知許可 - 履歴更新
            self.notification_history[content_hash] = {
                "type": notification_type,
                "priority": priority,
                "first_sent": self.notification_history.get(content_hash, {}).get(
                    "first_sent", current_timestamp
                ),
                "last_sent": current_timestamp,
                "send_count": self.notification_history.get(content_hash, {}).get("send_count", 0)
                + 1,
                "blocked_count": self.notification_history.get(content_hash, {}).get(
                    "blocked_count", 0
                ),
            }

            # 古いエントリクリーンアップ
            self._cleanup_old_entries()
            self._save_history()

            return True

    def set_silent_mode(self, enabled: bool) -> None:
        """サイレントモード設定"""
        with self.lock:
            self.silent_mode = enabled
            logger.info(f"Silent mode {'enabled' if enabled else 'disabled'}")
            self._save_history()

    def get_statistics(self) -> Dict:
        """統計情報取得"""
        with self.lock:
            total_notifications = len(self.notification_history)
            total_sent = sum(
                entry.get("send_count", 0) for entry in self.notification_history.values()
            )
            total_blocked = sum(
                entry.get("blocked_count", 0) for entry in self.notification_history.values()
            )

            return {
                "total_unique_notifications": total_notifications,
                "total_sent": total_sent,
                "total_blocked": total_blocked,
                "silent_mode": self.silent_mode,
                "config": self.config,
            }

    def reset_history(self) -> None:
        """履歴リセット"""
        with self.lock:
            self.notification_history.clear()
            self._save_history()
            logger.info("Notification history reset")


# グローバルインスタンス
_spam_filter = None


def get_spam_filter() -> NotificationSpamFilter:
    """スパムフィルターのシングルトンインスタンス取得"""
    global _spam_filter
    if _spam_filter is None:
        _spam_filter = NotificationSpamFilter()
    return _spam_filter


def should_allow_notification(
    notification_type: str, content: str, priority: str = "medium"
) -> bool:
    """通知許可判定（便利関数）"""
    return get_spam_filter().should_allow_notification(notification_type, content, priority)


def set_silent_mode(enabled: bool) -> None:
    """サイレントモード設定（便利関数）"""
    get_spam_filter().set_silent_mode(enabled)
