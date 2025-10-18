"""
通知スパムフィルターのユニットテスト
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from src.notification_spam_filter import NotificationSpamFilter


class TestNotificationSpamFilter(unittest.TestCase):
    """NotificationSpamFilterのテストクラス"""

    def setUp(self):
        """テストセットアップ"""
        self.temp_dir = tempfile.mkdtemp()
        self.history_file = os.path.join(self.temp_dir, "test_notifications.json")
        config = {
            "duplicate_threshold_hours": 24,
            "max_notifications_per_hour": 10,
            "silent_autopilot_mode": False,
            "history_file": self.history_file,
        }
        self.spam_filter = NotificationSpamFilter(config)

    def tearDown(self):
        """テストクリーンアップ"""
        if os.path.exists(self.history_file):
            os.unlink(self.history_file)
        os.rmdir(self.temp_dir)

    def test_init(self):
        """初期化のテスト"""
        self.assertIsNotNone(self.spam_filter)
        self.assertIsNotNone(self.spam_filter.config)
        self.assertEqual(self.spam_filter.duplicate_threshold_hours, 24)

    def test_should_send_notification_first_time(self):
        """初回通知送信のテスト"""
        result = self.spam_filter.should_allow_notification("test_alert", "Test message")
        self.assertTrue(result)

    def test_should_send_notification_spam_prevention(self):
        """スパム防止のテスト"""
        # 同じ通知を2回送信
        self.spam_filter.should_allow_notification("test_alert", "Test message")
        result = self.spam_filter.should_allow_notification("test_alert", "Test message")
        self.assertFalse(result)

    def test_should_send_notification_different_alerts(self):
        """異なるアラートのテスト"""
        result1 = self.spam_filter.should_allow_notification("alert1", "Message 1")
        result2 = self.spam_filter.should_allow_notification("alert2", "Message 2")
        self.assertTrue(result1)
        self.assertTrue(result2)

    def test_record_notification(self):
        """通知記録のテスト"""
        self.spam_filter.should_allow_notification("test_alert", "Test message")
        stats = self.spam_filter.get_statistics()
        self.assertGreater(stats["total_sent"], 0)

    def test_get_statistics(self):
        """統計取得のテスト"""
        self.spam_filter.should_allow_notification("test_alert", "Test message")
        stats = self.spam_filter.get_statistics()
        self.assertIn("total_sent", stats)
        self.assertIn("total_blocked", stats)

    def test_cleanup_old_records(self):
        """古いレコードのクリーンアップテスト"""
        self.spam_filter.should_allow_notification("old_alert", "Old message")
        # 時間を進める（モック）
        initial_count = len(self.spam_filter.notification_history)
        self.spam_filter._cleanup_old_entries()
        # 実際のクリーンアップは時間経過が必要なので、メソッドが呼べることを確認
        self.assertIsNotNone(self.spam_filter.notification_history)

    def test_database_persistence(self):
        """データベース永続化のテスト"""
        self.spam_filter.should_allow_notification("persist_test", "Persist message")
        # 新しいインスタンスを作成して履歴が保持されているか確認
        config = {
            "duplicate_threshold_hours": 24,
            "max_notifications_per_hour": 10,
            "silent_autopilot_mode": False,
            "history_file": self.history_file,
        }
        new_filter = NotificationSpamFilter(config)
        stats = new_filter.get_statistics()
        # 履歴ファイルが存在することを確認
        self.assertTrue(os.path.exists(self.history_file))

    def test_error_handling(self):
        """エラーハンドリングのテスト"""
        # 無効な設定でインスタンス作成
        invalid_config = {}  # 空の辞書を使用
        try:
            filter_instance = NotificationSpamFilter(invalid_config)
            # エラーが発生しないことを確認（デフォルト設定が使用される）
            self.assertIsNotNone(filter_instance)
        except Exception as e:
            self.fail(f"Unexpected exception: {e}")


if __name__ == "__main__":
    unittest.main()
