"""
Dispatcher モジュールのunit テスト
"""

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.dispatcher import Task, TaskDispatcher, TaskPriority, TaskStatus


class TestTaskStatus(unittest.TestCase):
    """TaskStatus enum のunit テスト"""

    def test_task_status_values(self):
        """TaskStatus の値をテスト"""
        self.assertEqual(TaskStatus.PENDING.value, "pending")
        self.assertEqual(TaskStatus.READY.value, "ready")
        self.assertEqual(TaskStatus.DOING.value, "doing")
        self.assertEqual(TaskStatus.REVIEW.value, "review")
        self.assertEqual(TaskStatus.DONE.value, "done")
        self.assertEqual(TaskStatus.HOLD.value, "hold")
        self.assertEqual(TaskStatus.DROP.value, "drop")


class TestTaskPriority(unittest.TestCase):
    """TaskPriority enum のunit テスト"""

    def test_task_priority_values(self):
        """TaskPriority の値をテスト"""
        self.assertEqual(TaskPriority.LOW.value, 1)
        self.assertEqual(TaskPriority.MEDIUM.value, 2)
        self.assertEqual(TaskPriority.HIGH.value, 3)
        self.assertEqual(TaskPriority.CRITICAL.value, 4)


class TestTaskDispatcher(unittest.TestCase):
    """TaskDispatcher のunit テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_dispatcher.db"
        self.dispatcher = TaskDispatcher(str(self.db_path))

    def tearDown(self):
        """テスト後のクリーンアップ"""
        try:
            if hasattr(self.dispatcher, "close"):
                self.dispatcher.close()
        except Exception:
            pass

    def test_init_database(self):
        """データベース初期化のテスト"""
        # データベースファイルが作成されることを確認
        self.assertTrue(self.db_path.exists())

        # テーブルが作成されることを確認
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.assertIn("tasks", tables)
            self.assertIn("locks", tables)
            self.assertIn("events", tables)

    def test_database_path_creation(self):
        """データベースパスの作成テスト"""
        # 存在しないディレクトリパスでTaskDispatcherを作成
        nested_path = Path(self.temp_dir) / "nested" / "path" / "test.db"
        dispatcher = TaskDispatcher(str(nested_path))

        # ディレクトリが作成されることを確認
        self.assertTrue(nested_path.parent.exists())
        self.assertTrue(nested_path.exists())

    def test_config_dict_initialization(self):
        """設定辞書での初期化テスト"""
        config = {"database": {"path": str(self.db_path)}}
        dispatcher = TaskDispatcher(config)
        self.assertTrue(self.db_path.exists())


if __name__ == "__main__":
    unittest.main()
