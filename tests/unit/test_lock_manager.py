"""
Lock Manager モジュールのunit テスト
"""

import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.lock_manager import LockInfo, LockManager, LockPriority, LockRequest


class TestLockManager(unittest.TestCase):
    """LockManager のunit テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_locks.db"

        # LockManagerは直接db_pathを受け取る
        self.lock_manager = LockManager(str(self.db_path), enable_cleanup_thread=False)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        try:
            self.lock_manager.close()
        except Exception:
            pass
        # ファイルが使用中の場合は削除をスキップ
        try:
            if self.db_path.exists():
                self.db_path.unlink()
        except PermissionError:
            pass

    def test_init_database(self):
        """データベース初期化のテスト"""
        self.assertTrue(self.db_path.exists())

        # テーブルが作成されることを確認
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        expected_tables = ["locks", "lock_queue", "lock_history"]
        for table in expected_tables:
            self.assertIn(table, tables)

    def test_acquire_lock_success(self):
        """ロック取得成功のテスト"""
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )

        result = self.lock_manager.acquire_lock(request)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, LockInfo)
        self.assertEqual(result.resource, "test_resource")
        self.assertEqual(result.owner, "test_owner")

    def test_acquire_lock_conflict(self):
        """ロック競合のテスト"""
        # 最初のロックを取得
        request1 = LockRequest(
            resource="test_resource",
            owner="owner1",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result1 = self.lock_manager.acquire_lock(request1)
        self.assertIsNotNone(result1)

        # 同じリソースに対して別のロックを試行（レガシー呼び出しで即座に失敗）
        result2 = self.lock_manager.acquire_lock(
            resource="test_resource",
            owner="owner2",
            priority=LockPriority.MEDIUM,
            ttl=300,
        )
        self.assertFalse(result2)  # レガシー呼び出しはFalseを返す

    def test_release_lock_success(self):
        """ロック解放成功のテスト"""
        # ロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # ロックを解放
        release_result = self.lock_manager.release_lock("test_resource", "test_owner")
        self.assertTrue(release_result)

    def test_release_lock_unauthorized(self):
        """権限のないロック解放のテスト"""
        # ロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="owner1",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # 別のオーナーがロック解放を試行
        release_result = self.lock_manager.release_lock("test_resource", "owner2")
        self.assertFalse(release_result)

    def test_extend_lock_success(self):
        """ロック延長成功のテスト"""
        # ロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # ロックを延長
        extend_result = self.lock_manager.extend_lock("test_resource", "test_owner", 600)
        self.assertTrue(extend_result)

    def test_get_lock_info(self):
        """ロック情報取得のテスト"""
        # ロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # ロック情報を取得
        info = self.lock_manager.get_lock_info("test_resource")
        self.assertIsNotNone(info)
        self.assertEqual(info["resource"], "test_resource")
        self.assertEqual(info["owner"], "test_owner")

    def test_list_locks_by_owner(self):
        """オーナー別ロック一覧のテスト"""
        # 複数のロックを取得
        request1 = LockRequest(
            resource="resource1",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request1)

        request2 = LockRequest(
            resource="resource2",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request2)

        request3 = LockRequest(
            resource="resource3",
            owner="other_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request3)

        # test_owner のロック一覧を取得
        locks = self.lock_manager.list_locks("test_owner")
        self.assertEqual(len(locks), 2)

    def test_list_all_locks(self):
        """全ロック一覧のテスト"""
        # 複数のロックを取得
        request1 = LockRequest(
            resource="resource1",
            owner="owner1",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request1)

        request2 = LockRequest(
            resource="resource2",
            owner="owner2",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request2)

        # 全ロック一覧を取得
        locks = self.lock_manager.list_locks()
        self.assertGreaterEqual(len(locks), 2)

    def test_cleanup_expired_locks(self):
        """期限切れロッククリーンアップのテスト"""
        # 短いTTLでロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=1,  # 1秒で期限切れ
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # 期限切れまで待機
        time.sleep(2)

        # クリーンアップを実行
        cleaned_count = self.lock_manager.cleanup_expired_locks()
        self.assertGreaterEqual(cleaned_count, 0)

        # ロックが削除されていることを確認
        info = self.lock_manager.get_lock_info("test_resource")
        self.assertIsNone(info)

    def test_get_statistics(self):
        """ロック統計情報取得のテスト"""
        # いくつかのロックを取得
        request1 = LockRequest(
            resource="resource1",
            owner="owner1",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request1)

        request2 = LockRequest(
            resource="resource2",
            owner="owner2",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        self.lock_manager.acquire_lock(request2)

        # 統計情報を取得
        stats = self.lock_manager.get_statistics()
        self.assertIn("active_locks", stats)
        self.assertIn("queue_length", stats)
        self.assertIn("recent_activity", stats)
        self.assertIn("average_lock_duration_seconds", stats)
        self.assertIn("timestamp", stats)
        self.assertGreaterEqual(stats["active_locks"], 2)

    def test_lock_priority_handling(self):
        """ロック優先度処理のテスト"""
        # 低優先度のロックを取得
        low_priority_request = LockRequest(
            resource="test_resource",
            owner="low_priority_owner",
            priority=LockPriority.LOW,
            ttl_seconds=300,
        )
        low_priority_result = self.lock_manager.acquire_lock(low_priority_request)
        self.assertIsNotNone(low_priority_result)

        # 高優先度のロックを試行（キューに入る）
        high_priority_request = LockRequest(
            resource="test_resource",
            owner="high_priority_owner",
            priority=LockPriority.HIGH,
            ttl_seconds=300,
        )
        # 高優先度でもすでにロックが取得されているため、キューに入るかタイムアウト
        high_priority_result = self.lock_manager.acquire_lock(
            high_priority_request, timeout_seconds=1
        )
        # タイムアウトでNoneが返される
        self.assertIsNone(high_priority_result)

    def test_memory_database(self):
        """インメモリデータベースのテスト"""
        # インメモリデータベースでLockManagerを作成
        memory_lock_manager = LockManager(db_path=":memory:", enable_cleanup_thread=False)

        # 基本的なロック操作をテスト
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = memory_lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # クリーンアップ
        memory_lock_manager.close()

    def test_close_method(self):
        """close メソッドのテスト"""
        # ロックを取得
        request = LockRequest(
            resource="test_resource",
            owner="test_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result = self.lock_manager.acquire_lock(request)
        self.assertIsNotNone(result)

        # close メソッドを呼び出し
        self.lock_manager.close()

        # close後もロック操作は可能（新しい接続が作成される）
        request2 = LockRequest(
            resource="test_resource2",
            owner="test_owner2",
            priority=LockPriority.MEDIUM,
            ttl_seconds=300,
        )
        result2 = self.lock_manager.acquire_lock(request2)
        # closeメソッドはリソースを解放するが、新しい操作時に再接続される
        self.assertIsNotNone(result2)

    def test_concurrent_lock_access(self):
        """並行ロックアクセスのテスト"""
        results = []

        def acquire_lock_thread(owner_id):
            request = LockRequest(
                resource="concurrent_resource",
                owner=f"owner_{owner_id}",
                priority=LockPriority.MEDIUM,
                ttl_seconds=300,
            )
            result = self.lock_manager.acquire_lock(request, timeout_seconds=1)
            results.append(result)

        # 複数スレッドで同時にロック取得を試行
        threads = []
        for i in range(3):
            thread = threading.Thread(target=acquire_lock_thread, args=(i,))
            threads.append(thread)
            thread.start()

        # 全スレッドの完了を待機
        for thread in threads:
            thread.join()

        # 1つだけ成功し、他はタイムアウトすることを確認
        successful_locks = [r for r in results if r is not None]
        failed_locks = [r for r in results if r is None]

        # 少なくとも1つは成功し、残りはタイムアウトすることを確認
        self.assertGreaterEqual(len(successful_locks), 1)
        self.assertGreaterEqual(len(failed_locks), 1)
        self.assertEqual(len(successful_locks) + len(failed_locks), 3)


class TestLockPriority(unittest.TestCase):
    """LockPriority列挙型のテスト"""

    def test_lock_priority_values(self):
        """LockPriority列挙型の値のテスト"""
        self.assertEqual(LockPriority.LOW.value, 1)
        self.assertEqual(LockPriority.MEDIUM.value, 2)
        self.assertEqual(LockPriority.HIGH.value, 3)

    def test_lock_priority_ordering(self):
        """LockPriority列挙型の順序のテスト"""
        self.assertLess(LockPriority.LOW.value, LockPriority.MEDIUM.value)
        self.assertLess(LockPriority.MEDIUM.value, LockPriority.HIGH.value)
        self.assertGreater(LockPriority.HIGH.value, LockPriority.LOW.value)


if __name__ == "__main__":
    unittest.main()
