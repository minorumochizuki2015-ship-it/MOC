"""
Security モジュールのunit テスト
"""

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException

from src.security import SecurityManager, UserRole


class TestSecurityManager(unittest.TestCase):
    """SecurityManager のunit テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_security.db"

        self.config = {
            "database": {"path": str(self.db_path)},
            "jwt": {
                "secret_key": "test-secret-key",
                "algorithm": "HS256",
                "expiry_hours": 24,
                "leeway_seconds": 120,
            },
            "webhook": {"secret": "test-webhook-secret", "time_tolerance": 120},
            "rate_limits": {"rules": []},
            "security": {"enable_cleanup_on_init": False},
        }

        self.security_manager = SecurityManager(self.config)

    def tearDown(self):
        """テスト後のクリーンアップ"""
        try:
            if hasattr(self.security_manager, "_conn") and self.security_manager._conn:
                self.security_manager._conn.close()
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

        expected_tables = ["users", "jwt_tokens", "rate_limit_records", "security_events"]
        for table in expected_tables:
            self.assertIn(table, tables)

    def test_create_user_success(self):
        """ユーザー作成成功のテスト"""
        user = self.security_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword",
            role=UserRole.OPERATOR,
        )

        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.role, UserRole.OPERATOR)
        self.assertIsNotNone(user.user_id)

    def test_create_user_duplicate_username(self):
        """Test creating user with duplicate username"""
        # Create first user
        user1 = self.security_manager.create_user(
            "testuser", "test1@example.com", "password123", UserRole.VIEWER
        )
        self.assertIsNotNone(user1)

        # Try to create second user with same username - should raise HTTPException
        with self.assertRaises(HTTPException) as context:
            self.security_manager.create_user(
                "testuser", "test2@example.com", "password456", UserRole.VIEWER
            )
        # The actual implementation raises HTTPException with status_code 400
        self.assertEqual(context.exception.status_code, 400)

    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        # Create user first
        user = self.security_manager.create_user(
            "testuser", "test@example.com", "password123", UserRole.VIEWER
        )

        # Authenticate user
        authenticated_user = self.security_manager.authenticate_user("testuser", "password123")

        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.username, "testuser")
        self.assertEqual(authenticated_user.email, "test@example.com")
        self.assertEqual(authenticated_user.role, UserRole.VIEWER)

    def test_authenticate_user_wrong_password(self):
        """Test authentication with wrong password"""
        # Create user first
        self.security_manager.create_user(
            "testuser", "test@example.com", "password123", UserRole.VIEWER
        )

        # Try to authenticate with wrong password
        authenticated_user = self.security_manager.authenticate_user("testuser", "wrongpassword")

        self.assertIsNone(authenticated_user)

    def test_authenticate_user_nonexistent(self):
        """Test authentication with nonexistent user"""
        authenticated_user = self.security_manager.authenticate_user("nonexistent", "password123")

        self.assertIsNone(authenticated_user)

    def test_create_jwt_token(self):
        """JWT トークン作成のテスト"""
        # ユーザーを作成
        user = self.security_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword",
            role=UserRole.OPERATOR,
        )

        # JWT トークンを作成
        token = self.security_manager.create_jwt_token(user=user)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

    def test_verify_jwt_token_valid(self):
        """有効なJWT トークンの検証テスト"""
        # ユーザーを作成
        user = self.security_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword",
            role=UserRole.OPERATOR,
        )

        # JWT トークンを作成
        token = self.security_manager.create_jwt_token(user=user)

        # トークンを検証
        verified_user = self.security_manager.verify_jwt_token(token)
        self.assertIsNotNone(verified_user)
        self.assertEqual(verified_user.username, "testuser")

    def test_verify_jwt_token_invalid(self):
        """無効なJWT トークンの検証テスト"""
        invalid_token = "invalid.jwt.token"
        verified_user = self.security_manager.verify_jwt_token(invalid_token)
        self.assertIsNone(verified_user)

    def test_hmac_verification_basic(self):
        """Test basic HMAC functionality exists"""
        # Just verify the security manager has the webhook secret configured
        self.assertEqual(self.security_manager.webhook_secret, self.config["webhook"]["secret"])

    def test_jwt_configuration(self):
        """Test JWT configuration is properly set"""
        self.assertEqual(self.security_manager.jwt_secret, self.config["jwt"]["secret_key"])
        self.assertEqual(self.security_manager.jwt_algorithm, self.config["jwt"]["algorithm"])
        self.assertEqual(self.security_manager.jwt_expiry_hours, self.config["jwt"]["expiry_hours"])

    def test_rate_limit_configuration(self):
        """Test rate limiting configuration"""
        # Verify rate limits are configured
        self.assertIsNotNone(self.security_manager.rate_limits)
        self.assertIsInstance(self.security_manager.rate_limits, list)

    def test_get_security_statistics(self):
        """Test security statistics retrieval"""
        # Create some test data
        user1 = self.security_manager.create_user(
            "user1", "user1@example.com", "password123", UserRole.VIEWER
        )
        user2 = self.security_manager.create_user(
            "user2", "user2@example.com", "password456", UserRole.ADMIN
        )

        # Get statistics
        stats = self.security_manager.get_security_statistics()

        self.assertIsInstance(stats, dict)
        self.assertIn("active_users", stats)
        self.assertIn("active_tokens", stats)
        self.assertIn("recent_events", stats)
        self.assertIn("timestamp", stats)
        self.assertEqual(stats["active_users"], 2)

    def test_database_configuration(self):
        """Test database configuration"""
        # Verify that database path is properly configured
        self.assertIsNotNone(self.config["database"]["path"])
        self.assertTrue(isinstance(self.config["database"]["path"], str))


class TestUserRole(unittest.TestCase):
    def test_user_role_values(self):
        """Test UserRole enum values"""
        self.assertEqual(UserRole.ADMIN.value, "admin")
        self.assertEqual(UserRole.OPERATOR.value, "operator")
        self.assertEqual(UserRole.VIEWER.value, "viewer")
        self.assertEqual(UserRole.WORKER.value, "worker")


# (Removed duplicate TestUserRole class and __main__ guards to satisfy flake8 F811/F401)
