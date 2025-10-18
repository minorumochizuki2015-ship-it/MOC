#!/usr/bin/env python3
"""
Tests for ORCH-Next Security Module
"""

import hashlib
import hmac
import json
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from src.security import (
    RateLimitRule,
    SecurityManager,
    User,
    UserRole,
    get_current_user,
    require_role,
)


class TestSecurityManager:
    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path for testing (Windows lock-safe)"""
        import os

        fd, path = tempfile.mkstemp(suffix=".db")
        # Close the file descriptor immediately to avoid Windows file locking issues
        os.close(fd)
        try:
            yield path
        finally:
            # Attempt graceful cleanup; Windows may hold WAL/SHM handles briefly
            try:
                Path(path).unlink(missing_ok=True)
            except PermissionError:
                import sqlite3
                import time

                try:
                    # Ensure no WAL checkpoints are pending
                    conn = sqlite3.connect(path)
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    conn.close()
                except Exception:
                    pass
                time.sleep(0.2)
                try:
                    Path(path).unlink(missing_ok=True)
                except PermissionError:
                    # Final fallback: leave temp file; tests should still pass
                    pass

    @pytest.fixture
    def security_config(self, temp_db_path):
        """Test security configuration"""
        return {
            "database": {"path": temp_db_path},
            "jwt": {
                "secret_key": "test-jwt-secret-key",
                "algorithm": "HS256",
                "expiry_hours": 24,
            },
            "webhook": {"secret": "test-webhook-secret", "time_tolerance": 120},
            "rate_limits": {
                "rules": [
                    {
                        "endpoint": "/test",
                        "method": "GET",
                        "max_requests": 10,
                        "window_seconds": 3600,
                        "per_user": True,
                    }
                ]
            },
        }

    @pytest.fixture
    def security_manager(self, security_config):
        """Create security manager instance"""
        return SecurityManager(security_config)

    def test_database_initialization(self, security_manager):
        """Test database schema initialization"""
        # Database should be created and tables should exist
        import sqlite3

        with sqlite3.connect(security_manager.db_path) as conn:
            cursor = conn.cursor()

            # Check if tables exist
            cursor.execute(
                """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('users', 'jwt_tokens', 'rate_limit_records', 'security_events')
            """
            )

            tables = [row[0] for row in cursor.fetchall()]

            assert "users" in tables
            assert "jwt_tokens" in tables
            assert "rate_limit_records" in tables
            assert "security_events" in tables

    def test_create_user(self, security_manager):
        """Test user creation"""
        user = security_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword123",
            role=UserRole.OPERATOR,
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.OPERATOR
        assert user.is_active is True
        assert user.user_id is not None

    def test_create_duplicate_user(self, security_manager):
        """Test creating duplicate user fails"""
        security_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="password123",
            role=UserRole.VIEWER,
        )

        # Try to create user with same username
        with pytest.raises(HTTPException) as exc_info:
            security_manager.create_user(
                username="testuser",
                email="different@example.com",
                password="password123",
                role=UserRole.VIEWER,
            )

        assert exc_info.value.status_code == 400
        assert "Username already exists" in str(exc_info.value.detail)

    def test_authenticate_user_success(self, security_manager):
        """Test successful user authentication"""
        # Create user
        created_user = security_manager.create_user(
            username="authuser",
            email="auth@example.com",
            password="authpassword123",
            role=UserRole.ADMIN,
        )

        # Authenticate
        auth_user = security_manager.authenticate_user("authuser", "authpassword123")

        assert auth_user is not None
        assert auth_user.username == "authuser"
        assert auth_user.role == UserRole.ADMIN
        assert auth_user.user_id == created_user.user_id

    def test_authenticate_user_invalid_password(self, security_manager):
        """Test authentication with invalid password"""
        security_manager.create_user(
            username="authuser",
            email="auth@example.com",
            password="correctpassword",
            role=UserRole.VIEWER,
        )

        # Try with wrong password
        auth_user = security_manager.authenticate_user("authuser", "wrongpassword")
        assert auth_user is None

    def test_authenticate_user_not_found(self, security_manager):
        """Test authentication with non-existent user"""
        auth_user = security_manager.authenticate_user("nonexistent", "password")
        assert auth_user is None

    def test_account_lockout(self, security_manager):
        """Test account lockout after failed attempts"""
        security_manager.create_user(
            username="lockuser",
            email="lock@example.com",
            password="correctpassword",
            role=UserRole.VIEWER,
        )

        # Make 5 failed attempts
        for i in range(5):
            auth_user = security_manager.authenticate_user("lockuser", "wrongpassword")
            assert auth_user is None

        # Account should be locked now
        with pytest.raises(HTTPException) as exc_info:
            security_manager.authenticate_user("lockuser", "correctpassword")

        assert exc_info.value.status_code == 423
        assert "Account is locked" in str(exc_info.value.detail)

    def test_jwt_token_creation_and_verification(self, security_manager):
        """Test JWT token creation and verification"""
        user = security_manager.create_user(
            username="jwtuser",
            email="jwt@example.com",
            password="jwtpassword",
            role=UserRole.OPERATOR,
        )

        # Create token
        token = security_manager.create_jwt_token(user)
        assert token is not None

        # Verify token
        verified_user = security_manager.verify_jwt_token(token)
        assert verified_user is not None
        assert verified_user.user_id == user.user_id
        assert verified_user.username == user.username
        assert verified_user.role == user.role

    def test_jwt_token_expiry(self, security_manager):
        """Test JWT token expiry"""
        user = security_manager.create_user(
            username="expireuser",
            email="expire@example.com",
            password="expirepassword",
            role=UserRole.VIEWER,
        )

        # Create token with short expiry
        with patch.object(security_manager, "jwt_expiry_hours", 0):  # Expire immediately
            token = security_manager.create_jwt_token(user)

        # Token should be expired
        time.sleep(1)  # Ensure time has passed
        verified_user = security_manager.verify_jwt_token(token)
        assert verified_user is None

    def test_jwt_token_revocation(self, security_manager):
        """Test JWT token revocation"""
        user = security_manager.create_user(
            username="revokeuser",
            email="revoke@example.com",
            password="revokepassword",
            role=UserRole.ADMIN,
        )

        # Create and verify token
        token = security_manager.create_jwt_token(user)
        verified_user = security_manager.verify_jwt_token(token)
        assert verified_user is not None

        # Revoke token
        revoked = security_manager.revoke_jwt_token(token)
        assert revoked is True

        # Token should no longer be valid
        verified_user = security_manager.verify_jwt_token(token)
        assert verified_user is None

    def test_hmac_signature_verification_success(self, security_manager):
        """Test successful HMAC signature verification"""
        # Use current timestamp for embedded timestamp in payload
        current_timestamp = datetime.utcnow().isoformat() + "Z"
        payload_dict = {"test": "data", "timestamp": current_timestamp}

        # Create canonical JSON payload (sorted keys, no spaces)
        canonical_payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        payload_bytes = canonical_payload.encode("utf-8")

        # Create valid signature using canonical payload
        signature = hmac.new(
            security_manager.webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        # Verify signature (no external timestamp needed due to embedded timestamp)
        is_valid = security_manager.verify_hmac_signature(payload_bytes, f"sha256={signature}")
        assert is_valid is True

    def test_hmac_signature_verification_invalid(self, security_manager):
        """Test HMAC signature verification with invalid signature"""
        payload = b'{"test": "data"}'
        invalid_signature = "invalid_signature"

        is_valid = security_manager.verify_hmac_signature(payload, invalid_signature)
        assert is_valid is False

    def test_hmac_timestamp_tolerance(self, security_manager):
        """Test HMAC timestamp tolerance"""
        # Create canonical JSON payload
        payload_dict = {"test": "data"}
        canonical_payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        payload_bytes = canonical_payload.encode("utf-8")

        # Test with old timestamp (beyond tolerance) using contract-style format
        old_timestamp = (datetime.utcnow() - timedelta(seconds=300)).isoformat() + "Z"
        # Create signature for old timestamp using timestamp.payload format
        old_message = f"{old_timestamp}.{canonical_payload}".encode("utf-8")
        old_signature = hmac.new(
            security_manager.webhook_secret.encode("utf-8"), old_message, hashlib.sha256
        ).hexdigest()
        is_valid = security_manager.verify_hmac_signature(
            payload_bytes, f"t={old_timestamp},v1={old_signature}"
        )
        assert is_valid is False

        # Test with recent timestamp (within tolerance) using contract-style format
        recent_timestamp = (datetime.utcnow() - timedelta(seconds=60)).isoformat() + "Z"
        # Create signature for recent timestamp using timestamp.payload format
        recent_message = f"{recent_timestamp}.{canonical_payload}".encode("utf-8")
        recent_signature = hmac.new(
            security_manager.webhook_secret.encode("utf-8"),
            recent_message,
            hashlib.sha256,
        ).hexdigest()
        is_valid = security_manager.verify_hmac_signature(
            payload_bytes, f"t={recent_timestamp},v1={recent_signature}"
        )
        assert is_valid is True

    def test_rate_limiting_within_limit(self, security_manager):
        """Test rate limiting within allowed limits"""
        # Make requests within limit
        for i in range(5):
            allowed, info = security_manager.check_rate_limit("user1", "/test", "GET")
            assert allowed is True
            assert info["remaining"] >= 0

    def test_rate_limiting_exceed_limit(self, security_manager):
        """Test rate limiting when exceeding limits"""
        # Make requests up to limit
        for i in range(10):
            allowed, info = security_manager.check_rate_limit("user2", "/test", "GET")
            assert allowed is True

        # Next request should be denied
        allowed, info = security_manager.check_rate_limit("user2", "/test", "GET")
        assert allowed is False
        assert info["remaining"] == 0
        assert "retry_after" in info

    def test_rate_limiting_different_users(self, security_manager):
        """Test rate limiting is per-user"""
        # User1 makes requests up to limit
        for i in range(10):
            allowed, info = security_manager.check_rate_limit("user1", "/test", "GET")
            assert allowed is True

        # User1 should be limited
        allowed, info = security_manager.check_rate_limit("user1", "/test", "GET")
        assert allowed is False

        # User2 should still be allowed
        allowed, info = security_manager.check_rate_limit("user2", "/test", "GET")
        assert allowed is True

    def test_rate_limiting_wildcard_rules(self, security_manager):
        """Test rate limiting with wildcard rules"""
        # Should match wildcard rule for unknown endpoint
        allowed, info = security_manager.check_rate_limit("user1", "/unknown", "GET")
        assert allowed is True  # Should use default wildcard rule

    def test_security_event_logging(self, security_manager):
        """Test security event logging"""
        # Create user to generate events
        user = security_manager.create_user(
            username="eventuser",
            email="event@example.com",
            password="eventpassword",
            role=UserRole.VIEWER,
        )

        # Authenticate to generate login event
        security_manager.authenticate_user("eventuser", "eventpassword", "192.168.1.1")

        # Check events were logged
        import sqlite3

        with sqlite3.connect(security_manager.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT event_type, user_id, ip_address 
                FROM security_events 
                WHERE user_id = ?
                ORDER BY timestamp DESC
            """,
                (user.user_id,),
            )

            events = cursor.fetchall()

            # Should have user_created and login events
            event_types = [event[0] for event in events]
            assert "user_created" in event_types
            assert "login" in event_types

            # Check IP address was logged
            login_events = [event for event in events if event[0] == "login"]
            assert len(login_events) > 0
            assert login_events[0][2] == "192.168.1.1"

    def test_cleanup_expired_tokens(self, security_manager):
        """Test cleanup of expired tokens"""
        user = security_manager.create_user(
            username="cleanupuser",
            email="cleanup@example.com",
            password="cleanuppassword",
            role=UserRole.VIEWER,
        )

        # Create token
        token = security_manager.create_jwt_token(user)

        # Manually expire the token in database
        import sqlite3

        with sqlite3.connect(security_manager.db_path) as conn:
            cursor = conn.cursor()

            expired_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cursor.execute(
                """
                UPDATE jwt_tokens 
                SET expires_at = ?
                WHERE user_id = ?
            """,
                (expired_time, user.user_id),
            )

            conn.commit()

        # Run cleanup
        security_manager._cleanup_expired_tokens()

        # Token should be removed
        with sqlite3.connect(security_manager.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT COUNT(*) FROM jwt_tokens 
                WHERE user_id = ?
            """,
                (user.user_id,),
            )

            count = cursor.fetchone()[0]
            assert count == 0

    def test_security_statistics(self, security_manager):
        """Test security statistics generation"""
        # Create some users and tokens
        user1 = security_manager.create_user(
            username="statsuser1",
            email="stats1@example.com",
            password="statspassword",
            role=UserRole.ADMIN,
        )

        user2 = security_manager.create_user(
            username="statsuser2",
            email="stats2@example.com",
            password="statspassword",
            role=UserRole.VIEWER,
        )

        # Create tokens
        token1 = security_manager.create_jwt_token(user1)
        token2 = security_manager.create_jwt_token(user2)

        # Get statistics
        stats = security_manager.get_security_statistics()

        assert "active_users" in stats
        assert "active_tokens" in stats
        assert "recent_events" in stats
        assert "timestamp" in stats

        assert stats["active_users"] >= 2
        assert stats["active_tokens"] >= 2


class TestFastAPIIntegration:
    @pytest.fixture
    def mock_security_manager(self):
        """Mock security manager for FastAPI tests"""
        manager = MagicMock()

        # Mock user
        mock_user = User(
            user_id="test-user-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.OPERATOR,
            is_active=True,
            created_at=datetime.utcnow(),
        )

        manager.verify_jwt_token.return_value = mock_user
        return manager

    def test_get_current_user_valid_token(self, mock_security_manager):
        """Test get_current_user with valid token"""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-jwt-token")

        with patch("src.security.get_security_manager", return_value=mock_security_manager):
            user = get_current_user(credentials, mock_security_manager)

            assert user.username == "testuser"
            assert user.role == UserRole.OPERATOR
            mock_security_manager.verify_jwt_token.assert_called_once_with("valid-jwt-token")

    def test_get_current_user_invalid_token(self, mock_security_manager):
        """Test get_current_user with invalid token"""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid-jwt-token")

        mock_security_manager.verify_jwt_token.return_value = None

        with patch("src.security.get_security_manager", return_value=mock_security_manager):
            with pytest.raises(HTTPException) as exc_info:
                get_current_user(credentials, mock_security_manager)

            assert exc_info.value.status_code == 401
            assert "Invalid or expired token" in str(exc_info.value.detail)

    def test_require_role_decorator(self):
        """Test require_role decorator"""

        @require_role(UserRole.ADMIN)
        def admin_function(current_user=None):
            return "admin_access"

        # Test with admin user
        admin_user = User(
            user_id="admin-id",
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            is_active=True,
            created_at=datetime.utcnow(),
        )

        result = admin_function(current_user=admin_user)
        assert result == "admin_access"

        # Test with insufficient role
        viewer_user = User(
            user_id="viewer-id",
            username="viewer",
            email="viewer@example.com",
            role=UserRole.VIEWER,
            is_active=True,
            created_at=datetime.utcnow(),
        )

        with pytest.raises(HTTPException) as exc_info:
            admin_function(current_user=viewer_user)

        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in str(exc_info.value.detail)


class TestRateLimitRule:
    def test_rate_limit_rule_creation(self):
        """Test RateLimitRule creation"""
        rule = RateLimitRule(
            endpoint="/api/test",
            method="POST",
            max_requests=100,
            window_seconds=3600,
            per_user=True,
        )

        assert rule.endpoint == "/api/test"
        assert rule.method == "POST"
        assert rule.max_requests == 100
        assert rule.window_seconds == 3600
        assert rule.per_user is True


class TestUserRole:
    def test_user_role_enum(self):
        """Test UserRole enum values"""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.OPERATOR.value == "operator"
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.WORKER.value == "worker"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
