#!/usr/bin/env python3
"""
ORCH-Next Security Module
Implements HMAC signature verification, JWT authentication, and rate limiting
"""

import hashlib
import hmac
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)


class UserRole(Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    WORKER = "worker"


@dataclass
class User:
    user_id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


@dataclass
class RateLimitRule:
    endpoint: str
    method: str
    max_requests: int
    window_seconds: int
    per_user: bool = True


class SecurityManager:
    """
    Comprehensive security manager for ORCH-Next
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = Path(config.get("database", {}).get("path", "data/security.db"))

        # For in-memory databases, maintain a persistent connection
        if str(self.db_path) == ":memory:":
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._init_database_connection(self._conn)
        else:
            self._conn = None
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.init_database()

        # JWT settings
        self.jwt_secret = config.get("jwt", {}).get("secret_key", "your-secret-key")
        self.jwt_algorithm = config.get("jwt", {}).get("algorithm", "HS256")
        self.jwt_expiry_hours = config.get("jwt", {}).get("expiry_hours", 24)

        # HMAC settings
        self.webhook_secret = config.get("webhook", {}).get("secret", "your-webhook-secret")
        self.hmac_time_tolerance = config.get("webhook", {}).get("time_tolerance", 120)  # seconds

        # Rate limiting
        self.rate_limits = self._load_rate_limits(config.get("rate_limits", {}))

        # Security headers
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }

        self.init_database()
        self._cleanup_expired_tokens()

    def init_database(self):
        """Initialize security database schema"""
        # For in-memory databases, use the persistent connection if available
        if str(self.db_path) == ":memory:" and hasattr(self, "_conn") and self._conn:
            conn = self._conn
            self._init_database_connection(conn)
        else:
            with sqlite3.connect(self.db_path) as conn:
                self._init_database_connection(conn)

    def _init_database_connection(self, conn):
        """Initialize database schema on the given connection"""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP NOT NULL,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        """
        )

        # Create indexes separately
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jwt_tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                issued_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                is_revoked BOOLEAN DEFAULT FALSE,
                revoked_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """
        )

        # Create indexes separately
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jwt_tokens_user_id ON jwt_tokens(user_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jwt_tokens_expires_at ON jwt_tokens(expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jwt_tokens_token_hash ON jwt_tokens(token_hash)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit_records (
                record_id TEXT PRIMARY KEY,
                identifier TEXT NOT NULL,  -- user_id or IP
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                request_count INTEGER NOT NULL,
                window_start TIMESTAMP NOT NULL,
                window_end TIMESTAMP NOT NULL
            )
        """
        )

        # Create indexes separately
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_limit_identifier ON rate_limit_records(identifier, endpoint, method)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_limit_window_end ON rate_limit_records(window_end)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,  -- 'login', 'logout', 'failed_auth', 'rate_limit', 'hmac_fail'
                user_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                endpoint TEXT,
                details TEXT,  -- JSON
                timestamp TIMESTAMP NOT NULL
            )
        """
        )

        # Create indexes separately
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_type_timestamp ON security_events(event_type, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_user_timestamp ON security_events(user_id, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_ip_timestamp ON security_events(ip_address, timestamp)"
        )

        conn.commit()

    def _load_rate_limits(self, config: Dict[str, Any]) -> List[RateLimitRule]:
        """Load rate limiting rules from configuration"""
        rules = []

        # Default rules
        default_rules = [
            RateLimitRule("/dispatch", "POST", 100, 3600, True),  # 100 dispatches per hour per user
            RateLimitRule("/webhook", "POST", 1000, 3600, False),  # 1000 webhooks per hour total
            RateLimitRule(
                "/metrics", "GET", 300, 3600, True
            ),  # 300 metrics requests per hour per user
            RateLimitRule("*", "GET", 1000, 3600, True),  # 1000 GET requests per hour per user
            RateLimitRule("*", "POST", 200, 3600, True),  # 200 POST requests per hour per user
        ]

        # Add configured rules
        for rule_config in config.get("rules", []):
            rules.append(
                RateLimitRule(
                    endpoint=rule_config["endpoint"],
                    method=rule_config["method"],
                    max_requests=rule_config["max_requests"],
                    window_seconds=rule_config["window_seconds"],
                    per_user=rule_config.get("per_user", True),
                )
            )

        return default_rules + rules

    # User Management
    def create_user(self, username: str, email: str, password: str, role: UserRole) -> User:
        """Create a new user"""
        import uuid

        user_id = str(uuid.uuid4())
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        now = datetime.utcnow()

        try:
            # Use persistent connection for in-memory databases
            if str(self.db_path) == ":memory:" and self._conn:
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (user_id, username, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (user_id, username, email, password_hash, role.value, now.isoformat()),
                )
                self._conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()

                    cursor.execute(
                        """
                        INSERT INTO users (user_id, username, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (user_id, username, email, password_hash, role.value, now.isoformat()),
                    )

                    conn.commit()

            self._log_security_event(
                "user_created",
                user_id,
                details={"username": username, "email": email, "role": role.value},
            )

            return User(
                user_id=user_id,
                username=username,
                email=email,
                role=role,
                is_active=True,
                created_at=now,
            )

        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                raise HTTPException(status_code=400, detail="Username already exists")
            elif "email" in str(e):
                raise HTTPException(status_code=400, detail="Email already exists")
            else:
                raise HTTPException(status_code=400, detail="User creation failed")

    def authenticate_user(
        self, username: str, password: str, ip_address: str = None
    ) -> Optional[User]:
        """Authenticate user with username/password"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if user is locked
                cursor.execute(
                    """
                    SELECT user_id, username, email, password_hash, role, is_active, 
                           failed_login_attempts, locked_until
                    FROM users 
                    WHERE username = ?
                """,
                    (username,),
                )

                row = cursor.fetchone()
                if not row:
                    self._log_security_event(
                        "failed_auth",
                        None,
                        ip_address=ip_address,
                        details={"reason": "user_not_found", "username": username},
                    )
                    return None

                (
                    user_id,
                    username,
                    email,
                    password_hash,
                    role,
                    is_active,
                    failed_attempts,
                    locked_until,
                ) = row

                # Check if account is locked
                if locked_until:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.utcnow() < lock_time:
                        self._log_security_event(
                            "failed_auth",
                            user_id,
                            ip_address=ip_address,
                            details={"reason": "account_locked"},
                        )
                        raise HTTPException(status_code=423, detail="Account is locked")

                # Check if account is active
                if not is_active:
                    self._log_security_event(
                        "failed_auth",
                        user_id,
                        ip_address=ip_address,
                        details={"reason": "account_inactive"},
                    )
                    raise HTTPException(status_code=403, detail="Account is inactive")

                # Verify password
                if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
                    # Increment failed attempts
                    new_failed_attempts = failed_attempts + 1

                    # Lock account after 5 failed attempts
                    if new_failed_attempts >= 5:
                        lock_until = datetime.utcnow() + timedelta(minutes=30)
                        cursor.execute(
                            """
                            UPDATE users 
                            SET failed_login_attempts = ?, locked_until = ?
                            WHERE user_id = ?
                        """,
                            (new_failed_attempts, lock_until.isoformat(), user_id),
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE users 
                            SET failed_login_attempts = ?
                            WHERE user_id = ?
                        """,
                            (new_failed_attempts, user_id),
                        )

                    conn.commit()

                    self._log_security_event(
                        "failed_auth",
                        user_id,
                        ip_address=ip_address,
                        details={"reason": "invalid_password", "attempts": new_failed_attempts},
                    )
                    return None

                # Successful authentication - reset failed attempts and update last login
                cursor.execute(
                    """
                    UPDATE users 
                    SET failed_login_attempts = 0, locked_until = NULL, last_login = ?
                    WHERE user_id = ?
                """,
                    (datetime.utcnow().isoformat(), user_id),
                )

                conn.commit()

                self._log_security_event("login", user_id, ip_address=ip_address)

                return User(
                    user_id=user_id,
                    username=username,
                    email=email,
                    role=UserRole(role),
                    is_active=bool(is_active),
                    created_at=datetime.utcnow(),  # Would need to fetch from DB
                    last_login=datetime.utcnow(),
                )

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT username, email, role, is_active, created_at, last_login
                    FROM users 
                    WHERE user_id = ?
                """,
                    (user_id,),
                )

                row = cursor.fetchone()
                if row:
                    username, email, role, is_active, created_at, last_login = row

                    return User(
                        user_id=user_id,
                        username=username,
                        email=email,
                        role=UserRole(role),
                        is_active=bool(is_active),
                        created_at=datetime.fromisoformat(created_at),
                        last_login=datetime.fromisoformat(last_login) if last_login else None,
                    )

                return None

        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None

    # JWT Token Management
    def create_jwt_token(self, user: User) -> str:
        """Create JWT token for user"""
        import uuid

        token_id = str(uuid.uuid4())
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=self.jwt_expiry_hours)

        payload = {
            "token_id": token_id,
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Store token in database
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO jwt_tokens (token_id, user_id, token_hash, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (token_id, user.user_id, token_hash, now.isoformat(), expires_at.isoformat()),
                )

                conn.commit()

        except Exception as e:
            logger.error(f"Error storing JWT token: {e}")
            raise HTTPException(status_code=500, detail="Token creation failed")

        return token

    def verify_jwt_token(self, token: str) -> Optional[User]:
        """Verify JWT token and return user"""
        try:
            # Decode token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            token_id = payload.get("token_id")
            user_id = payload.get("user_id")

            if not token_id or not user_id:
                return None

            # Check if token is revoked
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT is_revoked FROM jwt_tokens 
                    WHERE token_id = ? AND token_hash = ? AND expires_at > ?
                """,
                    (token_id, token_hash, datetime.utcnow().isoformat()),
                )

                row = cursor.fetchone()
                if not row or row[0]:  # Token not found or revoked
                    return None

            # Get user
            return self.get_user_by_id(user_id)

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            logger.error(f"JWT verification error: {e}")
            return None

    def revoke_jwt_token(self, token: str) -> bool:
        """Revoke JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            token_id = payload.get("token_id")

            if not token_id:
                return False

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    UPDATE jwt_tokens 
                    SET is_revoked = TRUE, revoked_at = ?
                    WHERE token_id = ?
                """,
                    (datetime.utcnow().isoformat(), token_id),
                )

                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False

    # HMAC Signature Verification
    def verify_hmac_signature(self, payload: bytes, signature: str, timestamp: str = None) -> bool:
        """Verify HMAC signature for webhooks"""
        try:
            # Check timestamp if provided (prevent replay attacks)
            if timestamp:
                try:
                    request_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    now = datetime.utcnow()
                    time_diff = abs((now - request_time.replace(tzinfo=None)).total_seconds())

                    if time_diff > self.hmac_time_tolerance:
                        self._log_security_event(
                            "hmac_fail",
                            None,
                            details={"reason": "timestamp_out_of_range", "time_diff": time_diff},
                        )
                        return False
                except ValueError:
                    self._log_security_event(
                        "hmac_fail", None, details={"reason": "invalid_timestamp_format"}
                    )
                    return False

            # Verify signature
            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            # Remove 'sha256=' prefix if present
            if signature.startswith("sha256="):
                signature = signature[7:]

            is_valid = hmac.compare_digest(expected_signature, signature)

            if not is_valid:
                self._log_security_event(
                    "hmac_fail", None, details={"reason": "signature_mismatch"}
                )

            return is_valid

        except Exception as e:
            logger.error(f"HMAC verification error: {e}")
            self._log_security_event(
                "hmac_fail", None, details={"reason": "verification_error", "error": str(e)}
            )
            return False

    # Rate Limiting
    def check_rate_limit(
        self, identifier: str, endpoint: str, method: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limits

        Returns:
            (is_allowed, rate_limit_info)
        """
        # Find applicable rate limit rule
        rule = self._find_rate_limit_rule(endpoint, method)
        if not rule:
            return True, {}

        now = datetime.utcnow()
        window_start = now - timedelta(seconds=rule.window_seconds)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get current request count in window
                cursor.execute(
                    """
                    SELECT SUM(request_count) 
                    FROM rate_limit_records 
                    WHERE identifier = ? AND endpoint = ? AND method = ? 
                    AND window_end > ?
                """,
                    (identifier, endpoint, method, window_start.isoformat()),
                )

                row = cursor.fetchone()
                current_count = row[0] if row[0] else 0

                # Check if limit exceeded
                if current_count >= rule.max_requests:
                    self._log_security_event(
                        "rate_limit",
                        None,
                        details={
                            "identifier": identifier,
                            "endpoint": endpoint,
                            "method": method,
                            "current_count": current_count,
                            "limit": rule.max_requests,
                        },
                    )

                    return False, {
                        "limit": rule.max_requests,
                        "remaining": 0,
                        "reset_time": (now + timedelta(seconds=rule.window_seconds)).isoformat(),
                        "retry_after": rule.window_seconds,
                    }

                # Record this request
                self._record_rate_limit_request(
                    identifier, endpoint, method, now, rule.window_seconds
                )

                return True, {
                    "limit": rule.max_requests,
                    "remaining": rule.max_requests - current_count - 1,
                    "reset_time": (now + timedelta(seconds=rule.window_seconds)).isoformat(),
                }

        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            # Allow request on error (fail open)
            return True, {}

    def _find_rate_limit_rule(self, endpoint: str, method: str) -> Optional[RateLimitRule]:
        """Find applicable rate limit rule"""
        # Exact match first
        for rule in self.rate_limits:
            if rule.endpoint == endpoint and rule.method == method:
                return rule

        # Wildcard endpoint match
        for rule in self.rate_limits:
            if rule.endpoint == "*" and rule.method == method:
                return rule

        # Wildcard method match
        for rule in self.rate_limits:
            if rule.endpoint == endpoint and rule.method == "*":
                return rule

        # Full wildcard
        for rule in self.rate_limits:
            if rule.endpoint == "*" and rule.method == "*":
                return rule

        return None

    def _record_rate_limit_request(
        self, identifier: str, endpoint: str, method: str, timestamp: datetime, window_seconds: int
    ):
        """Record a rate limit request"""
        import uuid

        record_id = str(uuid.uuid4())
        window_end = timestamp + timedelta(seconds=window_seconds)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Try to update existing record in current window
                cursor.execute(
                    """
                    UPDATE rate_limit_records 
                    SET request_count = request_count + 1
                    WHERE identifier = ? AND endpoint = ? AND method = ? 
                    AND window_start <= ? AND window_end > ?
                """,
                    (identifier, endpoint, method, timestamp.isoformat(), timestamp.isoformat()),
                )

                if cursor.rowcount == 0:
                    # Create new record
                    cursor.execute(
                        """
                        INSERT INTO rate_limit_records 
                        (record_id, identifier, endpoint, method, request_count, window_start, window_end)
                        VALUES (?, ?, ?, ?, 1, ?, ?)
                    """,
                        (
                            record_id,
                            identifier,
                            endpoint,
                            method,
                            timestamp.isoformat(),
                            window_end.isoformat(),
                        ),
                    )

                conn.commit()

        except Exception as e:
            logger.error(f"Error recording rate limit request: {e}")

    # Security Event Logging
    def _log_security_event(
        self,
        event_type: str,
        user_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
        endpoint: str = None,
        details: Dict[str, Any] = None,
    ):
        """Log security event"""
        import uuid

        event_id = str(uuid.uuid4())

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO security_events 
                    (event_id, event_type, user_id, ip_address, user_agent, endpoint, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        event_id,
                        event_type,
                        user_id,
                        ip_address,
                        user_agent,
                        endpoint,
                        json.dumps(details) if details else None,
                        datetime.utcnow().isoformat(),
                    ),
                )

                conn.commit()

        except Exception as e:
            logger.error(f"Error logging security event: {e}")

    # Cleanup and Maintenance
    def _cleanup_expired_tokens(self):
        """Clean up expired JWT tokens"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Delete expired tokens
                cursor.execute(
                    """
                    DELETE FROM jwt_tokens 
                    WHERE expires_at <= ?
                """,
                    (datetime.utcnow().isoformat(),),
                )

                deleted_count = cursor.rowcount

                # Clean up old rate limit records
                cleanup_time = datetime.utcnow() - timedelta(days=7)
                cursor.execute(
                    """
                    DELETE FROM rate_limit_records 
                    WHERE window_end <= ?
                """,
                    (cleanup_time.isoformat(),),
                )

                # Clean up old security events (keep 30 days)
                cleanup_time = datetime.utcnow() - timedelta(days=30)
                cursor.execute(
                    """
                    DELETE FROM security_events 
                    WHERE timestamp <= ?
                """,
                    (cleanup_time.isoformat(),),
                )

                conn.commit()

                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} expired tokens")

        except Exception as e:
            logger.error(f"Token cleanup error: {e}")

    def get_security_statistics(self) -> Dict[str, Any]:
        """Get security statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Active users
                cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
                active_users = cursor.fetchone()[0]

                # Active tokens
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM jwt_tokens 
                    WHERE expires_at > ? AND is_revoked = FALSE
                """,
                    (datetime.utcnow().isoformat(),),
                )
                active_tokens = cursor.fetchone()[0]

                # Recent security events (last 24 hours)
                day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
                cursor.execute(
                    """
                    SELECT event_type, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp > ? 
                    GROUP BY event_type
                """,
                    (day_ago,),
                )

                recent_events = dict(cursor.fetchall())

                return {
                    "active_users": active_users,
                    "active_tokens": active_tokens,
                    "recent_events": recent_events,
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error getting security statistics: {e}")
            return {}


# FastAPI Dependencies
security_bearer = HTTPBearer()


def get_security_manager() -> SecurityManager:
    """Dependency to get security manager"""
    # This would be configured with actual settings
    config = {
        "database": {"path": "data/security.db"},
        "jwt": {"secret_key": "your-jwt-secret-key", "algorithm": "HS256", "expiry_hours": 24},
        "webhook": {"secret": "your-webhook-secret", "time_tolerance": 120},
        "rate_limits": {"rules": []},
    }
    return SecurityManager(config)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
    security_manager: SecurityManager = Depends(get_security_manager),
) -> User:
    """Dependency to get current authenticated user"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = security_manager.verify_jwt_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user


def require_role(required_role: UserRole):
    """Decorator to require specific role"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get current user from kwargs (injected by FastAPI)
            current_user = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")

            # Check role hierarchy: ADMIN > OPERATOR > VIEWER > WORKER
            role_hierarchy = {
                UserRole.ADMIN: 4,
                UserRole.OPERATOR: 3,
                UserRole.VIEWER: 2,
                UserRole.WORKER: 1,
            }

            if role_hierarchy.get(current_user.role, 0) < role_hierarchy.get(required_role, 0):
                raise HTTPException(status_code=403, detail="Insufficient permissions")

            return func(*args, **kwargs)

        return wrapper

    return decorator


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    config = {
        "database": {"path": "test_security.db"},
        "jwt": {"secret_key": "test-secret"},
        "webhook": {"secret": "test-webhook-secret"},
        "rate_limits": {"rules": []},
    }

    security_manager = SecurityManager(config)

    # Create test user
    user = security_manager.create_user(
        username="testuser",
        email="test@example.com",
        password="testpassword",
        role=UserRole.OPERATOR,
    )

    print(f"Created user: {user}")

    # Test authentication
    auth_user = security_manager.authenticate_user("testuser", "testpassword")
    if auth_user:
        # Create JWT token
        token = security_manager.create_jwt_token(auth_user)
        print(f"JWT token: {token}")

        # Verify token
        verified_user = security_manager.verify_jwt_token(token)
        print(f"Verified user: {verified_user}")

    # Test HMAC
    payload = b'{"test": "data"}'
    signature = hmac.new(b"test-webhook-secret", payload, hashlib.sha256).hexdigest()

    is_valid = security_manager.verify_hmac_signature(payload, f"sha256={signature}")
    print(f"HMAC valid: {is_valid}")

    # Test rate limiting
    allowed, info = security_manager.check_rate_limit("test_user", "/test", "GET")
    print(f"Rate limit allowed: {allowed}, info: {info}")

    # Get statistics
    stats = security_manager.get_security_statistics()
    print(f"Security stats: {stats}")
