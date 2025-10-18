"""
セキュリティ管理システム（インメモリ版・レガシー）
認証、暗号化、アクセス制御を統合管理。

注意:
- 本モジュールの SecurityManager はインメモリ実装です。高信頼な永続化/レート制限/監査を備える
  DB版は `src.security.SecurityManager` を参照してください。
- 既存互換のため当面このクラスを維持しますが、段階的に `InMemorySecurityManager` へ移行予定です。
"""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import time
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecurityManager:
    """セキュリティ管理システム"""

    def __init__(self, config_path: str = "config/security.json"):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.config = self._load_config()

        # 暗号化キー管理
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)

        # JWT設定
        self.jwt_secret = self._get_or_create_jwt_secret()
        self.jwt_algorithm = "HS256"
        self.jwt_expiry_hours = 24

        # ユーザー管理
        self.users: Dict[str, Dict] = {}

        # セッション管理
        self.sessions: Dict[str, Dict] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.failed_attempts: Dict[str, List[float]] = {}

        # 監査ログ
        self.audit_logs: List[Dict] = []

        # アクセス制御
        self.permissions: Dict[str, List[str]] = {}
        self.roles: Dict[str, List[str]] = {}

        # IPホワイトリスト
        self.ip_whitelist: List[str] = []

        # レート制限
        self.rate_limits: Dict[str, List[float]] = {}

        # セキュリティポリシー
        self.security_policies = {
            "max_failed_attempts": 5,
            "lockout_duration": 300,  # 5分
            "password_min_length": 8,
            "password_require_special": True,
            "session_timeout": 3600,  # 1時間
            "allowed_ip_ranges": ["127.0.0.1/32", "192.168.0.0/16"],
            "rate_limit_per_minute": 10,
        }

        # レガシー利用の明示（Deprecation通知・アプリでは DB版の利用を推奨）
        try:
            warnings.warn(
                (
                    "security_manager.SecurityManager はインメモリ版（レガシー）です。"
                    "アプリケーションでの永続化・監査が必要な場合は src.security.SecurityManager を使用してください。"
                ),
                category=DeprecationWarning,
                stacklevel=2,
            )
        except Exception:
            pass
        self.logger.info("SecurityManager初期化完了（in-memory/legacy）")

    def _load_config(self) -> Dict:
        """設定ファイル読み込み"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                # デフォルト設定
                default_config = {
                    "encryption_enabled": True,
                    "audit_logging": True,
                    "rate_limiting": True,
                    "ip_whitelist_enabled": False,
                }
                self._save_config(default_config)
                return default_config
        except Exception as e:
            self.logger.error(f"設定ファイル読み込みエラー: {e}")
            return {}

    def _save_config(self, config: Dict) -> None:
        """設定ファイル保存"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"設定ファイル保存エラー: {e}")

    def _get_or_create_encryption_key(self) -> bytes:
        """暗号化キー取得または作成"""
        key_file = "config/encryption.key"
        try:
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, "wb") as f:
                    f.write(key)
                return key
        except Exception as e:
            self.logger.error(f"暗号化キー処理エラー: {e}")
            return Fernet.generate_key()

    def _get_or_create_jwt_secret(self) -> str:
        """JWT秘密鍵取得または作成"""
        secret_file = "config/jwt_secret.key"
        try:
            if os.path.exists(secret_file):
                with open(secret_file, "r") as f:
                    return f.read().strip()
            else:
                secret = secrets.token_urlsafe(32)
                os.makedirs(os.path.dirname(secret_file), exist_ok=True)
                with open(secret_file, "w") as f:
                    f.write(secret)
                return secret
        except Exception as e:
            self.logger.error(f"JWT秘密鍵処理エラー: {e}")
            return secrets.token_urlsafe(32)

    def hash_password(self, password: str) -> str:
        """パスワードハッシュ化"""
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return hashed.decode("utf-8")
        except Exception as e:
            self.logger.error(f"パスワードハッシュ化エラー: {e}")
            raise

    def verify_password(self, password: str, hashed: str) -> bool:
        """パスワード検証"""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception as e:
            self.logger.error(f"パスワード検証エラー: {e}")
            return False

    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """パスワード強度検証"""
        errors = []

        if len(password) < self.security_policies["password_min_length"]:
            errors.append(
                f"パスワードは{self.security_policies['password_min_length']}文字以上である必要があります"
            )

        if not any(c.isupper() for c in password):
            errors.append("大文字を含む必要があります")

        if not any(c.islower() for c in password):
            errors.append("小文字を含む必要があります")

        if not any(c.isdigit() for c in password):
            errors.append("数字を含む必要があります")

        if self.security_policies["password_require_special"]:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("特殊文字を含む必要があります")

        return len(errors) == 0, errors

    def check_password_strength(self, password: str) -> bool:
        """パスワード強度チェック（簡易版）"""
        is_valid, _ = self.validate_password_strength(password)
        return is_valid

    def register_user(self, username: str, password: str, role: str = "user") -> bool:
        """ユーザー登録"""
        try:
            # パスワード強度チェック
            if not self.check_password_strength(password):
                self.logger.warning(f"パスワード強度不足: {username}")
                return False

            # 既存ユーザーチェック
            if username in self.users:
                self.logger.warning(f"ユーザー既存: {username}")
                return False

            # ユーザー登録
            hashed_password = self.hash_password(password)
            self.users[username] = {
                "password_hash": hashed_password,
                "role": role,
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "failed_attempts": 0,
                "locked_until": None,
            }

            # 監査ログ
            self.log_security_event("user_registered", username, f"ユーザー登録: {role}")

            self.logger.info(f"ユーザー登録成功: {username}")
            return True

        except Exception as e:
            self.logger.error(f"ユーザー登録エラー: {e}")
            return False

# 明示エイリアス: 今後の段階的移行に備えた別名
InMemorySecurityManager = SecurityManager

    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """ユーザー認証"""
        try:
            # ユーザー存在チェック
            if username not in self.users:
                self.log_security_event("login_failed", username, "ユーザー不存在")
                return None

            user = self.users[username]

            # アカウントロックチェック
            if user.get("locked_until"):
                lock_time = datetime.fromisoformat(user["locked_until"])
                if datetime.now() < lock_time:
                    self.log_security_event("login_blocked", username, "アカウントロック中")
                    return None
                else:
                    # ロック解除
                    user["locked_until"] = None
                    user["failed_attempts"] = 0

            # パスワード検証
            if self.verify_password(password, user["password_hash"]):
                # 認証成功
                user["last_login"] = datetime.now().isoformat()
                user["failed_attempts"] = 0

                # JWTトークン生成
                token = self.generate_jwt_token(username, [user["role"]])

                self.log_security_event("login_success", username, "認証成功")
                return token
            else:
                # 認証失敗
                user["failed_attempts"] += 1

                # 失敗回数チェック
                if user["failed_attempts"] >= self.security_policies["max_failed_attempts"]:
                    lock_until = datetime.now() + timedelta(
                        seconds=self.security_policies["lockout_duration"]
                    )
                    user["locked_until"] = lock_until.isoformat()
                    self.log_security_event(
                        "account_locked",
                        username,
                        f"アカウントロック: {user['failed_attempts']}回失敗",
                    )

                self.log_security_event(
                    "login_failed", username, f"パスワード不正: {user['failed_attempts']}回目"
                )
                return None

        except Exception as e:
            self.logger.error(f"認証エラー: {e}")
            return None

    def generate_jwt_token(self, user_id: str, roles: List[str] = None) -> str:
        """JWTトークン生成"""
        try:
            payload = {
                "user_id": user_id,
                "roles": roles or [],
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + timedelta(hours=self.jwt_expiry_hours),
            }
            token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

            # セッション記録
            session_id = secrets.token_urlsafe(16)
            self.active_sessions[session_id] = {
                "user_id": user_id,
                "token": token,
                "created_at": time.time(),
                "last_activity": time.time(),
                "ip_address": None,  # 実際の実装では取得
            }

            return token
        except Exception as e:
            self.logger.error(f"JWTトークン生成エラー: {e}")
            raise

    def verify_token(self, token: str) -> Optional[Dict]:
        """JWTトークン検証（テスト用エイリアス）"""
        return self.verify_jwt_token(token)

    def verify_jwt_token(self, token: str) -> Optional[Dict]:
        """JWTトークン検証"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            # ユーザー名をpayloadに追加（互換性のため）
            if "user_id" in payload:
                payload["username"] = payload["user_id"]

            # セッション確認
            for session_id, session_data in self.active_sessions.items():
                if session_data["token"] == token:
                    # セッションタイムアウト確認
                    if (
                        time.time() - session_data["last_activity"]
                        > self.security_policies["session_timeout"]
                    ):
                        del self.active_sessions[session_id]
                        return None

                    # 最終活動時刻更新
                    session_data["last_activity"] = time.time()
                    return payload

            return None
        except jwt.ExpiredSignatureError:
            self.logger.warning("期限切れトークン")
            return None
        except jwt.InvalidTokenError:
            self.logger.warning("無効なトークン")
            return None
        except Exception as e:
            self.logger.error(f"JWTトークン検証エラー: {e}")
            return None

    def encrypt_data(self, data: str) -> str:
        """データ暗号化"""
        try:
            encrypted = self.cipher_suite.encrypt(data.encode("utf-8"))
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            self.logger.error(f"データ暗号化エラー: {e}")
            raise

    def decrypt_data(self, encrypted_data: str) -> str:
        """データ復号化"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode("utf-8"))
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode("utf-8")
        except Exception as e:
            self.logger.error(f"データ復号化エラー: {e}")
            raise

    def check_rate_limit_detailed(
        self, identifier: str, max_attempts: int = None, window_seconds: int = 300
    ) -> bool:
        """詳細レート制限チェック"""
        if max_attempts is None:
            max_attempts = self.security_policies["max_failed_attempts"]

        current_time = time.time()

        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []

        # 古いエントリを削除
        cutoff_time = current_time - window_seconds
        self.rate_limits[identifier] = [
            timestamp for timestamp in self.rate_limits[identifier] if timestamp > cutoff_time
        ]

        # レート制限チェック
        if len(self.rate_limits[identifier]) >= max_attempts:
            return False

        # 新しいリクエストを記録
        self.rate_limits[identifier].append(current_time)
        return True

    def record_failed_attempt(self, identifier: str) -> None:
        """失敗試行記録"""
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []

        self.failed_attempts[identifier].append(time.time())
        self.logger.warning(f"認証失敗記録: {identifier}")

    def is_ip_allowed_detailed(self, ip_address: str) -> bool:
        """IP許可確認（詳細版）"""
        if not self.config.get("ip_whitelist_enabled", False):
            return True

        try:
            ip = ipaddress.ip_address(ip_address)
            for allowed_range in self.security_policies["allowed_ip_ranges"]:
                if ip in ipaddress.ip_network(allowed_range):
                    return True
            return False
        except Exception as e:
            self.logger.error(f"IP確認エラー: {e}")
            return False

    def add_permission_role(self, role: str, permission: str) -> None:
        """ロール権限追加"""
        if role not in self.permissions:
            self.permissions[role] = []

        if permission not in self.permissions[role]:
            self.permissions[role].append(permission)
            self.logger.info(f"権限追加: {role} -> {permission}")

    def check_permission_role(self, user_roles: List[str], required_permission: str) -> bool:
        """ロール権限確認"""
        for role in user_roles:
            if role in self.permissions and required_permission in self.permissions[role]:
                return True
        return False

    def audit_log(self, event_type: str, user_id: str, details: Dict = None) -> None:
        """監査ログ記録"""
        if not self.config.get("audit_logging", True):
            return

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details or {},
        }

        audit_file = f"logs/security_audit_{datetime.now().strftime('%Y%m%d')}.log"
        try:
            os.makedirs(os.path.dirname(audit_file), exist_ok=True)
            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.error(f"監査ログ記録エラー: {e}")

    def get_security_status(self) -> Dict[str, Any]:
        """セキュリティ状態取得"""
        return {
            "overall_status": "healthy",
            "active_sessions": len(self.active_sessions),
            "failed_login_attempts": sum(
                len(attempts) for attempts in self.failed_attempts.values()
            ),
            "security_score": 85,
            "failed_attempts_count": sum(
                len(attempts) for attempts in self.failed_attempts.values()
            ),
            "encryption_enabled": self.config.get("encryption_enabled", True),
            "audit_logging": self.config.get("audit_logging", True),
            "ip_whitelist_enabled": self.config.get("ip_whitelist_enabled", False),
            "security_policies": self.security_policies,
            "timestamp": datetime.now().isoformat(),
        }

    def log_security_event(self, action: str, user: str, details: str) -> None:
        """セキュリティイベントログ記録"""
        log_entry = {
            "action": action,
            "user": user,
            "timestamp": datetime.now().isoformat(),
            "details": details,
        }
        self.audit_logs.append(log_entry)

        # ファイルにも記録
        self.audit_log(action, user, {"details": details})

    def get_audit_logs(self) -> List[Dict]:
        """監査ログ取得"""
        return self.audit_logs

    def create_session(self, username: str) -> str:
        """セッション作成"""
        session_id = secrets.token_urlsafe(16)
        self.sessions[session_id] = {
            "username": username,
            "created_at": time.time(),
            "last_activity": time.time(),
        }
        return session_id

    def validate_session(self, session_id: str) -> bool:
        """セッション検証"""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        current_time = time.time()

        # セッションタイムアウトチェック
        if current_time - session["last_activity"] > self.security_policies["session_timeout"]:
            del self.sessions[session_id]
            return False

        # 最終アクティビティ更新
        session["last_activity"] = current_time
        return True

    def invalidate_session(self, session_id: str) -> None:
        """セッション無効化"""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def add_to_whitelist(self, ip_address: str) -> None:
        """IPホワイトリストに追加"""
        if ip_address not in self.ip_whitelist:
            self.ip_whitelist.append(ip_address)

    def check_rate_limit(self, client_ip: str) -> bool:
        """レート制限チェック（簡易版）"""
        current_time = time.time()

        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []

        # 1分以内のリクエストをカウント
        recent_requests = [
            req_time for req_time in self.rate_limits[client_ip] if current_time - req_time < 60
        ]

        self.rate_limits[client_ip] = recent_requests

        # レート制限チェック
        if len(recent_requests) >= self.security_policies["rate_limit_per_minute"]:
            return False

        # 新しいリクエストを記録
        self.rate_limits[client_ip].append(current_time)
        return True

    def is_ip_allowed(self, ip_address: str) -> bool:
        """IP許可確認"""
        if not self.config.get("ip_whitelist_enabled", False):
            return True

        # ホワイトリストが空の場合はすべて許可
        if not self.ip_whitelist:
            return True

        return ip_address in self.ip_whitelist

    def check_permission(self, username: str, required_permission: str) -> bool:
        """権限確認（ユーザー名ベース）"""
        if username not in self.users:
            return False

        user_role = self.users[username]["role"]

        # 管理者は全権限を持つ
        if user_role == "admin":
            return True

        # ユーザーロールの場合、user権限のみ
        if user_role == "user" and required_permission == "user":
            return True

        return False

    def get_user_permissions(self, username: str) -> List[str]:
        """ユーザー権限取得"""
        if username not in self.users:
            return []

        user_role = self.users[username]["role"]

        if user_role == "admin":
            return ["admin", "user", "read", "write", "delete"]
        elif user_role == "user":
            return ["user", "read", "write"]
        else:
            return ["read"]

    def add_user_permission(self, username: str, permission: str) -> bool:
        """ユーザー権限追加"""
        if username not in self.users:
            return False

        if "permissions" not in self.users[username]:
            self.users[username]["permissions"] = []

        if permission not in self.users[username]["permissions"]:
            self.users[username]["permissions"].append(permission)

        return True

    def remove_user_permission(self, username: str, permission: str) -> bool:
        """ユーザー権限削除"""
        if username not in self.users:
            return False

        if "permissions" not in self.users[username]:
            return False

        if permission in self.users[username]["permissions"]:
            self.users[username]["permissions"].remove(permission)
            return True

        return False

    def cleanup_expired_sessions(self) -> None:
        """期限切れセッション削除"""
        current_time = time.time()
        expired_sessions = []

        for session_id, session_data in self.active_sessions.items():
            if (
                current_time - session_data["last_activity"]
                > self.security_policies["session_timeout"]
            ):
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self.active_sessions[session_id]
            self.logger.info(f"期限切れセッション削除: {session_id}")


def require_auth(required_permission: str = None):
    """認証デコレータ"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 実際の実装では、リクエストからトークンを取得
            # ここではサンプル実装
            token = kwargs.get("auth_token")
            if not token:
                return {"error": "認証が必要です"}, 401

            security_manager = SecurityManager()
            payload = security_manager.verify_jwt_token(token)
            if not payload:
                return {"error": "無効なトークンです"}, 401

            if required_permission:
                user_roles = payload.get("roles", [])
                if not security_manager.check_permission(user_roles, required_permission):
                    return {"error": "権限が不足しています"}, 403

            kwargs["current_user"] = payload
            return f(*args, **kwargs)

        return decorated_function

    return decorator


if __name__ == "__main__":
    # テスト実行
    security_manager = SecurityManager()

    # パスワード強度テスト
    password = "TestPass123!"
    is_valid, errors = security_manager.validate_password_strength(password)
    print(f"パスワード強度: {is_valid}, エラー: {errors}")

    # ハッシュ化テスト
    hashed = security_manager.hash_password(password)
    print(f"ハッシュ化: {hashed}")

    # 検証テスト
    is_valid = security_manager.verify_password(password, hashed)
    print(f"パスワード検証: {is_valid}")

    # JWTトークンテスト
    token = security_manager.generate_jwt_token("test_user", ["admin"])
    print(f"JWTトークン: {token}")

    # トークン検証テスト
    payload = security_manager.verify_jwt_token(token)
    print(f"トークン検証: {payload}")

    # 暗号化テスト
    data = "機密データ"
    encrypted = security_manager.encrypt_data(data)
    print(f"暗号化: {encrypted}")

    # 復号化テスト
    decrypted = security_manager.decrypt_data(encrypted)
    print(f"復号化: {decrypted}")

    # セキュリティ状態
    status = security_manager.get_security_status()
    print(f"セキュリティ状態: {status}")
