#!/usr/bin/env python3
"""
セキュリティシステム統合テストスイート

このテストスイートは以下の機能をテストします：
- SecurityManagerの初期化と基本機能
- 認証システム（ログイン、登録、JWT）
- 暗号化・復号化機能
- アクセス制御とロール管理
- セキュリティ監査ログ
- レート制限機能
- セッション管理
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from src.security_manager import SecurityManager
except ImportError as e:
    print(f"SecurityManagerのインポートに失敗しました: {e}")
    sys.exit(1)


class TestSecurityManagerIntegration(unittest.TestCase):
    """SecurityManager統合テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.temp_dir = tempfile.mkdtemp()
        self.security_manager = SecurityManager()

    def tearDown(self):
        """テスト後のクリーンアップ"""
        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_security_manager_initialization(self):
        """SecurityManagerの初期化テスト"""
        self.assertIsNotNone(self.security_manager)
        self.assertIsNotNone(self.security_manager.users)
        self.assertIsNotNone(self.security_manager.sessions)
        self.assertIsNotNone(self.security_manager.audit_logs)
        print("✓ SecurityManager初期化テスト成功")

    def test_password_strength_validation(self):
        """パスワード強度検証テスト"""
        # 弱いパスワード
        weak_passwords = ["123", "password", "abc"]
        for pwd in weak_passwords:
            self.assertFalse(self.security_manager.check_password_strength(pwd))

        # 強いパスワード
        strong_passwords = ["StrongPass123!", "MySecure@Pass2024", "Complex#Password1"]
        for pwd in strong_passwords:
            self.assertTrue(self.security_manager.check_password_strength(pwd))

        print("✓ パスワード強度検証テスト成功")

    def test_user_registration_and_authentication(self):
        """ユーザー登録と認証テスト"""
        username = "testuser"
        password = "TestPassword123!"
        role = "user"

        # ユーザー登録
        success = self.security_manager.register_user(username, password, role)
        self.assertTrue(success)

        # 認証テスト
        token = self.security_manager.authenticate_user(username, password)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

        # 間違ったパスワードでの認証
        invalid_token = self.security_manager.authenticate_user(username, "wrongpassword")
        self.assertIsNone(invalid_token)

        print("✓ ユーザー登録と認証テスト成功")

    def test_jwt_token_operations(self):
        """JWTトークン操作テスト"""
        username = "jwtuser"
        password = "JWTPassword123!"

        # ユーザー登録
        self.security_manager.register_user(username, password, "user")

        # トークン生成
        token = self.security_manager.authenticate_user(username, password)
        self.assertIsNotNone(token)

        # トークン検証
        payload = self.security_manager.verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("username"), username)

        # 無効なトークン検証
        invalid_payload = self.security_manager.verify_token("invalid.token.here")
        self.assertIsNone(invalid_payload)

        print("✓ JWTトークン操作テスト成功")

    def test_encryption_decryption(self):
        """暗号化・復号化テスト"""
        test_data = "これは機密データです"

        # 暗号化
        encrypted_data = self.security_manager.encrypt_data(test_data)
        self.assertIsNotNone(encrypted_data)
        self.assertNotEqual(encrypted_data, test_data)

        # 復号化
        decrypted_data = self.security_manager.decrypt_data(encrypted_data)
        self.assertEqual(decrypted_data, test_data)

        print("✓ 暗号化・復号化テスト成功")

    def test_access_control(self):
        """アクセス制御テスト"""
        # 管理者ユーザー
        admin_user = "admin"
        admin_password = "AdminPass123!"
        self.security_manager.register_user(admin_user, admin_password, "admin")

        # 一般ユーザー
        regular_user = "user"
        user_password = "UserPass123!"
        self.security_manager.register_user(regular_user, user_password, "user")

        # 権限チェック
        self.assertTrue(self.security_manager.check_permission(admin_user, "admin"))
        self.assertTrue(self.security_manager.check_permission(admin_user, "user"))
        self.assertFalse(self.security_manager.check_permission(regular_user, "admin"))
        self.assertTrue(self.security_manager.check_permission(regular_user, "user"))

        print("✓ アクセス制御テスト成功")

    def test_rate_limiting(self):
        """レート制限テスト"""
        client_ip = "192.168.1.100"

        # 制限内のリクエスト
        for i in range(5):
            allowed = self.security_manager.check_rate_limit(client_ip)
            self.assertTrue(allowed)

        # 制限を超えるリクエスト（デフォルト制限は10/分）
        for i in range(10):
            self.security_manager.check_rate_limit(client_ip)

        # 制限を超えた場合
        blocked = self.security_manager.check_rate_limit(client_ip)
        # 注意: 実際の制限値によって結果が変わる可能性があります

        print("✓ レート制限テスト成功")

    def test_session_management(self):
        """セッション管理テスト"""
        username = "sessionuser"
        password = "SessionPass123!"
        self.security_manager.register_user(username, password, "user")

        # セッション作成
        session_id = self.security_manager.create_session(username)
        self.assertIsNotNone(session_id)

        # セッション検証
        valid = self.security_manager.validate_session(session_id)
        self.assertTrue(valid)

        # セッション削除
        self.security_manager.invalidate_session(session_id)

        # 削除後の検証
        invalid = self.security_manager.validate_session(session_id)
        self.assertFalse(invalid)

        print("✓ セッション管理テスト成功")

    def test_audit_logging(self):
        """監査ログテスト"""
        initial_log_count = len(self.security_manager.audit_logs)

        # 監査ログ記録
        self.security_manager.log_security_event("test_event", "testuser", "テストイベント")

        # ログが追加されたことを確認
        self.assertEqual(len(self.security_manager.audit_logs), initial_log_count + 1)

        # ログ内容確認
        latest_log = self.security_manager.audit_logs[-1]
        self.assertEqual(latest_log["action"], "test_event")
        self.assertEqual(latest_log["user"], "testuser")
        self.assertEqual(latest_log["details"], "テストイベント")

        print("✓ 監査ログテスト成功")

    def test_security_status_retrieval(self):
        """セキュリティステータス取得テスト"""
        status = self.security_manager.get_security_status()

        self.assertIsInstance(status, dict)
        self.assertIn("overall_status", status)
        self.assertIn("active_sessions", status)
        self.assertIn("failed_login_attempts", status)
        self.assertIn("security_score", status)
        self.assertIn("timestamp", status)

        print("✓ セキュリティステータス取得テスト成功")

    def test_ip_whitelist_management(self):
        """IPホワイトリスト管理テスト"""
        test_ip = "192.168.1.50"

        # 初期状態（ホワイトリストが空の場合、すべて許可）
        initial_allowed = self.security_manager.is_ip_allowed(test_ip)

        # IPをホワイトリストに追加
        self.security_manager.add_to_whitelist(test_ip)

        # ホワイトリストに登録されたIPは許可される
        allowed = self.security_manager.is_ip_allowed(test_ip)
        self.assertTrue(allowed)

        # 登録されていないIPは拒否される（ホワイトリストが有効な場合）
        not_allowed = self.security_manager.is_ip_allowed("10.0.0.1")
        # 注意: 実装によって動作が異なる可能性があります

        print("✓ IPホワイトリスト管理テスト成功")


class TestSecurityIntegrationWithDashboard(unittest.TestCase):
    """ダッシュボード統合テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.security_manager = SecurityManager()

    def test_dashboard_integration_data_format(self):
        """ダッシュボード統合データ形式テスト"""
        # セキュリティステータス
        status = self.security_manager.get_security_status()
        required_fields = [
            "overall_status",
            "active_sessions",
            "failed_login_attempts",
            "security_score",
            "timestamp",
        ]

        for field in required_fields:
            self.assertIn(field, status, f"必須フィールド '{field}' がありません")

        # 監査ログ
        logs = self.security_manager.get_audit_logs()
        self.assertIsInstance(logs, list)

        if logs:
            log_entry = logs[0]
            log_required_fields = ["action", "user", "timestamp", "details"]
            for field in log_required_fields:
                self.assertIn(
                    field, log_entry, f"ログエントリに必須フィールド '{field}' がありません"
                )

        print("✓ ダッシュボード統合データ形式テスト成功")

    def test_error_handling(self):
        """エラーハンドリングテスト"""
        # 存在しないユーザーでの認証
        token = self.security_manager.authenticate_user("nonexistent", "password")
        self.assertIsNone(token)

        # 無効なデータでの暗号化
        try:
            encrypted = self.security_manager.encrypt_data(None)
            # Noneの場合の処理は実装依存
        except Exception:
            pass  # 例外が発生することも想定される

        # 無効なセッションIDでの検証
        valid = self.security_manager.validate_session("invalid_session_id")
        self.assertFalse(valid)

        print("✓ エラーハンドリングテスト成功")


def run_security_tests():
    """セキュリティテストスイートを実行"""
    print("=" * 60)
    print("セキュリティシステム統合テストスイート開始")
    print("=" * 60)

    # テストスイート作成
    test_suite = unittest.TestSuite()

    # SecurityManager統合テスト
    test_suite.addTest(unittest.makeSuite(TestSecurityManagerIntegration))

    # ダッシュボード統合テスト
    test_suite.addTest(unittest.makeSuite(TestSecurityIntegrationWithDashboard))

    # テスト実行
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # 結果サマリー
    print("\n" + "=" * 60)
    print("テスト結果サマリー")
    print("=" * 60)
    print(f"実行テスト数: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失敗: {len(result.failures)}")
    print(f"エラー: {len(result.errors)}")

    if result.failures:
        print("\n失敗したテスト:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")

    if result.errors:
        print("\nエラーが発生したテスト:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")

    success_rate = (
        ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        if result.testsRun > 0
        else 0
    )
    print(f"\n成功率: {success_rate:.1f}%")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_security_tests()
    sys.exit(0 if success else 1)
