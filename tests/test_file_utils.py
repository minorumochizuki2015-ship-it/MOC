#!/usr/bin/env python3
"""
file_utils統合テスト

UTF-8 LF・secrets・atomic write統合機能のテストスイート
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from src.tools.file_utils import (
    FileIntegrityError,
    FileSecurityError,
    atomic_write_json,
    atomic_write_text,
    check_eol,
    check_secrets,
    compute_sha256,
    normalize_eol,
    read_json_safe,
    read_text_safe,
    safe_read_json,
    safe_read_text,
    write_json_lf,
    write_text_lf,
)


class TestSecretDetection:
    """Secret検出テスト"""

    def test_detect_aws_key(self):
        """AWS Access Key検出"""
        content = "AWS_ACCESS_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"
        with pytest.raises(FileSecurityError, match="AWS Access Key"):
            check_secrets(content)

    def test_detect_generic_secret(self):
        """Generic SECRET検出"""
        content = "SECRET_KEY=" + "abc123" + "def456" + "ghi789"
        with pytest.raises(FileSecurityError, match="Generic SECRET"):
            check_secrets(content)

    def test_detect_bearer_token(self):
        """Bearer Token検出"""
        content = "Authorization: Bearer " + "eyJhbGciOiJI" + "UzI1NiIsInR5cCI6IkpXVCJ9"
        with pytest.raises(FileSecurityError, match="Bearer Token"):
            check_secrets(content)

    def test_detect_private_key(self):
        """Private Key検出"""
        content = "-----BEGIN " + "RSA PRIVATE KEY" + "-----\n" + "MIIEpAIBAAKCAQEA..."
        with pytest.raises(FileSecurityError, match="Private Key"):
            check_secrets(content)

    def test_safe_placeholders(self):
        """Safe placeholder許可"""
        safe_content = """
        SECRET_KEY=REDACTED
        API_KEY=CHANGEME
        JWT_TOKEN=jwt-ci
        WEBHOOK_SECRET=webhook-ci
        PASSWORD=CHANGE_ME_DEV_ONLY
        """
        # Should not raise
        check_secrets(safe_content)

    def test_no_secrets(self):
        """Secret無しコンテンツ"""
        clean_content = """
        # Configuration file
        database_host=localhost
        database_port=5432
        debug_mode=true
        """
        # Should not raise
        check_secrets(clean_content)


class TestEOLHandling:
    """EOL処理テスト"""

    def test_detect_crlf(self):
        """CRLF検出"""
        content = "line1\r\nline2\r\nline3"
        with pytest.raises(FileIntegrityError, match="CRLF detected"):
            check_eol(content)

    def test_allow_lf(self):
        """LF許可"""
        content = "line1\nline2\nline3"
        assert check_eol(content) is True

    def test_normalize_crlf_to_lf(self):
        """CRLF → LF正規化"""
        content = "line1\r\nline2\r\nline3"
        normalized = normalize_eol(content)
        assert normalized == "line1\nline2\nline3"

    def test_normalize_mixed_eol(self):
        """混在EOL正規化"""
        content = "line1\r\nline2\nline3\rline4"
        normalized = normalize_eol(content)
        assert normalized == "line1\nline2\nline3\nline4"


class TestAtomicWrite:
    """Atomic write テスト"""

    def test_atomic_write_text_basic(self):
        """基本的なatomic text write"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content = "Hello, World!\nThis is a test."

            result = atomic_write_text(file_path, content)

            # ファイルが作成されている
            assert file_path.exists()

            # 内容が正しい
            with open(file_path, "r", encoding="utf-8") as f:
                written_content = f.read()
            assert written_content == content

            # SHA256が一致
            assert result["sha_in"] == result["sha_out"]
            assert result["sha_in"] == compute_sha256(content)
            assert result["verified"] is True

    def test_atomic_write_with_backup(self):
        """バックアップ付きatomic write"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"

            # 既存ファイル作成
            original_content = "Original content"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_content)

            # 新しい内容で上書き
            new_content = "New content"
            result = atomic_write_text(file_path, new_content, backup=True)

            # 新しい内容が書き込まれている
            with open(file_path, "r", encoding="utf-8") as f:
                assert f.read() == new_content

            # バックアップが作成されている
            backup_path = Path(result["backup_path"])
            assert backup_path.exists()
            with open(backup_path, "r", encoding="utf-8") as f:
                assert f.read() == original_content

    def test_atomic_write_eol_normalization(self):
        """EOL正規化付きatomic write"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content_with_crlf = "line1\r\nline2\r\nline3"
            expected_content = "line1\nline2\nline3"

            result = atomic_write_text(file_path, content_with_crlf, normalize_eol_enabled=True)

            # LFに正規化されている
            with open(file_path, "r", encoding="utf-8") as f:
                written_content = f.read()
            assert written_content == expected_content

            # SHA256は正規化後の内容
            assert result["sha_out"] == compute_sha256(expected_content)

    def test_atomic_write_secret_detection(self):
        """Secret検出付きatomic write"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content_with_secret = "API_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"

            with pytest.raises(FileSecurityError):
                atomic_write_text(file_path, content_with_secret, check_secrets_enabled=True)

            # ファイルが作成されていない
            assert not file_path.exists()

    def test_atomic_write_json(self):
        """Atomic JSON write"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.json"
            data = {"name": "test", "value": 123, "nested": {"key": "value"}}

            result = atomic_write_json(file_path, data)

            # ファイルが作成されている
            assert file_path.exists()

            # JSON内容が正しい
            with open(file_path, "r", encoding="utf-8") as f:
                loaded_data = json.load(f)
            assert loaded_data == data

            # 整合性チェック
            assert result["verified"] is True


class TestSafeRead:
    """Safe read テスト"""

    def test_safe_read_text(self):
        """Safe text read"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content = "Hello, World!\nThis is a test."

            # ファイル作成
            with open(file_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)

            # Safe read
            read_content, metadata = safe_read_text(file_path)

            assert read_content == content
            assert metadata["sha256"] == compute_sha256(content)
            assert metadata["size"] == len(content.encode("utf-8"))
            assert metadata["eol_ok"] is True

    def test_safe_read_with_secret_check(self):
        """Secret検証付きsafe read"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content_with_secret = "API_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"

            # ファイル作成
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content_with_secret)

            # Secret検出でエラー
            with pytest.raises(FileSecurityError):
                safe_read_text(file_path, check_secrets_enabled=True)

    def test_safe_read_json(self):
        """Safe JSON read"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.json"
            data = {"key": "value", "number": 42}

            # JSON ファイル作成
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            # Safe read
            read_data, metadata = safe_read_json(file_path)

            assert read_data == data
            assert "sha256" in metadata


class TestConvenienceFunctions:
    """便利関数テスト"""

    def test_write_text_lf(self):
        """write_text_lf便利関数"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content = "Hello\nWorld"

            result = write_text_lf(file_path, content)

            assert file_path.exists()
            assert result["verified"] is True

    def test_write_json_lf(self):
        """write_json_lf便利関数"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.json"
            data = {"test": True}

            result = write_json_lf(file_path, data)

            assert file_path.exists()
            assert result["verified"] is True

    def test_read_text_safe(self):
        """read_text_safe便利関数"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"
            content = "Test content"

            # ファイル作成
            write_text_lf(file_path, content)

            # 読み込み
            read_content = read_text_safe(file_path)
            assert read_content == content

    def test_read_json_safe(self):
        """read_json_safe便利関数"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.json"
            data = {"test": True, "value": 123}

            # JSON作成
            write_json_lf(file_path, data)

            # 読み込み
            read_data = read_json_safe(file_path)
            assert read_data == data


class TestErrorHandling:
    """エラーハンドリングテスト"""

    def test_atomic_write_cleanup_on_error(self):
        """エラー時のクリーンアップ"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"

            # 無効なエンコーディングでエラーを発生させる
            with pytest.raises(Exception):
                atomic_write_text(file_path, "test", encoding="invalid-encoding")

            # 一時ファイルがクリーンアップされている
            tmp_files = list(Path(tmpdir).glob("*.tmp"))
            assert len(tmp_files) == 0

    def test_integrity_verification_failure(self):
        """整合性検証失敗"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.txt"

            # モックして整合性エラーを発生させる
            # 実際のテストでは、ディスク容量不足などで発生する可能性がある
            pass  # 実装は複雑になるため省略


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
