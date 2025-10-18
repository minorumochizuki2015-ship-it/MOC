#!/usr/bin/env python3
"""
統合ファイル操作ユーティリティ

UTF-8 LF・secrets検証・atomic write統合機能を提供します。
プロジェクトルールに準拠した安全なファイル操作を実現します。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Secret detection patterns
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic SECRET", re.compile(r"SECRET[_-]?KEY\s*[:=]\s*['\"]?[A-Za-z0-9/_+=-]{12,}")),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("Private Key", re.compile(r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----")),
    ("API Key", re.compile(r"API[_-]?KEY\s*[:=]\s*['\"]?[A-Za-z0-9/_+=-]{12,}")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
]

# Allowlist for safe placeholders
SAFE_PLACEHOLDERS = {"REDACTED", "CHANGEME", "jwt-ci", "webhook-ci", "CHANGE_ME_DEV_ONLY"}


class FileSecurityError(Exception):
    """ファイルセキュリティ違反エラー"""

    pass


class FileIntegrityError(Exception):
    """ファイル整合性エラー"""

    pass


def check_secrets(content: str, file_path: Optional[str] = None) -> List[Tuple[str, int, str]]:
    """
    コンテンツ内のsecret検出

    Args:
        content: 検査対象コンテンツ
        file_path: ファイルパス（ログ用）

    Returns:
        検出されたsecretのリスト [(pattern_name, line_number, line_content), ...]

    Raises:
        FileSecurityError: secretが検出された場合
    """
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Safe placeholderをチェック
        if any(placeholder in line for placeholder in SAFE_PLACEHOLDERS):
            continue

        # Secret patternをチェック
        for pattern_name, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append((pattern_name, line_num, line.strip()))

    if findings:
        error_msg = f"Secrets detected in {file_path or 'content'}:\n"
        for pattern_name, line_num, line_content in findings:
            error_msg += f"  - {pattern_name} at line {line_num}: {line_content[:50]}...\n"
        raise FileSecurityError(error_msg)

    return findings


def check_eol(content: str, file_path: Optional[str] = None) -> bool:
    """
    EOL検証（LF必須）

    Args:
        content: 検査対象コンテンツ
        file_path: ファイルパス（ログ用）

    Returns:
        True if LF only, False if CRLF detected

    Raises:
        FileIntegrityError: CRLF が検出された場合
    """
    if "\r\n" in content:
        raise FileIntegrityError(f"CRLF detected in {file_path or 'content'}. LF required.")

    return True


def normalize_eol(content: str) -> str:
    """
    EOL正規化（CRLF → LF）

    Args:
        content: 正規化対象コンテンツ

    Returns:
        LF正規化されたコンテンツ
    """
    return content.replace("\r\n", "\n").replace("\r", "\n")


def compute_sha256(content: Union[str, bytes]) -> str:
    """
    SHA256ハッシュ計算

    Args:
        content: ハッシュ対象コンテンツ

    Returns:
        SHA256ハッシュ（16進文字列）
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def atomic_write_text(
    file_path: Union[str, Path],
    content: str,
    *,
    encoding: str = "utf-8",
    newline: str = "\n",
    check_secrets_enabled: bool = True,
    normalize_eol_enabled: bool = True,
    backup: bool = True,
    verify_integrity: bool = True,
) -> Dict[str, Any]:
    """
    Atomic text file write with security and integrity checks

    Args:
        file_path: 書き込み先ファイルパス
        content: 書き込み内容
        encoding: 文字エンコーディング（デフォルト: utf-8）
        newline: 改行文字（デフォルト: LF）
        check_secrets_enabled: secret検証を実行するか
        normalize_eol_enabled: EOL正規化を実行するか
        backup: バックアップを作成するか
        verify_integrity: 整合性検証を実行するか

    Returns:
        操作結果辞書 {
            'sha_in': 入力SHA256,
            'sha_out': 出力SHA256,
            'backup_path': バックアップパス,
            'verified': 検証結果
        }

    Raises:
        FileSecurityError: secret検出時
        FileIntegrityError: 整合性エラー時
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 入力コンテンツ処理
    processed_content = content  # EOL正規化
    if normalize_eol_enabled:
        processed_content = normalize_eol(processed_content)

    # Security checks
    if check_secrets_enabled:
        check_secrets(processed_content, str(path))

    # EOL check
    check_eol(processed_content, str(path))

    # SHA256計算
    sha_in = compute_sha256(processed_content)

    # Backup existing file
    backup_path = None
    if backup and path.exists():
        backup_path = path.with_suffix(path.suffix + ".bak")
        if backup_path.exists():
            backup_path.unlink()
        shutil.copy2(path, backup_path)

    # Atomic write: tmp → validate → rename
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        # Write to temporary file
        with open(tmp_path, "w", encoding=encoding, newline=newline) as f:
            f.write(processed_content)

        # Verify written content
        if verify_integrity:
            with open(tmp_path, "r", encoding=encoding) as f:
                written_content = f.read()

            # Verify content matches
            if written_content != processed_content:
                raise FileIntegrityError(f"Content verification failed for {path}")

            # Verify SHA256
            sha_out = compute_sha256(written_content)
            if sha_out != sha_in:
                raise FileIntegrityError(f"SHA256 mismatch for {path}: {sha_in} != {sha_out}")
        else:
            sha_out = sha_in

        # Atomic rename
        if os.name == "nt":
            # Windows: remove target if exists
            if path.exists():
                path.unlink()
        tmp_path.replace(path)

        return {
            "sha_in": sha_in,
            "sha_out": sha_out,
            "backup_path": str(backup_path) if backup_path else None,
            "verified": verify_integrity,
        }

    except Exception as e:
        # Cleanup on error
        if tmp_path.exists():
            tmp_path.unlink()

        # Restore backup if needed
        if backup_path and backup_path.exists() and not path.exists():
            shutil.copy2(backup_path, path)

        raise e


def atomic_write_json(
    file_path: Union[str, Path],
    data: Any,
    *,
    ensure_ascii: bool = False,
    indent: Optional[int] = 2,
    sort_keys: bool = True,
    **kwargs,
) -> Dict[str, Any]:
    """
    Atomic JSON file write with security and integrity checks

    Args:
        file_path: 書き込み先ファイルパス
        data: JSON書き込みデータ
        ensure_ascii: ASCII強制フラグ
        indent: インデント（Noneで圧縮）
        sort_keys: キーソートフラグ
        **kwargs: atomic_write_textへの追加引数

    Returns:
        atomic_write_textの戻り値
    """
    json_content = json.dumps(
        data,
        ensure_ascii=ensure_ascii,
        indent=indent,
        sort_keys=sort_keys,
        separators=(",", ": ") if indent else (",", ":"),
    )

    # Add trailing newline for consistency
    if not json_content.endswith("\n"):
        json_content += "\n"

    return atomic_write_text(file_path, json_content, **kwargs)


def safe_read_text(
    file_path: Union[str, Path],
    *,
    encoding: str = "utf-8",
    check_secrets_enabled: bool = False,
    verify_eol: bool = False,
) -> Tuple[str, Dict[str, Any]]:
    """
    Safe text file read with optional security checks

    Args:
        file_path: 読み込みファイルパス
        encoding: 文字エンコーディング
        check_secrets_enabled: secret検証を実行するか
        verify_eol: EOL検証を実行するか

    Returns:
        (content, metadata) タプル
        metadata: {'sha256': str, 'size': int, 'eol_ok': bool}

    Raises:
        FileSecurityError: secret検出時
        FileIntegrityError: EOL違反時
    """
    path = Path(file_path)

    with open(path, "r", encoding=encoding) as f:
        content = f.read()

    # Security checks
    if check_secrets_enabled:
        check_secrets(content, str(path))

    # EOL verification
    eol_ok = True
    if verify_eol:
        try:
            check_eol(content, str(path))
        except FileIntegrityError:
            eol_ok = False
            if verify_eol:
                raise

    metadata = {
        "sha256": compute_sha256(content),
        "size": len(content.encode(encoding)),
        "eol_ok": eol_ok,
    }

    return content, metadata


def safe_read_json(file_path: Union[str, Path], **kwargs) -> Tuple[Any, Dict[str, Any]]:
    """
    Safe JSON file read with optional security checks

    Args:
        file_path: 読み込みファイルパス
        **kwargs: safe_read_textへの追加引数

    Returns:
        (parsed_data, metadata) タプル
    """
    content, metadata = safe_read_text(file_path, **kwargs)

    try:
        data = json.loads(content)
        return data, metadata
    except json.JSONDecodeError as e:
        raise FileIntegrityError(f"JSON parse error in {file_path}: {e}")


# Convenience functions
def write_text_lf(file_path: Union[str, Path], content: str, **kwargs) -> Dict[str, Any]:
    """UTF-8 LF text write (convenience function)"""
    return atomic_write_text(file_path, content, encoding="utf-8", newline="\n", **kwargs)


def write_json_lf(file_path: Union[str, Path], data: Any, **kwargs) -> Dict[str, Any]:
    """UTF-8 LF JSON write (convenience function)"""
    return atomic_write_json(file_path, data, **kwargs)


def read_text_safe(file_path: Union[str, Path], **kwargs) -> str:
    """Safe text read (content only)"""
    content, _ = safe_read_text(file_path, **kwargs)
    return content


def read_json_safe(file_path: Union[str, Path], **kwargs) -> Any:
    """Safe JSON read (data only)"""
    data, _ = safe_read_json(file_path, **kwargs)
    return data
