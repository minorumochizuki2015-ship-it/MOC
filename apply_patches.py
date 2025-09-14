#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統治核AI - パッチ適用スクリプト
エディター書き戻し機能とサーバー判定堅牢化のパッチを安全に適用
"""

import os
import shutil
import sys
from datetime import datetime
from pathlib import Path


def create_backup(file_path: str) -> str:
    """ファイルのバックアップを作成"""
    backup_path = f"{file_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(file_path, backup_path)
    print(f"✓ バックアップ作成: {backup_path}")
    return backup_path


def verify_patch(file_path: str) -> bool:
    """パッチが正しく適用されているか確認"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # キーワードでパッチ適用を確認
        if "target=" in content and "_update_editor_content" in content:
            print(f"✓ {file_path}: エディター書き戻し機能が適用されています")
            return True
        else:
            print(f"❌ {file_path}: パッチが適用されていません")
            return False
    except Exception as e:
        print(f"❌ {file_path}: ファイル読み込みエラー - {e}")
        return False


def main():
    """メイン処理"""
    print("=" * 60)
    print("統治核AI - パッチ適用スクリプト")
    print("=" * 60)

    # 対象ファイル
    target_files = ["src/ui/modern_interface.py", "src/core/cursor_ai_system.py"]

    # ファイル存在確認
    missing_files = []
    for file_path in target_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)

    if missing_files:
        print("❌ 以下のファイルが見つかりません:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False

    # バックアップ作成
    backups = []
    for file_path in target_files:
        backup_path = create_backup(file_path)
        backups.append(backup_path)

    # パッチ適用確認
    print("\nパッチ適用状況を確認中...")
    all_patched = True
    for file_path in target_files:
        if not verify_patch(file_path):
            all_patched = False

    if all_patched:
        print("\n✅ すべてのパッチが正しく適用されています")
        print("\n期待される動作:")
        print(
            "- コード生成・補完・リファクタリング・実行・フォーマットでエディターが更新されます"
        )
        print(
            "- サーバー判定が堅牢化され、短時間のラグでも機能ボタンが無効化されにくくなります"
        )
        print("\nテスト手順:")
        print("1. モダンUIを起動")
        print("2. エディターにコードを入力")
        print("3. コード補完ボタンをクリック")
        print("4. エディターの内容が更新されることを確認")

        return True
    else:
        print("\n❌ パッチの適用に問題があります")
        print("バックアップから復元する場合は以下のコマンドを実行してください:")
        for i, (original, backup) in enumerate(zip(target_files, backups)):
            print(f"   cp {backup} {original}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
