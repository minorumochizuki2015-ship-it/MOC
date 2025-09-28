#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最終的なクリーンアップスクリプト
エラーの繰り返しを防ぐ
"""

import glob
import os
import shutil
from pathlib import Path


def main():
    print("最終的なクリーンアップ実行")
    print("=" * 40)

    # 削除対象ファイル（パターンマッチング）
    patterns_to_delete = [
        # デバッグ・テストファイル
        "debug_*.py",
        "test_*.py",
        "fix_*.py",
        "*_test.py",
        "*_debug.py",
        "*_fix.py",
        "*_cleanup.py",
        "*_setup.py",
        "*_diagnosis.py",
        "*_timeout.py",
        # バッチファイル（一時的なもの）
        "debug_*.bat",
        "test_*.bat",
        "fix_*.bat",
        "*_test.bat",
        "*_debug.bat",
        "*_fix.bat",
        "*_cleanup.bat",
        "*_setup.bat",
        "*_diagnosis.bat",
        "*_timeout.bat",
        "run_*.bat",
        # その他の一時ファイル
        "*.tmp",
        "*.temp",
        "*.log",
        "*.bak",
        "*.backup",
        "*.old",
    ]

    deleted_files = []
    deleted_dirs = []

    print("1. 一時ファイルを削除中...")

    for pattern in patterns_to_delete:
        files = glob.glob(pattern)
        for file_path in files:
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    deleted_files.append(file_path)
                    print(f"✓ 削除: {file_path}")
            except Exception as e:
                print(f"✗ 削除失敗: {file_path} - {e}")

    print(f"✓ {len(deleted_files)}個のファイルを削除しました")

    print("\n2. キャッシュディレクトリを削除中...")

    cache_dirs = [
        "__pycache__",
        "src/__pycache__",
        "src/core/__pycache__",
        "src/ui/__pycache__",
        "src/utils/__pycache__",
        "src/genetic/__pycache__",
        "src/legacy/__pycache__",
        "modules/DCARD_Resonance_Distillation/__pycache__",
        "modules/DCARD_Resonance_Distillation/dcard_core/__pycache__",
        "modules/SetupTools/__pycache__",
    ]

    for cache_dir in cache_dirs:
        if os.path.exists(cache_dir):
            try:
                shutil.rmtree(cache_dir)
                deleted_dirs.append(cache_dir)
                print(f"✓ 削除: {cache_dir}")
            except Exception as e:
                print(f"✗ 削除失敗: {cache_dir} - {e}")

    print(f"✓ {len(deleted_dirs)}個のディレクトリを削除しました")

    print("\n3. 重複ファイルを確認中...")

    # ルートディレクトリの重複ファイルをチェック
    root_files = [f for f in os.listdir(".") if os.path.isfile(f)]
    for file_name in root_files:
        if file_name in ["kernel.py", "interface.py", "governance.py"]:
            # src/内に同じファイルがある場合はルートのものを削除
            src_path = f"src/core/{file_name}"
            if os.path.exists(src_path):
                try:
                    os.remove(file_name)
                    print(f"✓ 重複ファイル削除: {file_name}")
                except Exception as e:
                    print(f"✗ 重複ファイル削除失敗: {file_name} - {e}")

    print("\n4. バックアップディレクトリを整理中...")

    backup_dir = "backups"
    if os.path.exists(backup_dir):
        # 最新の3つのバックアップ以外を削除
        backup_files = []
        for file_name in os.listdir(backup_dir):
            file_path = os.path.join(backup_dir, file_name)
            if os.path.isfile(file_path):
                backup_files.append((file_path, os.path.getmtime(file_path)))

        # 更新日時でソート（新しい順）
        backup_files.sort(key=lambda x: x[1], reverse=True)

        # 最新の3つ以外を削除
        for file_path, _ in backup_files[3:]:
            try:
                os.remove(file_path)
                print(f"✓ 古いバックアップ削除: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"✗ バックアップ削除失敗: {file_path} - {e}")

    print("\n5. 最終確認...")

    # 重要なファイルの存在確認
    important_files = [
        "main.py",
        "main_modern.py",
        "start_gui.py",
        "src/core/kernel.py",
        "src/core/cursor_ai_system.py",
        "src/ui/modern_interface.py",
        "src/ui/cursor_ai_interface.py",
        "requirements.txt",
        "scripts/Start-Server-8080.ps1",
    ]

    missing_files = []
    for file_path in important_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
        else:
            print(f"✓ 存在確認: {file_path}")

    if missing_files:
        print(f"\n⚠️ 重要なファイルが見つかりません: {missing_files}")
        return False
    else:
        print("\n✅ すべての重要なファイルが存在します")

    print("\n" + "=" * 40)
    print("クリーンアップ完了！")
    print("=" * 40)
    print(f"削除されたファイル: {len(deleted_files)}個")
    print(f"削除されたディレクトリ: {len(deleted_dirs)}個")
    print("\n残された重要なファイル:")
    print("- main.py (従来UI)")
    print("- main_modern.py (モダンUI)")
    print("- start_gui.py (GUI起動)")
    print("- src/ (コアシステム)")
    print("- scripts/ (サーバー起動スクリプト)")
    print("- requirements.txt (依存関係)")
    print("- README.md (ドキュメント)")

    return True


if __name__ == "__main__":
    success = main()
    print("\nResult: " + ("SUCCESS" if success else "FAILED"))
    input("Press Enter to continue...")
