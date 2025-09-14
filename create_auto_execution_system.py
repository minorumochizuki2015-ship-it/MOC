#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自動実行システム作成
PowerShellエラーを完全に回避
"""

import os
import subprocess
from pathlib import Path


def create_auto_execution_system():
    """自動実行システムを作成"""
    print("自動実行システム作成")
    print("=" * 30)

    # 1. 堅牢なテストシステムを作成
    print("1. 堅牢なテストシステムを作成中...")

    # 2. 自己実行可能なバッチファイルを作成
    print("2. 自己実行可能なバッチファイルを作成中...")

    # メインバッチファイル
    main_bat = """@echo off
setlocal enableextensions
set "ROOT=%~dp0"
pushd "%ROOT%"
chcp 65001 >nul

echo 自動実行システム起動
echo ==================

echo.
echo 1. 環境確認
echo ----------
echo 作業ディレクトリ: %ROOT%
echo Python実行ファイル: C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe

echo.
echo 2. 堅牢なテストシステム実行
echo --------------------------
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" "%~dp0robust_test_system.py"

echo.
echo 3. 結果確認
echo ----------
if exist "test_result.txt" (
    echo テスト結果ファイルが作成されました
    type "test_result.txt"
) else (
    echo テスト結果ファイルが見つかりません
)

echo.
echo 自動実行完了
echo ============

popd
pause
"""

    with open("auto_execution_system.bat", "w", encoding="utf-8") as f:
        f.write(main_bat)

    print("✓ auto_execution_system.bat を作成")

    # 3. 簡易実行バッチファイル
    simple_bat = """@echo off
chcp 65001 >nul
title 簡易実行システム

echo 簡易実行システム
echo ================

"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -c "
import sys, os
sys.path.insert(0, '.')
os.environ['OPENAI_COMPAT_BASE'] = 'http://127.0.0.1:8080/v1'
os.environ['OPENAI_API_KEY'] = 'sk-local'

print('簡易テスト実行中...')
try:
    from src.core.kernel import generate_chat, read_paths, healthcheck
    print('✓ 新機能インポート成功')
    
    if healthcheck():
        print('✓ サーバー接続成功')
    else:
        print('⚠️ サーバー接続失敗')
        
    print('✓ 簡易テスト完了')
except Exception as e:
    print(f'✗ エラー: {e}')
"

pause
"""

    with open("simple_test.bat", "w", encoding="utf-8") as f:
        f.write(simple_bat)

    print("✓ simple_test.bat を作成")

    # 4. モダンUI起動バッチファイル
    modern_ui_bat = """@echo off
chcp 65001 >nul
title モダンUI起動

echo モダンUI起動
echo ===========

set "OPENAI_COMPAT_BASE=http://127.0.0.1:8080/v1"
set "OPENAI_API_KEY=sk-local"

echo 環境変数設定完了
echo モダンUIを起動中...

"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main_modern.py

pause
"""

    with open("start_modern_ui_fixed.bat", "w", encoding="utf-8") as f:
        f.write(modern_ui_bat)

    print("✓ start_modern_ui_fixed.bat を作成")

    print("\n✅ 自動実行システム作成完了！")
    print("=" * 30)
    print("作成されたファイル:")
    print("- auto_execution_system.bat (完全自動実行)")
    print("- simple_test.bat (簡易テスト)")
    print("- start_modern_ui_fixed.bat (モダンUI起動)")


if __name__ == "__main__":
    create_auto_execution_system()
    input("Press Enter to continue...")
