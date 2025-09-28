#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安定した起動スクリプトを作成
エラーの繰り返しを防ぐ
"""

import os


def create_stable_launcher():
    print("安定した起動スクリプトを作成中...")
    print("=" * 40)

    # 1. 統合起動スクリプト（エラーハンドリング付き）
    stable_launcher = """@echo off
chcp 65001 > nul
title 統治核AI - 安定起動システム

echo.
echo ========================================
echo    統治核AI - 安定起動システム
echo ========================================
echo.

:MAIN_MENU
echo 起動オプションを選択してください:
echo.
echo 1. モダンUI (推奨)
echo 2. 従来UI
echo 3. サーバーのみ
echo 4. システム診断
echo 5. 終了
echo.

set /p choice="選択してください (1-5): "

if "%choice%"=="1" goto START_MODERN
if "%choice%"=="2" goto START_CLASSIC
if "%choice%"=="3" goto START_SERVER_ONLY
if "%choice%"=="4" goto SYSTEM_DIAGNOSIS
if "%choice%"=="5" goto EXIT
goto INVALID_CHOICE

:START_MODERN
echo.
echo モダンUIを起動中...
echo ==================

echo 1. サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 2. 5秒待機中...
timeout /t 5 /nobreak > nul

echo 3. モダンUIを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main_modern.py

if errorlevel 1 (
    echo.
    echo ❌ モダンUIの起動に失敗しました
    echo フォールバック: 従来UIを起動します...
    "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main.py
)

goto MAIN_MENU

:START_CLASSIC
echo.
echo 従来UIを起動中...
echo ================

echo 1. サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 2. 5秒待機中...
timeout /t 5 /nobreak > nul

echo 3. 従来UIを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main.py

goto MAIN_MENU

:START_SERVER_ONLY
echo.
echo サーバーのみ起動中...
echo ==================

"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -m llama_cpp.server --model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf" --host 127.0.0.1 --port 8080 --ctx-size 4096 --batch-size 1024 --gpu-layers -1 --chat-template qwen --verbose true

goto MAIN_MENU

:SYSTEM_DIAGNOSIS
echo.
echo システム診断を実行中...
echo ====================

"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -c "
import os, sys
print('Python:', sys.executable)
print('Python version:', sys.version)
print('Current directory:', os.getcwd())
print('PYTHONPATH:', os.environ.get('PYTHONPATH', 'Not set'))
print()

# ファイル存在確認
important_files = ['main.py', 'main_modern.py', 'src/core/kernel.py', 'src/ui/modern_interface.py']
for f in important_files:
    if os.path.exists(f):
        print(f'✓ {f}')
    else:
        print(f'✗ {f}')

print()
print('診断完了')
"

echo.
echo 診断完了。メインメニューに戻ります...
timeout /t 3 /nobreak > nul
goto MAIN_MENU

:INVALID_CHOICE
echo.
echo ❌ 無効な選択です。1-5の数字を入力してください。
timeout /t 2 /nobreak > nul
goto MAIN_MENU

:EXIT
echo.
echo 終了します...
timeout /t 2 /nobreak > nul
exit
"""

    with open("統治核AI_安定起動.bat", "w", encoding="utf-8") as f:
        f.write(stable_launcher)
    print("✓ 統治核AI_安定起動.bat を作成")

    # 2. クイック起動スクリプト（モダンUI）
    quick_modern = """@echo off
chcp 65001 > nul
title 統治核AI - モダンUI (クイック起動)

echo 統治核AI - モダンUI クイック起動
echo ================================

echo サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 5秒待機中...
timeout /t 5 /nobreak > nul

echo モダンUIを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main_modern.py

if errorlevel 1 (
    echo.
    echo ❌ モダンUIの起動に失敗しました
    echo 従来UIを起動します...
    "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main.py
)

pause
"""

    with open("モダンUI_クイック起動.bat", "w", encoding="utf-8") as f:
        f.write(quick_modern)
    print("✓ モダンUI_クイック起動.bat を作成")

    # 3. エラー防止スクリプト
    error_prevention = """@echo off
chcp 65001 > nul
title 統治核AI - エラー防止システム

echo 統治核AI - エラー防止システム
echo =============================

echo 1. 不要ファイルをクリーンアップ中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" ultimate_cleanup.py

echo.
echo 2. システム状態を確認中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -c "
import os, sys
print('システム状態確認')
print('================')
print(f'Python: {sys.executable}')
print(f'作業ディレクトリ: {os.getcwd()}')
print()

# 重要なファイルの確認
files = ['main.py', 'main_modern.py', 'src/core/kernel.py', 'src/ui/modern_interface.py']
all_ok = True
for f in files:
    if os.path.exists(f):
        size = os.path.getsize(f)
        print(f'✓ {f} ({size} bytes)')
    else:
        print(f'✗ {f} が見つかりません')
        all_ok = False

if all_ok:
    print()
    print('✅ システムは正常です')
else:
    print()
    print('❌ システムに問題があります')
"

echo.
echo 3. 安定起動システムを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -c "
import subprocess
import sys
subprocess.run([sys.executable, 'main_modern.py'])
"

pause
"""

    with open("エラー防止システム.bat", "w", encoding="utf-8") as f:
        f.write(error_prevention)
    print("✓ エラー防止システム.bat を作成")

    print("\n✅ 安定した起動スクリプト作成完了！")
    print("=" * 40)
    print("作成されたファイル:")
    print("- 統治核AI_安定起動.bat (メイン起動)")
    print("- モダンUI_クイック起動.bat (クイック起動)")
    print("- エラー防止システム.bat (エラー防止)")


if __name__ == "__main__":
    create_stable_launcher()
    input("Press Enter to continue...")
