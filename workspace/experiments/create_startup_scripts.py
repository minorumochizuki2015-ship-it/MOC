#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
起動用スクリプトを作成
"""

import os


def create_startup_scripts():
    print("起動用スクリプトを作成中...")
    print("=" * 40)

    # 1. モダンUI起動スクリプト
    modern_ui_bat = """@echo off
echo 統治核AI - モダンUI起動
echo ========================

echo サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 5秒待機中...
timeout /t 5 /nobreak > nul

echo モダンUIを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main_modern.py

pause
"""

    with open("起動_モダンUI.bat", "w", encoding="utf-8") as f:
        f.write(modern_ui_bat)
    print("✓ 起動_モダンUI.bat を作成")

    # 2. 従来UI起動スクリプト
    classic_ui_bat = """@echo off
echo 統治核AI - 従来UI起動
echo =====================

echo サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 5秒待機中...
timeout /t 5 /nobreak > nul

echo 従来UIを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main.py

pause
"""

    with open("起動_従来UI.bat", "w", encoding="utf-8") as f:
        f.write(classic_ui_bat)
    print("✓ 起動_従来UI.bat を作成")

    # 3. サーバーのみ起動スクリプト
    server_only_bat = """@echo off
echo 統治核AI - サーバーのみ起動
echo ==========================

echo サーバーを起動中...
"C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -m llama_cpp.server --model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf" --host 127.0.0.1 --port 8080 --ctx-size 4096 --batch-size 1024 --gpu-layers -1 --chat-template qwen --verbose true

pause
"""

    with open("起動_サーバーのみ.bat", "w", encoding="utf-8") as f:
        f.write(server_only_bat)
    print("✓ 起動_サーバーのみ.bat を作成")

    # 4. 統合起動スクリプト
    integrated_bat = """@echo off
echo 統治核AI - 統合起動
echo ==================

echo 1. サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\\Start-Server-8080.ps1" -Model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf"

echo 2. 5秒待機中...
timeout /t 5 /nobreak > nul

echo 3. UI選択メニュー
echo ================
echo 1. モダンUI (推奨)
echo 2. 従来UI
echo 3. サーバーのみ
echo.

set /p choice="選択してください (1-3): "

if "%choice%"=="1" (
    echo モダンUIを起動中...
    "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main_modern.py
) else if "%choice%"=="2" (
    echo 従来UIを起動中...
    "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" main.py
) else if "%choice%"=="3" (
    echo サーバーのみ起動中...
    "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\python.exe" -m llama_cpp.server --model "C:\\models\\qwen2-7b-instruct-q4_k_m.gguf" --host 127.0.0.1 --port 8080 --ctx-size 4096 --batch-size 1024 --gpu-layers -1 --chat-template qwen --verbose true
) else (
    echo 無効な選択です
)

pause
"""

    with open("起動_統合.bat", "w", encoding="utf-8") as f:
        f.write(integrated_bat)
    print("✓ 起動_統合.bat を作成")

    print("\n✅ 起動用スクリプト作成完了！")
    print("=" * 40)
    print("作成されたファイル:")
    print("- 起動_モダンUI.bat (推奨)")
    print("- 起動_従来UI.bat")
    print("- 起動_サーバーのみ.bat")
    print("- 起動_統合.bat (メニュー選択)")


if __name__ == "__main__":
    create_startup_scripts()
    input("Press Enter to continue...")
