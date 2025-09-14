@echo off
echo 統治核AI - モダンUI起動
echo ========================

echo サーバーを起動中...
start "AI Server" powershell -ExecutionPolicy Bypass -File "scripts\Start-Server-8080.ps1" -Model "C:\models\qwen2-7b-instruct-q4_k_m.gguf"

echo 5秒待機中...
timeout /t 5 /nobreak > nul

echo モダンUIを起動中...
"C:\Users\User\AppData\Local\Programs\Python\Python310\python.exe" main_modern.py

pause

