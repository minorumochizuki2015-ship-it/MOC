@echo off
setlocal
python -X utf8 -u tools/quick_diagnose.py
if %ERRORLEVEL% equ 0 exit /b 0
if %ERRORLEVEL% equ 1 (
    echo [WARN] quick_diagnose: 环境/依存に未解決あり
    exit /b 1
)
echo [ERR] quick_diagnose: 危険設定/実装検出
exit /b 2
