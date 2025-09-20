@echo off
setlocal enabledelayedexpansion

REM === 必要に応じて直す ===
set "MODEL=C:\models\qwen2-7b-instruct-q4_k_m.gguf"   REM or C:\models\Qwen2.5-3B-Instruct-Q4_K_M.gguf
set "PORT=8080"
set "HOST=127.0.0.1"
set "CTX=8192"
set "NGL=22"                                          REM GPU無い/CPUビルドなら空にする: set "NGL="
set "LOG=D:\llama_server_python_%DATE: =_%_%TIME::=%.log"
set "LOG=%LOG:/=-%"

REM === 存在チェック ===
if not exist "%MODEL%" (
  echo [ERROR] MODEL not found: %MODEL%
  echo 利用可能なモデルを検索中...
  for /f "delims=" %%f in ('dir /s /b "*.gguf" 2^>nul') do (
    echo   - %%f
  )
  pause & exit /b 1
)

REM === ポート衝突チェック ===
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /r /c:":%PORT% .*LISTEN"') do (
  echo [WARN] Port %PORT% already in use by PID %%P
  echo  → PORT を変えるか、既存プロセスを停止してください。
  pause & exit /b 1
)

echo [INFO] logging to: %LOG%
echo --- start %DATE% %TIME% --- > "%LOG%"

REM === Python版llama-cpp-server起動 ===
set "BASEARGS=--model "%MODEL%" --host %HOST% --port %PORT% --n_ctx %CTX%"

if defined NGL (
  set "BASEARGS=%BASEARGS% --n_gpu_layers %NGL%"
)

echo [INFO] python -m llama_cpp.server %BASEARGS% >> "%LOG%"
python -m llama_cpp.server %BASEARGS% >> "%LOG%" 2>&1

set EC=%ERRORLEVEL%
echo --- exit code: %EC% --- >> "%LOG%"

echo.
if %EC% NEQ 0 (
  echo [FAILED] exit code %EC%. See "%LOG%" for details.
) else (
  echo [INFO] server exited normally. See "%LOG%".
)

echo 動作確認:  curl http://%HOST%:%PORT%/v1/models
pause


