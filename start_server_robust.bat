@echo off
setlocal enabledelayedexpansion

REM === 必要に応じて直す ===
set "MODEL=C:\models\qwen2-7b-instruct-q4_k_m.gguf"   REM or C:\models\Qwen2.5-3B-Instruct-Q4_K_M.gguf
set "EXE=C:\llama\server.exe"                         REM 例: llama.cpp の server.exe
REM set "EXE=C:\llama\llama.exe"                      REM 例: llama.exe の場合（--server 必須）
set "PORT=8080"
set "HOST=127.0.0.1"
set "CTX=8192"
set "NGL=22"                                          REM GPU無い/CPUビルドなら空にする: set "NGL="
set "LOG=D:\llama_server_%DATE: =_%_%TIME::=%.log"
set "LOG=%LOG:/=-%"

REM === 存在チェック ===
if not exist "%MODEL%" (
  echo [ERROR] MODEL not found: %MODEL%
  pause & exit /b 1
)
if not exist "%EXE%" (
  echo [ERROR] EXE not found: %EXE%
  echo ヒント: どこにあるか探す →  where /R C:\ llama.exe ^| findstr /i llama
  echo                                   where /R C:\ server.exe ^| findstr /i server
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

REM === 起動（llama.exe なら --server を付ける） ===
set "LEAF=%EXE%"
for %%A in ("%EXE%") do set "LEAF=%%~nxA"

if /i "%LEAF%"=="llama.exe" (
  set "BASEARGS=--server -m "%MODEL%" --ctx-size %CTX% --host %HOST% --port %PORT%"
) else (
  set "BASEARGS=-m "%MODEL%" --ctx-size %CTX% --host %HOST% --port %PORT%"
)

if defined NGL (
  set "BASEARGS=%BASEARGS% -ngl %NGL%"
)

echo [INFO] "%EXE%" %BASEARGS% >> "%LOG%"
"%EXE%" %BASEARGS%  >> "%LOG%" 2>&1

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
