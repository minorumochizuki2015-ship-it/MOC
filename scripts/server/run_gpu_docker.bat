@echo off
setlocal
cd /d "%~dp0"

echo === Docker GPU版 llama-server 起動 ===

REM [1] Docker確認
echo [1] Docker確認中...
docker --version >nul 2>&1 || (
  echo ERROR: Docker Desktop is required
  pause & exit /b 1
)

REM [2] モデルファイル確認
echo [2] モデルファイル確認中...
set "MODEL=C:\models\qwen2-7b-instruct-q4_k_m.gguf"
if not exist "%MODEL%" (
  echo ERROR: Model not found: %MODEL%
  pause & exit /b 1
)
echo OK: Model file confirmed

REM [3] GPU確認
echo [3] GPU確認中...
set "GPU_FLAG=--gpus all"
docker run --rm %GPU_FLAG% nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi >nul 2>&1 || (
  echo WARN: GPU not available
  set "GPU_FLAG="
)

REM [4] サーバ起動
echo [4] サーバ起動中...
echo Port: 8080
echo Model: %MODEL%
echo GPU_FLAG: %GPU_FLAG%

docker run -d --rm %GPU_FLAG% ^
  -p 8080:8080 ^
  -v C:\models:/models ^
  ghcr.io/ggerganov/llama.cpp:server-cuda ^
  --host 0.0.0.0 --port 8080 ^
  -m /models/qwen2-7b-instruct-q4_k_m.gguf ^
  --ctx-size 8192 ^
  -ngl 22

echo.
echo Server started in background
pause
