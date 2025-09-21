@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo === Docker GPU版 llama-server 起動 (デバッグ版) ===

REM [1] Docker確認
echo [1] Docker確認中...
docker --version
if %ERRORLEVEL% NEQ 0 (
  echo ERROR: Docker Desktop が必要です。
  pause & exit /b 1
)

REM [2] モデルファイル確認
echo [2] モデルファイル確認中...
set "MODEL=C:\models\qwen2-7b-instruct-q4_k_m.gguf"
if not exist "%MODEL%" (
  echo ERROR: モデルが見つかりません: %MODEL%
  echo 利用可能なモデル:
  dir C:\models\*.gguf
  pause & exit /b 1
)
echo OK: モデルファイル確認完了

REM [3] GPU確認
echo [3] GPU確認中...
set "GPU_FLAG=--gpus all"
docker run --rm %GPU_FLAG% nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
if %ERRORLEVEL% NEQ 0 (
  echo WARN: GPUが使えません
  set "GPU_FLAG="
)

REM [4] サーバ起動
echo [4] サーバ起動中...
echo ポート: 8080
echo モデル: %MODEL%
echo GPU_FLAG: %GPU_FLAG%

docker run -it --rm %GPU_FLAG% ^
  -p 8080:8080 ^
  -v C:\models:/models ^
  ghcr.io/ggerganov/llama.cpp:server-cuda ^
  --server --host 0.0.0.0 --port 8080 ^
  -m /models/qwen2-7b-instruct-q4_k_m.gguf ^
  --ctx-size 8192 ^
  -ngl 22

echo.
echo 終了しました。
pause


