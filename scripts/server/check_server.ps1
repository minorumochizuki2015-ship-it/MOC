@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo === Docker GPU版 llama-server 起動 ===

REM [1] Docker
docker --version >nul 2>&1 || (
    echo ERROR: Docker Desktop が必要です。インストール後に再実行してください。
    pause & exit /b 1
)

REM [2] NVIDIA Container Toolkit / GPU可用性確認
set "GPU_FLAG=--gpus all"
docker run --rm %GPU_FLAG% nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi >nul 2>&1 || (
    echo WARN: GPUが使えません（NVIDIA Container Toolkit/WSL2設定未完 or 未対応）
    echo → CPUモードで起動します。
    set "GPU_FLAG="
)

REM [3] サーバ起動（モデルは C:\models を /models にマウント）
set "MODEL=C:\models\qwen2-7b-instruct-q4_k_m.gguf"
if not exist "%MODEL%" (
    echo ERROR: モデルが見つかりません: %MODEL%
    echo 例) C:\models\qwen2-7b-instruct-q4_k_m.gguf を配置してください。
pause & exit /b 1
)

echo ポート: 8080
echo モデル: %MODEL%
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


