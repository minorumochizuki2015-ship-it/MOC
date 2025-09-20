# 即時ヘルス & 回帰チェック（1-15秒）
# Usage: .\scripts\ops\quick-health.ps1 [-Mode <tools|agent>] [-Timeout <seconds>]

param(
    [string]$Mode = "tools",
    [int]$Timeout = 15,
    [switch]$Baseline = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "🔍 Quick Health Check (Mode: $Mode, Timeout: $Timeout)" -ForegroundColor Cyan

# 1秒ヘルス
Write-Host "`n1️⃣ ヘルスチェック..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -X utf8 -u tools\quick_diagnose.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ ヘルスチェック失敗"
    exit 1
}
Write-Host "✅ ヘルスチェック OK" -ForegroundColor Green

# 環境変数設定
$env:MINI_EVAL_MODE = $Mode
$env:MINI_EVAL_TIMEOUT = $Timeout.ToString()

# 回帰チェック
Write-Host "`n2️⃣ 回帰チェック ($Mode mode, ${Timeout}s)..." -ForegroundColor Yellow
$args = @("--mode", $Mode, "--timeout", $Timeout.ToString())
if ($Baseline) { $args += @("--baseline", "data\outputs\mini_eval_baseline.json") }
$args += @("--out", "data\outputs\mini_eval.json")
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py @args

if ($LASTEXITCODE -eq 0) {
    $result = Get-Content data\outputs\mini_eval.json | ConvertFrom-Json
    Write-Host "✅ 回帰チェック OK (Score: $($result.score))" -ForegroundColor Green
}
else {
    Write-Error "❌ 回帰チェック失敗 (Exit: $LASTEXITCODE)"
    exit 1
}

Write-Host "`n🎉 全チェック完了！" -ForegroundColor Green
