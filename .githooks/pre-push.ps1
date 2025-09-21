#requires -version 5.1
$ErrorActionPreference = 'Stop'
$PSStyle.OutputRendering = 'PlainText'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# 1) 学習インテーク・アプリのヘルス（ポート8787）
try {
    $healthz = Invoke-RestMethod http://127.0.0.1:8787/healthz -TimeoutSec 3
    if (-not $healthz.ok) {
        Write-Error "Learning Intake App not ready at http://127.0.0.1:8787"
        exit 1
    }
    Write-Host "✅ Learning Intake App: OK" -ForegroundColor Green
} catch {
    Write-Error "Learning Intake App not running at http://127.0.0.1:8787"
    exit 1
}

# 2) ミニ回帰（ツールモード・短時間）
Write-Host "Running mini evaluation..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py --mode tools --timeout 15
if ($LASTEXITCODE -ne 0) { 
    Write-Error "Mini evaluation failed"
    exit $LASTEXITCODE 
}

Write-Host "✅ All checks passed" -ForegroundColor Green
exit 0