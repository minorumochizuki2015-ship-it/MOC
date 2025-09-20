# データ収集自走設定（Task Scheduler）
# Usage: .\scripts\ops\setup-data-collection.ps1 [-Interval <minutes>] [-Remove]

param(
    [int]$Interval = 30,
    [switch]$Remove = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$taskName = "gc-data-loop"
$scriptPath = Join-Path $PWD "scripts\data-collection-loop.ps1"
$workingDir = $PWD

Write-Host "📊 データ収集自走設定 (Interval: ${Interval}min)" -ForegroundColor Cyan

if ($Remove) {
    Write-Host "`n🗑️  既存タスクを削除..." -ForegroundColor Yellow
    schtasks /Delete /TN $taskName /F 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ タスク削除完了" -ForegroundColor Green
    }
    else {
        Write-Host "ℹ️  削除対象タスクなし" -ForegroundColor Blue
    }
    exit 0
}

# 既存タスクを削除
Write-Host "`n🗑️  既存タスクを削除..." -ForegroundColor Yellow
schtasks /Delete /TN $taskName /F 2>$null

# 新しいタスクを作成
Write-Host "`n➕ 新しいタスクを作成..." -ForegroundColor Yellow
$command = "powershell -ExecutionPolicy Bypass -File `"$scriptPath`""
$schedule = if ($Interval -lt 60) { "MINUTE" } else { "HOURLY" }
$modifier = if ($Interval -lt 60) { $Interval } else { [math]::Floor($Interval / 60) }

schtasks /Create /TN $taskName /TR $command /SC $schedule /MO $modifier /RU SYSTEM /RP "" /F

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ データ収集タスク作成完了" -ForegroundColor Green
    Write-Host "Task: $taskName" -ForegroundColor Yellow
    Write-Host "Schedule: $schedule / $modifier" -ForegroundColor Yellow
    Write-Host "Script: $scriptPath" -ForegroundColor Yellow
}
else {
    Write-Error "❌ タスク作成失敗"
    exit 1
}

# タスクの確認
Write-Host "`n📋 タスク詳細:" -ForegroundColor Cyan
schtasks /Query /TN $taskName /FO LIST

Write-Host "`n🔧 管理コマンド:" -ForegroundColor Cyan
Write-Host "即時実行: schtasks /Run /TN $taskName" -ForegroundColor White
Write-Host "停止: schtasks /End /TN $taskName" -ForegroundColor White
Write-Host "削除: schtasks /Delete /TN $taskName /F" -ForegroundColor White
Write-Host "再設定: .\scripts\ops\setup-data-collection.ps1 -Remove" -ForegroundColor White
