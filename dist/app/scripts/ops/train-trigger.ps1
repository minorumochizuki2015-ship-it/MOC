# 学習トリガー統合（ローカルトレーナー委譲）
# Usage: .\scripts\ops\train-trigger.ps1 [-PlanOnly] [-Trainer <path>]

param(
    [switch]$PlanOnly = $false,
    [string]$Trainer = "",
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "🚀 学習トリガー (PlanOnly: $PlanOnly, DryRun: $DryRun)" -ForegroundColor Cyan

# 環境変数確認
$trainer = if ($Trainer) { $Trainer } else { $env:LOCAL_LORA_TRAINER }
if (-not $trainer) {
    Write-Warning "⚠️  LOCAL_LORA_TRAINER not set, using default trainer"
    $trainer = "scripts\trainer\local_trainer.ps1"
}

Write-Host "Trainer: $trainer" -ForegroundColor Yellow

if ($DryRun) {
    Write-Host "DRY RUN: Would execute training trigger" -ForegroundColor Yellow
    exit 0
}

# 学習計画生成
if ($PlanOnly) {
    Write-Host "`n📋 学習計画生成のみ..." -ForegroundColor Yellow
    & .\.venv\Scripts\python.exe -X utf8 -u tools\train_local.py --plan-only
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ 学習計画生成完了" -ForegroundColor Green
    } else {
        Write-Error "❌ 学習計画生成失敗"
        exit 1
    }
} else {
    # 実学習実行
    Write-Host "`n🏃 学習実行..." -ForegroundColor Yellow
    & .\scripts\trigger-training.ps1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ 学習実行完了" -ForegroundColor Green
    } else {
        Write-Error "❌ 学習実行失敗"
        exit 1
    }
}

Write-Host "`n🎉 学習トリガー完了！" -ForegroundColor Green
