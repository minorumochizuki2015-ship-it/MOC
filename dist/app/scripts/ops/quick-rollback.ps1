# ロールバック統合（ベースライン復元）
# Usage: .\scripts\ops/quick-rollback.ps1 [-Tag <tag>] [-DryRun] [-Verify]

param(
    [string]$Tag = "",
    [switch]$DryRun = $false,
    [switch]$Verify = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "🔄 ロールバック統合" -ForegroundColor Cyan

# ベースラインタグの自動検出
if (-not $Tag) {
    $tags = git tag -l "mini-eval-ok-*" | Sort-Object -Descending
    if ($tags.Count -eq 0) {
        Write-Error "❌ ベースラインタグが見つかりません (mini-eval-ok-*)"
        exit 1
    }
    $Tag = $tags[0]
}

Write-Host "対象タグ: $Tag" -ForegroundColor Yellow

# 現在の状態確認
$currentBranch = git branch --show-current
$currentCommit = git rev-parse HEAD
Write-Host "現在ブランチ: $currentBranch" -ForegroundColor Yellow
Write-Host "現在コミット: $currentCommit" -ForegroundColor Yellow

if ($DryRun) {
    Write-Host "`n🔍 DRY RUN: ロールバック予定" -ForegroundColor Yellow
    Write-Host "対象: $Tag" -ForegroundColor White
    Write-Host "現在: $currentCommit" -ForegroundColor White
    exit 0
}

# バックアップブランチ作成
$backupBranch = "backup-before-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Host "`n💾 バックアップブランチ作成: $backupBranch" -ForegroundColor Yellow
git checkout -b $backupBranch
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ バックアップブランチ作成失敗"
    exit 1
}

# ベースラインにチェックアウト
Write-Host "`n🔄 ベースラインにロールバック: $Tag" -ForegroundColor Yellow
git checkout $Tag
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ ロールバック失敗"
    Write-Host "復元: git checkout $backupBranch" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ ロールバック完了" -ForegroundColor Green
Write-Host "バックアップ: $backupBranch" -ForegroundColor Yellow

if ($Verify) {
    Write-Host "`n🔍 ロールバック検証..." -ForegroundColor Yellow
    & .\scripts\ops\quick-health.ps1 -Mode tools -Timeout 15
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ ロールバック検証成功" -ForegroundColor Green
    } else {
        Write-Warning "⚠️  ロールバック検証失敗"
    }
}

Write-Host "`n🎉 ロールバック完了！" -ForegroundColor Green
Write-Host "復元コマンド: git checkout $backupBranch" -ForegroundColor Cyan
