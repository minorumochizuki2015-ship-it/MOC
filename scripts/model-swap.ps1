# 安全なモデル置換（シンボリックリンク + 原子置換）
param(
    [string]$NewModelPath = "",
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$currentLink = "models\current.gguf"
$modelsDir = "models"

Write-Host "🔄 安全なモデル置換 (DryRun: $DryRun)" -ForegroundColor Cyan

if (-not $NewModelPath) {
    Write-Error "NewModelPath is required"
    exit 1
}

if (-not (Test-Path $NewModelPath)) {
    Write-Error "New model file not found: $NewModelPath"
    exit 1
}

# ハッシュ名ディレクトリ作成
$modelHash = (Get-FileHash $NewModelPath -Algorithm SHA256).Hash
$hashDir = Join-Path $modelsDir $modelHash
$hashModelPath = Join-Path $hashDir "model.gguf"

if ($DryRun) {
    Write-Host "DRY RUN: Would copy $NewModelPath to $hashModelPath" -ForegroundColor Yellow
    Write-Host "DRY RUN: Would create symlink $currentLink -> $hashModelPath" -ForegroundColor Yellow
    exit 0
}

# ハッシュディレクトリ作成
New-Item -Force -ItemType Directory -Path $hashDir | Out-Null

# モデルファイルコピー
Write-Host "Copying model to hash directory..." -ForegroundColor Yellow
Copy-Item $NewModelPath $hashModelPath -Force

# 既存シンボリックリンク削除
if (Test-Path $currentLink) {
    Remove-Item $currentLink -Force
}

# 新しいシンボリックリンク作成
Write-Host "Creating symlink..." -ForegroundColor Yellow
New-Item -ItemType SymbolicLink -Path $currentLink -Target $hashModelPath | Out-Null

# 置換後の自動評価
Write-Host "Running post-swap evaluation..." -ForegroundColor Yellow
& .\scripts\ops\quick-health.ps1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Model swap successful" -ForegroundColor Green
    Write-Host "Current model: $currentLink -> $hashModelPath" -ForegroundColor Cyan
} else {
    Write-Warning "⚠️ Post-swap evaluation failed, consider rollback"
    Write-Host "Rollback command: git checkout mini-eval-ok-20250920" -ForegroundColor Yellow
}

exit $LASTEXITCODE
