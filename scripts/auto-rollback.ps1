# 自動ロールバックシステム（mini_eval失敗時）
param(
    [string]$BaselineTag = "",
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'

# ベースラインタグの自動検出
if (-not $BaselineTag) {
    $tags = git tag -l "mini-eval-ok-*" | Sort-Object -Descending
    if ($tags.Count -eq 0) {
        Write-Error "No baseline tags found (mini-eval-ok-*)"
        exit 1
    }
    $BaselineTag = $tags[0]
}

Write-Host "Using baseline tag: $BaselineTag"

# 現在の状態を確認
$currentBranch = git branch --show-current
$currentCommit = git rev-parse HEAD
Write-Host "Current branch: $currentBranch"
Write-Host "Current commit: $currentCommit"

# mini_evalを実行してスコアを確認
Write-Host "Running mini_eval to check current score..."
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py --mode tools --timeout 15 --baseline data\outputs\mini_eval_baseline.json --out data\outputs\mini_eval.json

if ($LASTEXITCODE -ne 0) {
    Write-Warning "mini_eval failed with exit code $LASTEXITCODE"
} else {
    # スコアを解析
    $result = Get-Content data\outputs\mini_eval.json | ConvertFrom-Json
    $score = $result.score
    Write-Host "Current score: $score"
    
    # スコアが5未満の場合はロールバック
    if ($score -match '(\d+)/\d+' -and [int]$matches[1] -lt 5) {
        Write-Warning "Score is below 5, triggering rollback..."
    } else {
        Write-Host "Score is acceptable, no rollback needed"
        exit 0
    }
}

if ($DryRun) {
    Write-Host "DRY RUN: Would rollback to $BaselineTag"
    Write-Host "Command: git checkout $BaselineTag"
    exit 0
}

# ロールバック実行
Write-Host "Rolling back to baseline: $BaselineTag"

# 現在の変更を保存（オプション）
$backupBranch = "backup-before-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
git checkout -b $backupBranch
Write-Host "Created backup branch: $backupBranch"

# ベースラインにチェックアウト
git checkout $BaselineTag

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully rolled back to $BaselineTag"
    Write-Host "Backup branch: $backupBranch"
    Write-Host "To restore: git checkout $backupBranch"
} else {
    Write-Error "❌ Failed to rollback to $BaselineTag"
    exit 1
}

# ロールバック後の確認
Write-Host "Verifying rollback with mini_eval..."
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py --mode tools --timeout 15 --baseline data\outputs\mini_eval_baseline.json --out data\outputs\mini_eval.json

if ($LASTEXITCODE -eq 0) {
    $result = Get-Content data\outputs\mini_eval.json | ConvertFrom-Json
    Write-Host "Post-rollback score: $($result.score)"
    Write-Host "✅ Rollback verification successful"
} else {
    Write-Warning "⚠️  Post-rollback verification failed"
}
