# 継続運用監視（見るポイント確認）
# Usage: .\scripts\ops\monitor-status.ps1 [-Fix] [-LogRotate]

# 単一インスタンス実行
$mtx = New-Object System.Threading.Mutex($false, "GC_$($MyInvocation.MyCommand.Name)")
if (-not $mtx.WaitOne(0)) { exit 0 }

param(
    [switch]$Fix = $false,
    [switch]$LogRotate = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "📊 継続運用監視" -ForegroundColor Cyan

# 1. hooksPath確認
Write-Host "`n1️⃣ Git hooksPath確認..." -ForegroundColor Yellow
$hooksPath = git config core.hooksPath
if ($hooksPath -eq ".githooks") {
    Write-Host "✅ hooksPath: $hooksPath" -ForegroundColor Green
}
else {
    Write-Warning "⚠️  hooksPath: $hooksPath (expected: .githooks)"
    if ($Fix) {
        git config core.hooksPath .githooks
        Write-Host "🔧 Fixed: hooksPath set to .githooks" -ForegroundColor Green
    }
}

# 2. 環境変数確認
Write-Host "`n2️⃣ 環境変数確認..." -ForegroundColor Yellow
$miniEvalMode = $env:MINI_EVAL_MODE
$miniEvalTimeout = $env:MINI_EVAL_TIMEOUT
Write-Host "MINI_EVAL_MODE: $miniEvalMode" -ForegroundColor $(if ($miniEvalMode) { "Green" } else { "Yellow" })
Write-Host "MINI_EVAL_TIMEOUT: $miniEvalTimeout" -ForegroundColor $(if ($miniEvalTimeout) { "Green" } else { "Yellow" })

# 3. 学習成果確認
Write-Host "`n3️⃣ 学習成果確認..." -ForegroundColor Yellow
$loraDir = "dist\lora"
if (Test-Path $loraDir) {
    $loraFiles = Get-ChildItem $loraDir -File | Select-Object Name, Length, LastWriteTime
    if ($loraFiles.Count -gt 0) {
        Write-Host "✅ LoRA成果物: $($loraFiles.Count) files" -ForegroundColor Green
        $loraFiles | Format-Table Name, @{Name = "Size(KB)"; Expression = { [math]::Round($_.Length / 1KB, 1) } }, LastWriteTime -AutoSize
    }
    else {
        Write-Host "ℹ️  LoRA成果物なし" -ForegroundColor Blue
    }
}
else {
    Write-Host "ℹ️  LoRA成果物ディレクトリなし" -ForegroundColor Blue
}

# 4. ログ肥大確認
Write-Host "`n4️⃣ ログ肥大確認..." -ForegroundColor Yellow
$logDir = "data\logs"
if (Test-Path $logDir) {
    $logSize = (Get-ChildItem $logDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $logSizeMB = [math]::Round($logSize / 1MB, 2)
    Write-Host "ログ総サイズ: ${logSizeMB}MB" -ForegroundColor $(if ($logSizeMB -gt 100) { "Yellow" } else { "Green" })
    
    if ($LogRotate -and $logSizeMB -gt 50) {
        Write-Host "🔧 ログローテーション実行..." -ForegroundColor Yellow
        $oldLogs = Get-ChildItem $logDir -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) }
        if ($oldLogs.Count -gt 0) {
            $oldLogs | Remove-Item -Force
            Write-Host "✅ 14日以上古いログを削除: $($oldLogs.Count) files" -ForegroundColor Green
        }
    }
}
else {
    Write-Host "ℹ️  ログディレクトリなし" -ForegroundColor Blue
}

# 5. 最近のmini_eval履歴
Write-Host "`n5️⃣ 最近のmini_eval履歴..." -ForegroundColor Yellow
$historyFile = "data\logs\current\mini_eval_history.jsonl"
if (Test-Path $historyFile) {
    $recent = Get-Content $historyFile -Tail 3 | ForEach-Object { $_ | ConvertFrom-Json }
    if ($recent.Count -gt 0) {
        Write-Host "最近の評価結果:" -ForegroundColor Green
        $recent | Format-Table @{Name = "Time"; Expression = { [DateTime]::Parse($_.timestamp).ToString("MM/dd HH:mm") } }, score, success, @{Name = "Elapsed(ms)"; Expression = { $_.elapsed_ms } } -AutoSize
    }
}
else {
    Write-Host "ℹ️  評価履歴なし" -ForegroundColor Blue
}

Write-Host "`n🎉 監視完了！" -ForegroundColor Green
