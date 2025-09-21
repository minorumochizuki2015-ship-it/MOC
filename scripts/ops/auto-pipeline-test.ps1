# 押したら終わり自動化テスト
# PowerShell継続入力状態を避ける修正版

$ErrorActionPreference = 'Stop'

Write-Host "=== 押したら終わり自動化テスト ===" -ForegroundColor Green

# 1. アプリ起動（自動パイプライン有効）
Write-Host "`n1. アプリ起動（自動パイプライン有効）..." -ForegroundColor Yellow
$app_process = Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "scripts\ops\start-intake-app.ps1" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 8

# 2. 自動パイプライン有効確認
Write-Host "`n2. 自動パイプライン有効確認..." -ForegroundColor Yellow
try {
    $healthz = Invoke-RestMethod http://127.0.0.1:8787/healthz -TimeoutSec 5
    Write-Host "✅ サービス正常: $($healthz | ConvertTo-Json -Compress)" -ForegroundColor Green
    $service_ok = $true
}
catch {
    Write-Host "❌ サービス接続失敗: $($_.Exception.Message)" -ForegroundColor Red
    $service_ok = $false
}

# 3. 押したら終わりテスト（HTTP Push）
Write-Host "`n3. 押したら終わりテスト（HTTP Push）..." -ForegroundColor Yellow
try {
    $push_result = & "scripts\ops\cursor-integration.ps1" -Title "auto-pipeline-test" -Success $true -Prompt "Test prompt" -Output "Test output"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ HTTP Push成功（自動パイプライン起動）" -ForegroundColor Green
        $push_ok = $true
    }
    else {
        Write-Host "❌ HTTP Push失敗" -ForegroundColor Red
        $push_ok = $false
    }
}
catch {
    Write-Host "❌ HTTP Push失敗: $($_.Exception.Message)" -ForegroundColor Red
    $push_ok = $false
}

# 4. 30秒待機（自動処理確認）
Write-Host "`n4. 30秒待機（自動処理確認）..." -ForegroundColor Yellow
Write-Host "自動パイプライン処理を待機中..." -ForegroundColor Cyan
Start-Sleep -Seconds 30

# 5. 結果確認
Write-Host "`n5. 結果確認..." -ForegroundColor Yellow
$inbox_count = (Get-ChildItem "data\intake\inbox" -ErrorAction SilentlyContinue).Count
$accepted_count = (Get-ChildItem "data\intake\accepted" -ErrorAction SilentlyContinue).Count
$buckets_count = (Get-ChildItem "data\intake\buckets" -Recurse -File -ErrorAction SilentlyContinue).Count
$sft_count = (Get-ChildItem "data\sft" -ErrorAction SilentlyContinue).Count

Write-Host "inbox: $inbox_count 件" -ForegroundColor Cyan
Write-Host "accepted: $accepted_count 件" -ForegroundColor Cyan
Write-Host "buckets: $buckets_count 件" -ForegroundColor Cyan
Write-Host "sft: $sft_count 件" -ForegroundColor Cyan

$processing_ok = $accepted_count -gt 0 -or $buckets_count -gt 0 -or $sft_count -gt 0

# 6. プロセス停止
Write-Host "`n6. プロセス停止..." -ForegroundColor Yellow
if ($app_process) {
    $app_process.Kill()
    Write-Host "アプリプロセス停止完了" -ForegroundColor Green
}

# 7. 総合判定
Write-Host "`n=== 押したら終わり自動化テスト結果 ===" -ForegroundColor Green
Write-Host "サービス: $(if ($service_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($service_ok) { "Green" } else { "Red" })
Write-Host "HTTP Push: $(if ($push_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($push_ok) { "Green" } else { "Red" })
Write-Host "自動処理: $(if ($processing_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($processing_ok) { "Green" } else { "Red" })

$overall_pass = $service_ok -and $push_ok -and $processing_ok

Write-Host "`n総合結果: $(if ($overall_pass) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($overall_pass) { "Green" } else { "Red" })

if ($overall_pass) {
    Write-Host "`n✅ 押したら終わり自動化成功" -ForegroundColor Green
    Write-Host "POST/保存 → 自動フィルタ → バケット → SFT更新まで自動完了！" -ForegroundColor Cyan
    exit 0
}
else {
    Write-Host "`n❌ 押したら終わり自動化失敗" -ForegroundColor Red
    Write-Host "追加の修正が必要です。" -ForegroundColor Yellow
    exit 1
}

