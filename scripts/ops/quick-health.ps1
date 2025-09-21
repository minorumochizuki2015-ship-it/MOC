# 学習インテーク・アプリ健康監視スクリプト
# 落ちてたら気づく用

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== 学習インテーク・アプリ健康監視 ===" -ForegroundColor Green

# 1. サービス生存確認
Write-Host "`n1. サービス生存確認..." -ForegroundColor Yellow
try {
    $healthz = Invoke-RestMethod http://127.0.0.1:8787/healthz -TimeoutSec 5
    if ($healthz.ok) {
        Write-Host "✅ サービス正常: $($healthz | ConvertTo-Json -Compress)" -ForegroundColor Green
        $service_ok = $true
    }
    else {
        Write-Host "❌ サービス異常: $($healthz | ConvertTo-Json -Compress)" -ForegroundColor Red
        $service_ok = $false
    }
}
catch {
    Write-Host "❌ サービス接続失敗: $($_.Exception.Message)" -ForegroundColor Red
    $service_ok = $false
}

# 2. タスク稼働確認
Write-Host "`n2. タスク稼働確認..." -ForegroundColor Yellow
try {
    $tasks = Get-ScheduledTask gc-* | Get-ScheduledTaskInfo | Select-Object TaskName, NextRunTime, LastTaskResult
    Write-Host "スケジュールタスク状況:" -ForegroundColor Cyan
    $tasks | Format-Table -AutoSize
    
    $gc_intake = $tasks | Where-Object { $_.TaskName -eq "gc-intake-app" }
    $gc_data = $tasks | Where-Object { $_.TaskName -eq "gc-data-loop" }
    
    $intake_ok = $gc_intake -and $gc_intake.LastTaskResult -eq 0
    $data_ok = $gc_data -and $gc_data.LastTaskResult -eq 0
    
    Write-Host "gc-intake-app: $(if ($intake_ok) { 'OK' } else { 'NG' })" -ForegroundColor $(if ($intake_ok) { "Green" } else { "Red" })
    Write-Host "gc-data-loop: $(if ($data_ok) { 'OK' } else { 'NG' })" -ForegroundColor $(if ($data_ok) { "Green" } else { "Red" })
    
    $tasks_ok = $intake_ok -and $data_ok
}
catch {
    Write-Host "❌ タスク確認失敗: $($_.Exception.Message)" -ForegroundColor Red
    $tasks_ok = $false
}

# 3. データ状況確認
Write-Host "`n3. データ状況確認..." -ForegroundColor Yellow
$inbox_count = (Get-ChildItem "data\intake\inbox" -ErrorAction SilentlyContinue).Count
$accepted_count = (Get-ChildItem "data\intake\accepted" -ErrorAction SilentlyContinue).Count
$buckets_count = (Get-ChildItem "data\intake\buckets" -Recurse -File -ErrorAction SilentlyContinue).Count
$sft_count = (Get-ChildItem "data\sft" -ErrorAction SilentlyContinue).Count

Write-Host "inbox: $inbox_count 件" -ForegroundColor Cyan
Write-Host "accepted: $accepted_count 件" -ForegroundColor Cyan
Write-Host "buckets: $buckets_count 件" -ForegroundColor Cyan
Write-Host "sft: $sft_count 件" -ForegroundColor Cyan

# 4. ログ確認
Write-Host "`n4. ログ確認..." -ForegroundColor Yellow
$log_file = "$env:USERPROFILE\GoverningCore_v5_Slice\data\logs\current\gc-data-loop.log"
if (Test-Path $log_file) {
    Write-Host "gc-data-loopログ（最新30行）:" -ForegroundColor Cyan
    Get-Content $log_file -Tail 30
}
else {
    Write-Host "gc-data-loopログなし" -ForegroundColor Yellow
}

# 5. 総合判定
Write-Host "`n=== 健康監視結果 ===" -ForegroundColor Green
$overall_ok = $service_ok -and $tasks_ok
Write-Host "サービス: $(if ($service_ok) { 'OK' } else { 'NG' })" -ForegroundColor $(if ($service_ok) { "Green" } else { "Red" })
Write-Host "タスク: $(if ($tasks_ok) { 'OK' } else { 'NG' })" -ForegroundColor $(if ($tasks_ok) { "Green" } else { "Red" })

if ($overall_ok) {
    Write-Host "`n✅ システム正常稼働中" -ForegroundColor Green
    Write-Host "放っておいて育つ運用中！" -ForegroundColor Cyan
}
else {
    Write-Host "`n❌ システム異常検出" -ForegroundColor Red
    Write-Host "復旧手順を確認してください" -ForegroundColor Yellow
}

exit $(if ($overall_ok) { 0 } else { 1 })