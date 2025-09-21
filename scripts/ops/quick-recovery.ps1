# 学習インテーク・アプリ速攻リカバリスクリプト
# 壊れた時の最短復旧用

$ErrorActionPreference = 'Stop'

Write-Host "=== 速攻リカバリ ===" -ForegroundColor Green

# 1. 外部鍵クリア
Write-Host "`n1. 外部鍵クリア..." -ForegroundColor Yellow
$api_keys = @("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_KEY", "GOOGLE_AI_KEY")
foreach ($key in $api_keys) {
    try {
        setx $key ""
        Write-Host "✅ $key クリア完了" -ForegroundColor Green
    } catch {
        Write-Host "❌ $key クリア失敗: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 2. タスク再開
Write-Host "`n2. タスク再開..." -ForegroundColor Yellow
try {
    SCHTASKS /Change /TN gc-data-loop /ENABLE
    Write-Host "✅ gc-data-loop 再開完了" -ForegroundColor Green
} catch {
    Write-Host "❌ gc-data-loop 再開失敗: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    SCHTASKS /Change /TN gc-intake-app /ENABLE
    Write-Host "✅ gc-intake-app 再開完了" -ForegroundColor Green
} catch {
    Write-Host "❌ gc-intake-app 再開失敗: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. アプリ再起動
Write-Host "`n3. アプリ再起動..." -ForegroundColor Yellow
try {
    $app_process = Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "scripts\ops\start-intake-app.ps1" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 5
    Write-Host "✅ アプリ再起動完了" -ForegroundColor Green
} catch {
    Write-Host "❌ アプリ再起動失敗: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. 健康確認
Write-Host "`n4. 健康確認..." -ForegroundColor Yellow
try {
    $healthz = Invoke-RestMethod http://127.0.0.1:8787/healthz -TimeoutSec 5
    if ($healthz.ok) {
        Write-Host "✅ サービス正常: $($healthz | ConvertTo-Json -Compress)" -ForegroundColor Green
        $service_ok = $true
    } else {
        Write-Host "❌ サービス異常: $($healthz | ConvertTo-Json -Compress)" -ForegroundColor Red
        $service_ok = $false
    }
} catch {
    Write-Host "❌ サービス接続失敗: $($_.Exception.Message)" -ForegroundColor Red
    $service_ok = $false
}

# 5. 結果判定
Write-Host "`n=== リカバリ結果 ===" -ForegroundColor Green
if ($service_ok) {
    Write-Host "✅ リカバリ成功" -ForegroundColor Green
    Write-Host "システムは正常に復旧しました" -ForegroundColor Cyan
} else {
    Write-Host "❌ リカバリ失敗" -ForegroundColor Red
    Write-Host "手動での確認が必要です" -ForegroundColor Yellow
}

exit $(if ($service_ok) { 0 } else { 1 })

