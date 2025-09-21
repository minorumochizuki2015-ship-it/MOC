# 学習インテーク・アプリ即席スモークテスト
# POST & DROP の動作確認用

$ErrorActionPreference = 'Stop'

Write-Host "=== 即席スモークテスト ===" -ForegroundColor Green

# 1. HTTP Pushテスト
Write-Host "`n1. HTTP Pushテスト..." -ForegroundColor Yellow
try {
    $push_result = & "scripts\ops\cursor-integration.ps1" -Title "smoke" -Success $true -Prompt "p" -Output "o"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ HTTP Push成功" -ForegroundColor Green
        $push_ok = $true
    } else {
        Write-Host "❌ HTTP Push失敗" -ForegroundColor Red
        $push_ok = $false
    }
} catch {
    Write-Host "❌ HTTP Push失敗: $($_.Exception.Message)" -ForegroundColor Red
    $push_ok = $false
}

# 2. ファイルDROPテスト
Write-Host "`n2. ファイルDROPテスト..." -ForegroundColor Yellow
try {
    $drop_data = @'
{"source":"Trae","title":"drop-smoke","domain":"auto","task":"edit","success":true,"prompt":"p","output":"o","privacy":"none"}
'@
    $drop_file = "$env:USERPROFILE\GoverningCore_v5_Slice\data\intake\inbox\drop-smoke.json"
    $drop_data | Set-Content $drop_file -Encoding UTF8
    Write-Host "✅ ファイルDROP成功: $drop_file" -ForegroundColor Green
    $drop_ok = $true
} catch {
    Write-Host "❌ ファイルDROP失敗: $($_.Exception.Message)" -ForegroundColor Red
    $drop_ok = $false
}

# 3. 1分待機（自動処理確認）
Write-Host "`n3. 1分待機（自動処理確認）..." -ForegroundColor Yellow
Write-Host "自動処理を待機中..." -ForegroundColor Cyan
Start-Sleep -Seconds 60

# 4. 結果確認
Write-Host "`n4. 結果確認..." -ForegroundColor Yellow
$inbox_count = (Get-ChildItem "data\intake\inbox" -ErrorAction SilentlyContinue).Count
$accepted_count = (Get-ChildItem "data\intake\accepted" -ErrorAction SilentlyContinue).Count
$buckets_count = (Get-ChildItem "data\intake\buckets" -Recurse -File -ErrorAction SilentlyContinue).Count

Write-Host "inbox: $inbox_count 件" -ForegroundColor Cyan
Write-Host "accepted: $accepted_count 件" -ForegroundColor Cyan
Write-Host "buckets: $buckets_count 件" -ForegroundColor Cyan

$processing_ok = $accepted_count -gt 0 -or $buckets_count -gt 0

# 5. 総合判定
Write-Host "`n=== スモークテスト結果 ===" -ForegroundColor Green
Write-Host "HTTP Push: $(if ($push_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($push_ok) { "Green" } else { "Red" })
Write-Host "ファイルDROP: $(if ($drop_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($drop_ok) { "Green" } else { "Red" })
Write-Host "自動処理: $(if ($processing_ok) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($processing_ok) { "Green" } else { "Red" })

$overall_pass = $push_ok -and $drop_ok -and $processing_ok

Write-Host "`n総合結果: $(if ($overall_pass) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($overall_pass) { "Green" } else { "Red" })

if ($overall_pass) {
    Write-Host "`n✅ スモークテスト成功" -ForegroundColor Green
    Write-Host "システムは正常に動作しています" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ スモークテスト失敗" -ForegroundColor Red
    Write-Host "復旧手順を確認してください" -ForegroundColor Yellow
}

exit $(if ($overall_pass) { 0 } else { 1 })

