# エディタ自動ポスト用スクリプト
# Cursor/Trae 共通で使用

param(
    [Parameter(Mandatory = $true)]
    [string]$Title,
    
    [Parameter(Mandatory = $true)]
    [string]$Prompt,
    
    [Parameter(Mandatory = $true)]
    [string]$Output,
    
    [string]$Source = "Cursor",
    [string]$Domain = "code",
    [string]$TaskType = "edit",
    [bool]$Success = $true,
    [string]$SuccessReasons = "",
    [string]$FailureReasons = "",
    [string]$UsedMethods = "",
    [string]$References = "",
    [string]$PrivacyLevel = "none",
    [string]$Tags = "auto"
)

$ErrorActionPreference = 'Stop'

Write-Host "=== エディタ自動ポスト ===" -ForegroundColor Green

# リクエストボディ作成
$body = @{
    source          = $Source
    title           = $Title
    domain          = $Domain
    task_type       = $TaskType
    prompt          = $Prompt
    output          = $Output
    success         = $Success
    success_reasons = $SuccessReasons
    failure_reasons = $FailureReasons
    used_methods    = $UsedMethods
    references      = $References
    privacy_level   = $PrivacyLevel
    tags            = $Tags
} | ConvertTo-Json -Depth 6

Write-Host "送信データ:" -ForegroundColor Cyan
Write-Host $body -ForegroundColor White

try {
    # 自動パイプライン有効でPOST
    $response = Invoke-RestMethod "http://127.0.0.1:8787/intake/post?auto=1" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
    
    Write-Host "✅ 自動ポスト成功: $($response | ConvertTo-Json -Compress)" -ForegroundColor Green
    Write-Host "   タイトル: $Title" -ForegroundColor Cyan
    Write-Host "   ドメイン: $Domain" -ForegroundColor Cyan
    Write-Host "   成功: $Success" -ForegroundColor Cyan
    Write-Host "   自動パイプライン: 有効" -ForegroundColor Cyan
    
    return $true
}
catch {
    Write-Host "❌ 自動ポスト失敗: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   URL: http://127.0.0.1:8787/intake/post?auto=1" -ForegroundColor Yellow
    Write-Host "   ボディ: $body" -ForegroundColor Yellow
    
    return $false
}

