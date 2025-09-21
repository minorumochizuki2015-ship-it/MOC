# 学習インテーク・アプリへの自動取り込みスクリプト
# エディタ（Cursor/Trae）から呼び出し用

param(
    [Parameter(Mandatory = $true)]
    [string]$Title,
    
    [Parameter(Mandatory = $true)]
    [string]$Prompt,
    
    [Parameter(Mandatory = $true)]
    [string]$Output,
    
    [string]$Source = "Trae",
    [string]$Domain = "auto",
    [string]$TaskType = "edit",
    [bool]$Success = $true,
    [string]$SuccessReason = "",
    [string]$FailureReason = "",
    [string]$UsedMethods = "",
    [string]$Refs = "",
    [string]$Privacy = "none",
    [string]$Tags = "auto-push"
)

$ErrorActionPreference = 'Stop'

# リポジトリルート
$repo = "$env:USERPROFILE\GoverningCore_v5_Slice"
$intakeUrl = "http://127.0.0.1:8787/intake/post?auto=1"  # 自動パイプライン有効

# リクエストボディ作成
$body = @{
    source            = $Source
    title             = $Title
    domain            = $Domain
    task_type         = $TaskType
    success           = $Success
    prompt            = $Prompt
    output            = $Output
    rationale_success = $SuccessReason
    rationale_failure = $FailureReason
    math_or_rules     = $UsedMethods
    refs              = if ($Refs) { $Refs.Split(',') | ForEach-Object { $_.Trim() } } else { @() }
    privacy           = $Privacy
    tags              = if ($Tags) { $Tags.Split(',') | ForEach-Object { $_.Trim() } } else { @() }
} | ConvertTo-Json -Depth 4

try {
    # HTTP Push
    $response = Invoke-RestMethod -Uri $intakeUrl -Method POST -ContentType "application/json; charset=utf-8" -Body $body -TimeoutSec 5
    
    Write-Host "✅ 取り込み成功: $($response.message)" -ForegroundColor Green
    Write-Host "   タイトル: $Title" -ForegroundColor Cyan
    Write-Host "   ドメイン: $Domain" -ForegroundColor Cyan
    Write-Host "   成功: $Success" -ForegroundColor Cyan
    
    return $true
}
catch {
    Write-Host "❌ 取り込み失敗: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   URL: $intakeUrl" -ForegroundColor Yellow
    Write-Host "   ボディ: $body" -ForegroundColor Yellow
    
    return $false
}
