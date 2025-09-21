# 学習インテーク・アプリへのファイルDROP自動取り込みスクリプト
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
    [string]$Tags = "auto-drop"
)

$ErrorActionPreference = 'Stop'

# リポジトリルート
$repo = "$env:USERPROFILE\GoverningCore_v5_Slice"
$inboxDir = "$repo\data\intake\inbox"

# インボックスディレクトリ作成
if (-not (Test-Path $inboxDir)) {
    New-Item -Path $inboxDir -ItemType Directory -Force | Out-Null
}

# ファイル名生成（タイムスタンプ付き）
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$safeTitle = $Title -replace '[<>:"/\\|?*]', '_'
$filename = "$timestamp-$safeTitle.json"
$filepath = Join-Path $inboxDir $filename

# JSONデータ作成
$data = @{
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
    timestamp         = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
}

try {
    # JSONファイル保存
    $data | ConvertTo-Json -Depth 4 | Out-File -FilePath $filepath -Encoding UTF8
    
    Write-Host "✅ ファイルDROP成功: $filename" -ForegroundColor Green
    Write-Host "   パス: $filepath" -ForegroundColor Cyan
    Write-Host "   タイトル: $Title" -ForegroundColor Cyan
    Write-Host "   ドメイン: $Domain" -ForegroundColor Cyan
    Write-Host "   成功: $Success" -ForegroundColor Cyan
    Write-Host "   (gc-data-loopが1分以内に自動処理します)" -ForegroundColor Yellow
    
    return $true
}
catch {
    Write-Host "❌ ファイルDROP失敗: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   パス: $filepath" -ForegroundColor Yellow
    
    return $false
}

