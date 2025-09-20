# 週次回帰メトリクスレポート
param(
    [int]$Days = 7
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "📊 週次回帰メトリクスレポート (過去${Days}日)" -ForegroundColor Cyan

$historyFile = "data\logs\current\mini_eval_history.jsonl"
if (-not (Test-Path $historyFile)) {
    Write-Error "History file not found: $historyFile"
    exit 1
}

# 履歴データ読み込み
$history = Get-Content $historyFile | ForEach-Object { $_ | ConvertFrom-Json }

# 過去N日間のデータフィルタ
$cutoffDate = (Get-Date).AddDays(-$Days)
$recentHistory = $history | Where-Object { 
    try {
        $timestamp = if ($_.timestamp -match '^\d+$') { 
            [DateTimeOffset]::FromUnixTimeSeconds([int]$_.timestamp).DateTime 
        } else { 
            [DateTime]::Parse($_.timestamp) 
        }
        $timestamp -gt $cutoffDate 
    } catch {
        $false
    }
}

if ($recentHistory.Count -eq 0) {
    Write-Host "No data found in the last $Days days" -ForegroundColor Yellow
    exit 0
}

# メトリクス計算
$scores = $recentHistory | ForEach-Object { $_.score }
$latencies = $recentHistory | ForEach-Object { $_.elapsed_ms }
$successRates = $recentHistory | ForEach-Object { $_.success }

$avgScore = ($scores | Measure-Object -Average).Average
$maxScore = ($scores | Measure-Object -Maximum).Maximum
$minScore = ($scores | Measure-Object -Minimum).Minimum

$avgLatency = ($latencies | Measure-Object -Average).Average
$p95Latency = ($latencies | Sort-Object | Select-Object -Skip ([math]::Floor($latencies.Count * 0.05)) | Select-Object -First 1)

$successRate = ($successRates | Where-Object { $_ -eq $true }).Count / $successRates.Count * 100

# レポート出力
Write-Host "`n📈 パフォーマンス指標:" -ForegroundColor Yellow
Write-Host "  平均スコア: $([math]::Round($avgScore, 2))" -ForegroundColor White
Write-Host "  最高スコア: $maxScore" -ForegroundColor White
Write-Host "  最低スコア: $minScore" -ForegroundColor White

Write-Host "`n⏱️ レイテンシ指標:" -ForegroundColor Yellow
Write-Host "  平均レイテンシ: $([math]::Round($avgLatency, 0))ms" -ForegroundColor White
Write-Host "  95%点レイテンシ: $($p95Latency)ms" -ForegroundColor White

Write-Host "`n✅ 成功率:" -ForegroundColor Yellow
Write-Host "  成功率: $([math]::Round($successRate, 1))%" -ForegroundColor White

# トレンド分析
$trend = if ($avgScore -gt 4.5) { "良好" } elseif ($avgScore -gt 3.5) { "普通" } else { "要改善" }
Write-Host "`n📊 トレンド: $trend" -ForegroundColor $(if ($trend -eq "良好") { "Green" } elseif ($trend -eq "普通") { "Yellow" } else { "Red" })

# 推奨アクション
if ($successRate -lt 90) {
    Write-Host "`n⚠️ 推奨アクション: 成功率が90%未満です。ロールバックを検討してください。" -ForegroundColor Red
} elseif ($avgLatency -gt 60000) {
    Write-Host "`n⚠️ 推奨アクション: 平均レイテンシが60秒を超えています。パフォーマンス改善が必要です。" -ForegroundColor Yellow
} else {
    Write-Host "`n✅ システムは正常に動作しています。" -ForegroundColor Green
}

Write-Host "`n📋 詳細データ: $($recentHistory.Count)件の評価結果" -ForegroundColor Cyan
