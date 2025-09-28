param([switch]$Apply)

# Basic setup
$logDir = "data/logs/current"
if (-not (Test-Path $logDir)) { 
    New-Item -ItemType Directory -Force $logDir | Out-Null 
}

$log = Join-Path $logDir ("trae_metrics_simple_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Write-Host "RUN: simple metrics test"
"RUN: simple metrics test" | Out-File -FilePath $log -Append

# Initialize metrics
$metricsAccepted = 3
$metricsDup = 1
$metricsErrors = 0

# Calculate SFT file size
$sft = "data\sft\train.jsonl"
if (Test-Path $sft) {
    $trainMB = [math]::Round((Get-Item $sft).Length / 1MB, 2)
    $trainLines = (Get-Content $sft | Measure-Object).Count
} else {
    $trainMB = 0
    $trainLines = 0
}

# Record metrics
$metricsFile = "data\logs\current\metrics.tsv"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Create header if first time
if (-not (Test-Path $metricsFile)) {
    $header = "ts`taccepted`tdup`terrors`ttrain_mb`tlines"
    $header | Out-File -FilePath $metricsFile -Encoding utf8
    Write-Host "METRICS: created header in $metricsFile"
    "METRICS: created header in $metricsFile" | Out-File -FilePath $log -Append
}

# Append metrics line
$metricsLine = "$timestamp`t$metricsAccepted`t$metricsDup`t$metricsErrors`t$trainMB`t$trainLines"
$metricsLine | Out-File -FilePath $metricsFile -Append -Encoding utf8

$message = "METRICS: accepted=$metricsAccepted, dup=$metricsDup, errors=$metricsErrors, train_mb=$trainMB, lines=$trainLines"
Write-Host $message
$message | Out-File -FilePath $log -Append

Write-Host "OK: metrics recorded to $metricsFile"
"OK: metrics recorded to $metricsFile" | Out-File -FilePath $log -Append