param(
    [string]$ProjectRoot = "C:\Users\User\Trae\ORCH-Next"
)

try {
    Set-Location -Path $ProjectRoot
} catch {
    Write-Error "Failed to Set-Location to $ProjectRoot: $_"
}

# Python 実行（環境に依存せず system python を試行）。必要なら .venv を指定してください。
$python = "python"
$scriptPath = Join-Path $ProjectRoot "scripts\add_recent_quality_metric.py"
$logDir = Join-Path "C:\Users\User\Trae\LOGS" "longrun"
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = Join-Path $logDir "add_metric_schedule.log"

Write-Output ("[{0}] Start add_recent_quality_metric" -f (Get-Date).ToString("s")) | Out-File -FilePath $logFile -Append -Encoding UTF8

try {
    & $python -u $scriptPath *>> $logFile
    Write-Output ("[{0}] Completed add_recent_quality_metric" -f (Get-Date).ToString("s")) | Out-File -FilePath $logFile -Append -Encoding UTF8
} catch {
    Write-Output ("[{0}] Error: {1}" -f (Get-Date).ToString("s"), $_) | Out-File -FilePath $logFile -Append -Encoding UTF8
    exit 1
}