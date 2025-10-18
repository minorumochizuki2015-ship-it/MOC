# ORCH-Next Dashboard Watchdog
# 目的: Flask開発サーバーが終了した/クラッシュした場合に自動で再起動し、安定稼働を補助する
# 実行方法: PowerShellから `pwsh -File scripts/ops/run_dashboard_watchdog.ps1` を実行
# 端末を閉じると停止します。バックグラウンド常駐が必要な場合はタスクスケジューラへ登録してください。

$ErrorActionPreference = 'Stop'

# プロジェクトルート
$root = "C:\Users\User\Trae\ORCH-Next"
Set-Location $root

# ログ保存先（プロジェクト規約: data\logs\current\）
$logDir = Join-Path $root "data\logs\current"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir ("dashboard_watchdog_" + (Get-Date -Format 'yyyyMMdd') + ".log")

function Write-Log([string]$msg) {
  $ts = Get-Date -Format 'o'
  $line = "$ts `t $msg"
  $line | Tee-Object -FilePath $logFile -Append
}

function Start-Dashboard {
  param(
    [int]$Port = 5000
  )
  $env:ORCH_PORT = "$Port"
  Write-Log "Starting dashboard (port=$Port)"
  $proc = Start-Process -FilePath "python" -ArgumentList "-m src.dashboard" -WorkingDirectory $root -PassThru -WindowStyle Hidden
  Write-Log "Started PID=$($proc.Id)"
  return $proc
}

function Test-Port([int]$Port) {
  try {
    $res = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue
    return ($res.TcpTestSucceeded -eq $true)
  } catch { return $false }
}

# 連続監視ループ
$restartDelaySec = 2
$preferredPort = 5000

while ($true) {
  try {
    $proc = Start-Dashboard -Port $preferredPort
    # 実行中は待機（終了したら抜ける）
    Wait-Process -Id $proc.Id
    Write-Log "Process exited (PID=$($proc.Id))"
  } catch {
    Write-Log "Start/Wait error: $($_.Exception.Message)"
  }
  # すぐに再起動（待機時間を調整可）
  Start-Sleep -Seconds $restartDelaySec
  # 健全性チェック（ポートが開いていない場合はログ）
  if (-not (Test-Port -Port $preferredPort)) {
    Write-Log "HealthCheck: port $preferredPort not listening; restarting"
  } else {
    Write-Log "HealthCheck: port $preferredPort listening"
  }
}
