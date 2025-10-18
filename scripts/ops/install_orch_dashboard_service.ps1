param(
  [string]$ServiceName = "ORCHNextDashboard",
  [string]$Port = "5000",
  [switch]$Uninstall
)

function Require-Admin {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "このスクリプトは管理者権限で実行してください (PowerShell を右クリック→管理者として実行)。" -ErrorAction Stop
  }
}

Require-Admin

$ScriptsDir = $PSScriptRoot
$RepoRoot = (Get-Item $ScriptsDir).Parent.Parent.FullName
$NSSM = Join-Path $RepoRoot "nssm\nssm-2.24\win64\nssm.exe"
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$AppDir = $RepoRoot
$LogsDir = Join-Path $RepoRoot "logs\service"

if (!(Test-Path $NSSM)) {
  Write-Error "NSSM が見つかりません: $NSSM" -ErrorAction Stop
}
if (!(Test-Path $Python)) {
  Write-Error "Python 実行ファイルが見つかりません: $Python (仮想環境が存在するか確認してください)" -ErrorAction Stop
}

if ($Uninstall) {
  try { & $NSSM stop $ServiceName } catch {}
  try { & $NSSM remove $ServiceName confirm } catch {}
  Write-Host "サービス $ServiceName を削除しました。"
  exit 0
}

New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

# 1) サービス登録
& $NSSM install $ServiceName $Python "-m" "src.dashboard"

# 2) 設定
& $NSSM set $ServiceName AppDirectory $AppDir
$envExtra = "ORCH_PORT=$Port`r`nORCH_USE_WERKZEUG=0"
& $NSSM set $ServiceName AppEnvironmentExtra $envExtra
& $NSSM set $ServiceName Start SERVICE_AUTO_START
& $NSSM set $ServiceName AppStdout (Join-Path $LogsDir "dashboard.out.log")
& $NSSM set $ServiceName AppStderr (Join-Path $LogsDir "dashboard.err.log")
& $NSSM set $ServiceName Description "ORCH Next Quality Dashboard (Waitress)"

# 3) 起動
& $NSSM start $ServiceName

Write-Host "サービス $ServiceName を起動しました。" -ForegroundColor Green
Write-Host "検証コマンド:" -ForegroundColor Cyan
Write-Host "  curl -I http://localhost:$Port/healthz" -ForegroundColor Yellow
Write-Host "  curl -i -X OPTIONS http://localhost:$Port/preview" -ForegroundColor Yellow
Write-Host "Server ヘッダが 'waitress'、プリフライトに 'Access-Control-Max-Age: 600' が含まれることを確認してください。"