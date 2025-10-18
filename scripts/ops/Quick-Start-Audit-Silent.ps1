<#
Quick-Start-Audit-Silent.ps1
目的: リポジトリ内の audit_endpoints.py をサイレント（非対話）で実行し、結果をログに記録します。

使用例:
  pwsh -ExecutionPolicy Bypass -File ./scripts/ops/Quick-Start-Audit-Silent.ps1 -Silent
  pwsh -ExecutionPolicy Bypass -File ./scripts/ops/Quick-Start-Audit-Silent.ps1 -BaseUrl "http://localhost:5001" -DataDir "data" -LogPath "data/logs/current/audit_quickstart.log"

注意:
  - PowerShell 7+ を推奨
  - .venv\Scripts\python.exe が存在しない場合は、システムの python を試行します
#>

param(
  [string]$DataDir = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data'),
  [string]$BaseUrl = 'http://127.0.0.1:5001',
  [string]$LogPath,
  [switch]$Silent
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
  )
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts][$Level] $Message"
  if (-not $Silent) { Write-Host $line }
  if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line }
}

try {
  # ルート解決
  $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

  # ログファイル初期化
  if (-not $LogPath -or [string]::IsNullOrWhiteSpace($LogPath)) {
    $logDir = Join-Path $repoRoot 'data/logs/current'
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    $script:LogFile = Join-Path $logDir ("audit_quickstart_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".log")
  } else {
    $logDir = Split-Path -Parent $LogPath
    if ($logDir) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $script:LogFile = $LogPath
  }
  Write-Log "Quick-Start Audit 開始" 'INFO'

  # 環境設定
  $env:PYTHONPATH = $repoRoot
  $env:ORCH_BASE_URL = $BaseUrl
  $env:ORCH_DATA_DIR = $DataDir

  # ベースラインディレクトリの作成（存在しない場合）
  $baselineRoot = Join-Path $repoRoot 'data/baseline'
  foreach ($d in @($baselineRoot, (Join-Path $baselineRoot 'milestones'), (Join-Path $baselineRoot 'tasks'), (Join-Path $baselineRoot 'metrics'))) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
  }

  # Python 実行ファイルの探索
  $pythonCandidates = @(
    (Join-Path $repoRoot '.venv/Scripts/python.exe'),
    'python.exe',
    'py.exe'
  )
  $pythonExe = $null
  foreach ($c in $pythonCandidates) { if (Get-Command $c -ErrorAction SilentlyContinue) { $pythonExe = $c; break } }
  if (-not $pythonExe) { throw 'Python 実行ファイルが見つかりません (.venv/Systems/python.exe もしくはシステム python)' }

  # スクリプトパス
  $auditScript = Join-Path $repoRoot 'src/audit_endpoints.py'
  if (-not (Test-Path $auditScript)) { throw "監査スクリプトが見つかりません: $auditScript" }

  Write-Log "使用Python: $pythonExe" 'DEBUG'
  Write-Log "監査スクリプト: $auditScript" 'DEBUG'
  Write-Log "BaseUrl: $BaseUrl / DataDir: $DataDir" 'DEBUG'

  # 実行（非対話）
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $pythonExe
  $psi.Arguments = "`"$auditScript`""
  $psi.WorkingDirectory = $repoRoot
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true

  $proc = [System.Diagnostics.Process]::Start($psi)
  $stdout = $proc.StandardOutput.ReadToEnd()
  $stderr = $proc.StandardError.ReadToEnd()
  $proc.WaitForExit()

  if ($stdout) { Write-Log $stdout 'INFO' }
  if ($stderr) { Write-Log $stderr 'ERROR' }

  Write-Log "監査完了: ExitCode=$($proc.ExitCode)" 'INFO'

  if ($proc.ExitCode -eq 0) {
    Write-Log '成功終了' 'INFO'
    exit 0
  } else {
    Write-Log '失敗終了' 'ERROR'
    exit $proc.ExitCode
  }
} catch {
  Write-Log ("エラー: " + $_.Exception.Message) 'ERROR'
  exit 1
}