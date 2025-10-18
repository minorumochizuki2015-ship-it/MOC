param(
  [string]$At = '03:00',
  [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$repoRoot = Join-Path $PSScriptRoot '..\..'
$scriptPath = Join-Path $repoRoot 'scripts\power\learning\adjust_idle.py'

function Write-Log($msg) {
  $root = $repoRoot
  $dir = Join-Path $root 'artifacts\power'
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $path = Join-Path $dir 'learning_install.log'
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts] $msg"
  Add-Content -Path $path -Value $line -Encoding UTF8
  Write-Host $line
}

if (!(Test-Path $scriptPath)) { throw "学習器スクリプトが見つかりません: $scriptPath" }

# Python 実行ファイルの検出（優先: .venv → py → python）
$venvPy = Join-Path $repoRoot '.venv\Scripts\python.exe'
$pythonExe = $null
if (Test-Path $venvPy) {
  $pythonExe = $venvPy
  Write-Log "python: .venv を使用: $pythonExe"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
  $pythonExe = 'py'
  Write-Log 'python: py ランチャーを使用'
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $pythonExe = 'python'
  Write-Log 'python: python を使用'
} else {
  throw 'python が見つかりません。Python 3 の導入または .venv の作成が必要です。'
}

# タスク登録（条件/設定の強化）
$taskFolder = '\\ORCH-Next\\'
$taskName   = 'Learning_AdjustIdle_Daily'

# 厳密クォート（引数）
$quotedScript = '"' + $scriptPath + '"'
if ($pythonExe -eq 'py') {
  $program = 'py'
  $args    = '-3 ' + $quotedScript + ' --apply --rollback-on-fail'
} elseif ($pythonExe -eq 'python') {
  $program = 'python'
  $args    = $quotedScript + ' --apply --rollback-on-fail'
} else {
  $program = $pythonExe
  $args    = $quotedScript + ' --apply --rollback-on-fail'
}

# 03:00 などの文字列を DateTime に解釈
try {
  $time = [DateTime]::ParseExact($At, 'HH:mm', $null)
} catch {
  $parts = $At.Split(':')
  $h = [int]$parts[0]; $m = [int]$parts[1]
  $time = (Get-Date).Date.AddHours($h).AddMinutes($m)
}

$trigger  = New-ScheduledTaskTrigger -Daily -At $time
$trigger.Delay = (New-TimeSpan -Minutes 1) # 開始遅延 1 分

$settings = New-ScheduledTaskSettingsSet \
  -DisallowStartIfOnBatteries $true \
  -StopIfGoingOnBatteries $true \
  -RunOnlyIfNetworkAvailable $false \
  -ExecutionTimeLimit (New-TimeSpan -Minutes 5) \
  -RestartCount 3 \
  -RestartInterval (New-TimeSpan -Minutes 5)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$action    = New-ScheduledTaskAction -Execute $program -Argument $args -WorkingDirectory $repoRoot

Write-Log "登録計画: Folder=$taskFolder Name=$taskName Program=$program Args=$args At=$At (Delay=1m, Max=5m, Retry=3x/5m, ACのみ)"
if ($Apply) {
  try {
    Register-ScheduledTask -TaskName $taskName -TaskPath $taskFolder -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Log '完了: 日次タスク登録 (条件/設定 反映)'
  } catch {
    Write-Log "ERROR: タスク登録に失敗しました: $($_.Exception.Message)"
    throw
  }
} else {
  Write-Log 'Dry-Run: /Apply を付けると登録実行します（管理者権限推奨）'
}