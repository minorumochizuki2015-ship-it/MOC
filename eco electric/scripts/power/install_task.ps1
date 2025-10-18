<#
 Auto Power Profile — Scheduled Task Installer
 目的: ユーザーログオン時に auto_power_profile.ps1 を自動起動するタスクを登録
 依存: PowerShell 7+ 推奨。スクリプトはリポジトリ相対パスで起動されます。
#>

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $repoRoot 'scripts\power\auto_power_profile.ps1'

if (!(Test-Path $scriptPath)) { throw "スクリプトが見つかりません: $scriptPath" }

$taskName = 'AutoPowerProfile'
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$principal= New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel LeastPrivilege

$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal

try {
  Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
  Write-Host "Scheduled Task 登録完了: $taskName"
} catch {
  throw "Scheduled Task の登録に失敗しました: $($_.Exception.Message)"
}