Param(
  [ValidateSet('ensure','create','enable','disable','show','remove')]
  [string]$Action = 'ensure',
  [string]$DisplayName = 'ORCH-Next Dev 5010 Inbound',
  [int]$Port = 5010,
  [string]$Profile = 'Private',
  [string]$RemoteAddress = 'LocalSubnet'
)

$ErrorActionPreference = 'Stop'

function Get-Rule { Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue }

if ($Action -in @('ensure','create')) {
  if (-not (Get-Rule)) {
    New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile $Profile -RemoteAddress $RemoteAddress -Enabled False | Out-Null
    Write-Host "[FW] Created rule '$DisplayName' (Port=$Port, Profile=$Profile, Remote=$RemoteAddress, Enabled=False)"
  } else { Write-Host "[FW] Rule '$DisplayName' already exists" }
  if ($Action -eq 'create') { return }
}

switch ($Action) {
  'enable'  { Set-NetFirewallRule -DisplayName $DisplayName -Enabled True ; Write-Host "[FW] Enabled '$DisplayName'" }
  'disable' { Set-NetFirewallRule -DisplayName $DisplayName -Enabled False ; Write-Host "[FW] Disabled '$DisplayName' (default)" }
  'show'    { $r = Get-Rule; if ($r){ $r | Get-NetFirewallPortFilter | Format-List | Out-String | Write-Host } else { Write-Warning "[FW] Rule not found: $DisplayName" } }
  'remove'  { if (Get-Rule) { Remove-NetFirewallRule -DisplayName $DisplayName ; Write-Host "[FW] Removed '$DisplayName'" } else { Write-Host "[FW] Skip remove: rule not found" } }
}

Write-Host "[FW] Done ($Action)"