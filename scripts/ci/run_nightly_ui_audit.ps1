Param(
  [int] $Port = 5001,
  [string] $HostName = "127.0.0.1",
  [string] $OutDir = "artifacts/nightly-ui-audit"
)

$ErrorActionPreference = "Stop"

# Determine project root
$projRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $projRoot

# Allow env overrides
if ($env:NIGHTLY_UI_AUDIT_PORT) { $Port = [int]$env:NIGHTLY_UI_AUDIT_PORT }
if ($env:NIGHTLY_UI_AUDIT_HOST) { $HostName = $env:NIGHTLY_UI_AUDIT_HOST }
if ($env:NIGHTLY_UI_AUDIT_OUTDIR) { $OutDir = $env:NIGHTLY_UI_AUDIT_OUTDIR }

$opsScript = Join-Path $projRoot "scripts\ops\run_nightly_ui_audit.ps1"
Write-Host "[nightly-ui-audit] Invoking ops audit script: $opsScript -Port $Port -HostName $HostName -OutDir $OutDir" -ForegroundColor Cyan

$exitCode = 0
try {
  & $opsScript -Port $Port -HostName $HostName -OutDir $OutDir
  $exitCode = $LASTEXITCODE
} catch {
  Write-Error "[nightly-ui-audit] Ops audit failed: $($_.Exception.Message)"
  $exitCode = 1
}

exit $exitCode