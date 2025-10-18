Param(
  [int]$Port = 5001,
  [switch]$ForceGuard = $true,
  [string]$PythonPath = "",
  [string]$BindHost = "127.0.0.1"
)

# Ensure CWD is project root (ORCH-Next) to resolve imports like 'src.dashboard'
try {
  $projectRoot = Join-Path $PSScriptRoot "..\.."
  Set-Location $projectRoot
  Write-Host "[start_ui_server] Set-Location to $projectRoot"
} catch {
  Write-Warning "[start_ui_server] Failed to Set-Location; continuing in current directory"
}

# Optional: add project root to PYTHONPATH for safety when executed from different shells
try {
  $env:PYTHONPATH = "$projectRoot;$($env:PYTHONPATH)"
  Write-Host "[start_ui_server] PYTHONPATH=$($env:PYTHONPATH)"
} catch {}

function Get-Python {
  if ($PythonPath -and (Test-Path $PythonPath)) { return $PythonPath }
  if (Test-Path ".\.venv\Scripts\python.exe") { return ".\.venv\Scripts\python.exe" }
  return "python"
}

# Port guard (default ON or when CI=true)
if ($ForceGuard -or $env:CI -eq "true") {
  Write-Host "[start_ui_server] Guard active: attempting to free port $Port"
  try {
    $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
      try {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "[start_ui_server] Stopped process $($c.OwningProcess) on port $Port"
      } catch {}
    }
  } catch {}
}

$env:FLASK_APP = "src.dashboard"
Write-Host "[start_ui_server] FLASK_APP=$($env:FLASK_APP)"

$py = Get-Python

# Show registered routes for verification
Write-Host "[start_ui_server] Listing routes..."
& $py -m flask --app $env:FLASK_APP routes | Out-Host

Write-Host "[start_ui_server] Starting Flask on port $Port (host=$BindHost)"
# propagate to runtime
$env:ORCH_PORT = "$Port"
$env:ORCH_HOST = $BindHost
& $py -m flask run --port $Port --host $env:ORCH_HOST