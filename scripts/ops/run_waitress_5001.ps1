Param(
  [int]$Port = 5001,
  [string]$BindHost = "127.0.0.1",
  [string]$McpToken = $env:ORCH_MCP_TOKEN,
  [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"

# Resolve project root
try {
  $projectRoot = Join-Path $PSScriptRoot "..\.."
  Set-Location $projectRoot
  Write-Host "[run_waitress_5001] CWD=$projectRoot"
} catch {
  Write-Warning "[run_waitress_5001] Failed to Set-Location; continuing"
}

function Get-Python {
  if ($PythonPath -and (Test-Path $PythonPath)) { return $PythonPath }
  if (Test-Path ".\.venv\Scripts\python.exe") { return ".\.venv\Scripts\python.exe" }
  return "python"
}

# Ensure log dir exists
$logDir = Join-Path $projectRoot "data\logs\current"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# Daily-rotated filenames (fallback when NSSM unavailable)
$date = Get-Date -Format "yyyyMMdd"
$stdoutPath = Join-Path $logDir ("service_stdout_" + $date + ".log")
$stderrPath = Join-Path $logDir ("service_stderr_" + $date + ".log")

# Propagate environment for Waitress + MCP protection
$env:ORCH_HOST = $BindHost
$env:ORCH_PORT = "$Port"
if (-not $McpToken -or $McpToken.Trim().Length -eq 0) {
  Write-Warning "[run_waitress_5001] ORCH_MCP_TOKEN が未設定です。MCP保護なし（devモード）で起動します。必要に応じて -McpToken または環境変数 ORCH_MCP_TOKEN を設定してください。"
  Write-Host "[run_waitress_5001] ORCH_HOST=$BindHost ORCH_PORT=$Port ORCH_MCP_TOKEN=(unset)"
} else {
  $env:ORCH_MCP_TOKEN = $McpToken
  Write-Host "[run_waitress_5001] ORCH_HOST=$BindHost ORCH_PORT=$Port ORCH_MCP_TOKEN=(set)"
}

<# Port guard: try to free port proactively #>
try {
  $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
  foreach ($c in $conns) {
    try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
  }
} catch {}

$py = Get-Python
$entry = Join-Path $projectRoot "scripts\ops\waitress_entry.py"

Write-Host "[run_waitress_5001] Starting: $py $entry"

# Start Waitress with redirection; this is a console fallback emulating NSSM logging
Start-Process -FilePath $py -ArgumentList $entry -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
Write-Host "[run_waitress_5001] Logs: `n  stdout: $stdoutPath`n  stderr: $stderrPath" -ForegroundColor Cyan
Write-Host "[run_waitress_5001] Note: logs rotate daily by filename; NSSM rotation by size/count will apply when service mode is enabled."