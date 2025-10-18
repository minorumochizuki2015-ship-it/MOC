Param(
  [string]$PythonPath = "",
  [switch]$Upgrade = $true
)

function Get-Python {
  if ($PythonPath -and (Test-Path $PythonPath)) { return $PythonPath }
  if (Test-Path ".\.venv\Scripts\python.exe") { return ".\.venv\Scripts\python.exe" }
  return "python"
}

$py = Get-Python

if ($Upgrade) {
  & $py -m pip install --upgrade pip
}

Write-Host "[install_playwright] Installing Playwright (Python)..."
& $py -m pip install --upgrade playwright
if ($LASTEXITCODE -ne 0) {
  Write-Error "pip install playwright failed"
  exit 1
}

Write-Host "[install_playwright] Downloading browsers..."
& $py -m playwright install
if ($LASTEXITCODE -ne 0) {
  Write-Error "playwright install failed"
  exit 1
}

Write-Host "[install_playwright] Done: Playwright Python installed and browsers downloaded."