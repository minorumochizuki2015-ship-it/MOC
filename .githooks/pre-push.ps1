$ErrorActionPreference='Stop'
function Find-Python {
  $candidates = @(
    (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'),
    $env:PYTHON, 'py -3', 'python'
  ) | Where-Object { $_ -and $_ -ne '' }
  foreach ($p in $candidates) {
    try { & $p -V *> $null; return $p } catch {}
  }
  throw "Python not found."
}
$py = Find-Python
& $py -X utf8 -u tools/quick_diagnose.py
if ($LASTEXITCODE -eq 0) { exit 0 }
if ($LASTEXITCODE -eq 1) { Write-Error "Diagnosis WARNING: Fix before push"; exit 1 }
Write-Error "Diagnosis ERROR: Dangerous configuration/implementation"; exit 2