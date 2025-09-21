param([switch]$Apply)
$ErrorActionPreference='Stop'
$py = ".\.venv\Scripts\python.exe"
$covXml = "observability/coverage/coverage.xml"
$cmd = "$py -m pytest -q --maxfail=1 --strict-markers -m `"not integration and not e2e and not slow`" --durations=10 --cov=src --cov-report=xml:$covXml"
"PLAN: $cmd"
if (-not $Apply) { exit 0 }
if (-not (Test-Path "observability/coverage")) { New-Item -ItemType Directory -Force "observability/coverage" | Out-Null }
iex $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "tests failed"; exit 1 }