# Nightly regression (agent mode). Fails build if score < 5.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-Python {
  $candidates = @(
    (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'),
    $env:PYTHON, 'py -3', 'python'
  ) | Where-Object { $_ -and $_ -ne '' }
  foreach ($p in $candidates) { try { & $p -V *> $null; return $p } catch {} }
  throw "Python not found."
}

# repo root (hooks run from .git/hooks usually)
$Root = Resolve-Path (Join-Path $PSScriptRoot '..') | Select-Object -Expand Path
Set-Location $Root

$py = Find-Python
$out = Join-Path $Root 'data\outputs\nightly_mini_eval.json'

# longer timeout + agent mode (heavy)
$env:MINI_EVAL_MODE = 'agent'
$env:MINI_EVAL_TIMEOUT = '45'

& $py -X utf8 -u tools\mini_eval.py --mode agent --timeout 45 --baseline data\outputs\mini_eval_baseline.json --out $out
if ($LASTEXITCODE -ne 0) {
  Write-Error "mini_eval.py exited with $LASTEXITCODE"
  exit $LASTEXITCODE
}

# robust JSON parse
if (-not (Test-Path $out)) { Write-Error "Result JSON missing: $out"; exit 2 }
try {
  $json = Get-Content -Raw -Encoding UTF8 $out | ConvertFrom-Json
  $scoreStr = $json.score
  if ($scoreStr -match '(\d+)/\d+') {
    $score = [int]$matches[1]
  } else {
    $score = [int]$scoreStr
  }
}
catch {
  Write-Error "Failed to parse score from $out`: $($_.Exception.Message)"
  exit 3
}

Write-Host "nightly score: $score / 5"
if ($score -lt 5) {
  Write-Error "Nightly regression (score < 5)."
  exit 4
}

# append to history
$hist = Join-Path $Root 'data\logs\current\mini_eval_history.jsonl'
New-Item -Force -ItemType Directory -Path (Split-Path $hist) | Out-Null
("{0}`t{1}" -f (Get-Date).ToString('o'), ($json | ConvertTo-Json -Depth 6)) | Out-File -Append -Encoding utf8 $hist

exit 0