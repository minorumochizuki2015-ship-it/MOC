$ErrorActionPreference = 'Stop'
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
Write-Host "Nightly evaluation: agent mode with 45s timeout"

# nightly用の重い評価（agent経由・45秒タイムアウト）
& $py -X utf8 -u tools/mini_eval.py --mode agent --timeout 45 --baseline data/outputs/mini_eval_baseline.json --out data/outputs/mini_eval_nightly.json

if ($LASTEXITCODE -ne 0) { 
    Write-Warning "Nightly eval FAILED: Regression detected in agent mode"
    exit 1 
}

Write-Host "Nightly evaluation: PASSED"
exit 0
