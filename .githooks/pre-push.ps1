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
& $py -X utf8 -u tools/quick_diagnose.py
if ($LASTEXITCODE -eq 0) { exit 0 }
if ($LASTEXITCODE -eq 1) { Write-Error "Diagnosis WARNING: Fix before push"; exit 1 }

# mini eval（tools直呼び＋短Timeoutで高速回帰）
& $py -X utf8 -u tools/mini_eval.py --mode tools --timeout 12 --baseline data/outputs/mini_eval_baseline.json --out data/outputs/mini_eval.json
if ($LASTEXITCODE -ne 0) { Write-Error "Mini eval FAILED: Regression detected"; exit 1 }

# リモートAPI痕跡の静的検査
$bad = @(
    'api\.openai\.com', 'openai.azure\.com', 'anthropic\.com', 'cohere\.ai',
    'gemini\.googleapis\.com', 'vertexai', 'bedrock\.', 'huggingface\.co/api'
)
$files = git diff --cached --name-only
foreach ($f in $files) { 
    if (Test-Path $f) {
        $t = Get-Content -Raw -ErrorAction SilentlyContinue $f
        foreach ($p in $bad) { 
            if ($t -match $p) { 
                Write-Error "blocked: $f contains pattern $p"; exit 1 
            } 
        }
    }
}

Write-Error "Diagnosis ERROR: Dangerous configuration/implementation"; exit 2