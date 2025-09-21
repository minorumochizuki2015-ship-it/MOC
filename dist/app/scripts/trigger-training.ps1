# Requires -Version 5.1
# Robust local trainer launcher (no pop-ups; strict quoting)

# 単一インスタンス実行
$mtx = New-Object System.Threading.Mutex($false,"GC_$($MyInvocation.MyCommand.Name)")
if (-not $mtx.WaitOne(0)) { exit 0 }

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

# workspace = repo root
$Root = Resolve-Path (Join-Path $PSScriptRoot '..') | Select-Object -Expand Path
Set-Location $Root

# external trainer entry (bat/ps1/py). prefer ENV, fallback to config path if any
$trainer = $env:LOCAL_LORA_TRAINER
if ([string]::IsNullOrWhiteSpace($trainer)) {
    $trainer = Join-Path $Root 'scripts\trainer\local_trainer.ps1'
}

if (-not (Test-Path $trainer)) {
    throw "LOCAL_LORA_TRAINER not found: $trainer"
}

# inputs
$plan = Join-Path $Root 'dist\lora\train_plan.json'
if (-not (Test-Path $plan)) { throw "train_plan.json not found: $plan" }

# logs
$logDir = Join-Path $Root 'data\logs\training'
New-Item -Force -ItemType Directory -Path $logDir | Out-Null
$status = Join-Path $logDir ('status_{0:yyyyMMdd_HHmmss}.json' -f (Get-Date))

# run
try {
    # the trainer script should read train_plan.json and produce lora artifacts under dist/lora/
    Write-Host "[trainer] $trainer"
    if ($trainer.ToLower().EndsWith('.ps1')) {
        powershell -ExecutionPolicy Bypass -File $trainer -Plan "$plan" -LogDir "$logDir"
    }
    elseif ($trainer.ToLower().EndsWith('.py')) {
        $py = Find-Python
        & $py -X utf8 -u $trainer --plan "$plan" --logdir "$logDir"
    }
    else {
        & $trainer "$plan" "$logDir"
    }

    $result = @{
        ts      = (Get-Date).ToString('o')
        ok      = $true
        trainer = $trainer
        plan    = (Resolve-Path $plan).Path
    }
    $result | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 $status
    Write-Host "[ok] training triggered. status: $status"
    exit 0
}
catch {
    $err = @{
        ts      = (Get-Date).ToString('o')
        ok      = $false
        trainer = $trainer
        error   = $_.Exception.Message
    }
    $err | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 $status
    Write-Error "[fail] training trigger error: $($_.Exception.Message)"
    exit 1
}