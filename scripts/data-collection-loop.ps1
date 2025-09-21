# Robust data-collection-loop (create log first, then cd)
$ErrorActionPreference = 'Stop'

# Paths (repo = .. from this script)
$here = Split-Path -Parent $PSCommandPath
$repo = (Resolve-Path (Join-Path $here '..')).Path

# Log first (even if cd fails)
$logDir = Join-Path $repo 'data\logs\current'
$log = Join-Path $logDir 'gc-data-loop.log'
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
"=== $(Get-Date -Format o) START ===" | Out-File -FilePath $log -Append -Encoding utf8

$exit = 1
try {
    Set-Location -LiteralPath $repo
    "repo=$repo" | Out-File $log -Append

    $py = Join-Path $repo '.venv\Scripts\python.exe'
    if (-not (Test-Path $py)) { throw "python not found: $py" }

    # 1) intake filter (inbox→queue/accepted/rejected)
    & "$py" -X utf8 -u tools\intake_filter.py --data-dir data\intake *>> $log
    $if_rc = $LASTEXITCODE; $if_ok = ($if_rc -eq 0)
    "intake_filter_ok=$if_ok rc=$if_rc" | Out-File $log -Append

    # 2) quick diagnose
    & "$py" -X utf8 -u tools\quick_diagnose.py *>> $log
    $qd_rc = $LASTEXITCODE; $qd_ok = ($qd_rc -eq 0)
    "qd_ok=$qd_ok rc=$qd_rc" | Out-File $log -Append

    # 3) mini eval (tools mode, short timeout)
    $mode = $env:MINI_EVAL_MODE; if (-not $mode) { $mode = 'tools' }
    $to = $env:MINI_EVAL_TIMEOUT; if (-not $to) { $to = 15 }
  
    # 直前に保存
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
  
    & "$py" -W ignore::SyntaxWarning -X utf8 -u tools\mini_eval.py --mode $mode --timeout $to --baseline data\outputs\mini_eval_baseline.json --out data\outputs\mini_eval.json *>> $log
  
    $me_rc = $LASTEXITCODE; $me_ok = ($me_rc -eq 0)
    "mini_eval_ok=$me_ok rc=$me_rc" | Out-File $log -Append
  
    # 元に戻す
    $ErrorActionPreference = $prevEAP

    # 4) files appear with slight delay under scheduler → retry
    $qd_path = Join-Path $repo 'data\outputs\quick_diagnose.json'
    $hist_path = Join-Path $repo 'data\logs\current\mini_eval_history.jsonl'
    $files_ok = $false
    foreach ($i in 1..10) {
        if ((Test-Path $qd_path) -and (Test-Path $hist_path)) { $files_ok = $true; break }
        Start-Sleep -Milliseconds 250
    }
    "files_ok=$files_ok qd=$(Test-Path $qd_path) hist=$(Test-Path $hist_path)" | Out-File $log -Append

    if ($if_ok -and $qd_ok -and $me_ok -and $files_ok) { $exit = 0 }
    elseif (-not $if_ok) { $exit = 8 }
    elseif (-not $qd_ok) { $exit = 10 }
    elseif (-not $me_ok) { $exit = 11 }
    else { $exit = 12 }
}
catch {
    "ERROR: $($_.Exception.Message)" | Out-File $log -Append
    $exit = 9
}
finally {
    "END exit=$exit" | Out-File $log -Append
    exit $exit
}