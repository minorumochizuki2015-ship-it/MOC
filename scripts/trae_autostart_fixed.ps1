param([switch]$Apply)
$ErrorActionPreference = 'Stop'

# === Paths ===
$lockPath   = "data/locks/autopatch.lock"
$backoff    = "data/locks/autopatch.backoff"
$logDir     = "data/logs/current"
$sftDir     = "data/sft"
$trainPath  = Join-Path $sftDir "train.jsonl"
$accDir     = "data/intake/accepted"
$procDir    = "data/intake/processed"
$errDir     = "data/intake/errors"
$seenPath   = "data/intake/.seen"
$log        = Join-Path $logDir ("trae_autostart_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# === Utils ===
function Write-Log([string]$msg) {
  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force $logDir | Out-Null }
  $msg | Tee-Object -FilePath $log -Append
}
function Ensure-Dirs {
  foreach($d in @($logDir,$sftDir,$accDir,$procDir,$errDir,(Split-Path $lockPath))) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null }
  }
}
function Acquire-Lock([int]$ttlMin=30) {
  if (Test-Path $lockPath) {
    $ageMin = ((Get-Date) - (Get-Item $lockPath).LastWriteTime).TotalMinutes
    if ($ageMin -lt $ttlMin) { return $false }
    Remove-Item $lockPath -Force -ErrorAction SilentlyContinue
  }
  New-Item -ItemType File -Path $lockPath -Force | Out-Null
  return $true
}
function Release-Lock { Remove-Item $lockPath -Force -ErrorAction SilentlyContinue }

function Should-Backoff([ref]$waitSec) {
  $waitSec.Value = 0
  if (-not (Test-Path $backoff)) { return $false }
  $parts = (Get-Content $backoff -Raw) -split '\|'
  if ($parts.Count -lt 2) { return $false }
  $ts   = [datetime]::Parse($parts[0])
  $n    = [int]$parts[1]
  $delay = [int](60 * [math]::Pow(2, [math]::Min(3,$n)))  # 60s→120→240→480
  $until = $ts.AddSeconds($delay)
  if ((Get-Date) -lt $until) { $waitSec.Value = ($until - (Get-Date)).TotalSeconds; return $true }
  return $false
}
function Bump-Backoff {
  $n = 0
  if (Test-Path $backoff) { $p=(Get-Content $backoff -Raw) -split '\|'; if ($p.Count -ge 2) { $n=[int]$p[1] } }
  ("{0}|{1}" -f ((Get-Date).ToUniversalTime().ToString("u").Trim()), ($n+1)) | Set-Content $backoff -Encoding utf8
}
function Reset-Backoff { Remove-Item $backoff -Force -ErrorAction SilentlyContinue }

function Invoke-Tests([switch]$Apply) {
  $py = ".\.venv\Scripts\python.exe"
  $cmd = "$py -m pytest -q --maxfail=1 --strict-markers --durations=10"
  Write-Log "TEST: $cmd"
  if (-not $Apply) { Write-Log "PLAN: skip tests (dry-run)"; return $true }
  & $py -m pytest -q --maxfail=1 --strict-markers --durations=10
  if ($LASTEXITCODE -ne 0) { Write-Log "TEST: failed ($LASTEXITCODE)"; return $false }
  Write-Log "TEST: ok"
  return $true
}
function Get-ContentHash([string]$instr,[string]$out){
  $bytes = [Text.Encoding]::UTF8.GetBytes("$instr`n$out")
  $sha = [System.Security.Cryptography.SHA256]::Create()
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
}
function Load-Seen {
  $seen = @{}
  if (Test-Path $seenPath) {
    Get-Content $seenPath | ForEach-Object {
      if ($_ -match '^([0-9a-f]{64}):') { $seen[$matches[1]] = $true }
    }
  }
  return $seen
}
function Append-Seen([string]$hash,[string]$name){
  ("{0}:{1} ({2})" -f $hash, $name, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) | Add-Content $seenPath -Encoding utf8
}
function Rotate-Train([int]$thresholdMB=200) {
  if (-not (Test-Path $trainPath)) { return }
  $len = (Get-Item $trainPath).Length
  if ($len -gt ($thresholdMB*1MB)) {
    $dst = Join-Path $sftDir ("train_{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Move-Item $trainPath $dst -Force
    New-Item -ItemType File -Path $trainPath -Force | Out-Null
    Write-Log ("ROTATE: {0} -> {1} (>{2}MB)" -f "train.jsonl",(Split-Path $dst -Leaf),$thresholdMB)
  }
}

function Process-Accepted {
  $seen = Load-Seen
  $accepted=0; $dup=0; $errors=0; $lines=0

  if (-not (Test-Path $accDir)) { return @{accepted=0;dup=0;errors=0;lines=0} }

  Get-ChildItem $accDir -Filter *.json -ErrorAction SilentlyContinue | ForEach-Object {
    $name=$_.Name
    try {
      $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
      $prompt = [string]$j.prompt
      $output = [string]$j.output
      if ([string]::IsNullOrWhiteSpace($prompt) -or $prompt.Length -lt 16 -or [string]::IsNullOrWhiteSpace($output)) {
        "SFT-SCHEMA-ERROR $name: missing/short prompt or output" | Tee-Object -FilePath "$logDir\intake_errors.log" -Append | Out-Null
        Move-Item $_.FullName (Join-Path $errDir $name) -Force
        $errors++
        return
      }
      $h = Get-ContentHash $prompt $output
      if ($seen.ContainsKey($h)) {
        Write-Log "SFT: DUP $name (hash=$h)"
        Move-Item $_.FullName (Join-Path $procDir $name) -Force
        $dup++
        return
      }
      $obj = @{instruction=$prompt; input=""; output=$output} | ConvertTo-Json -Compress
      $obj | Add-Content $trainPath -Encoding utf8
      Append-Seen $h $name
      Move-Item $_.FullName (Join-Path $procDir $name) -Force
      $accepted++; $lines++
      Write-Log "SFT: accepted $name"
    } catch {
      ("SFT-ERROR {0}: {1}" -f $name, $_.Exception.Message) | Tee-Object -FilePath "$logDir\intake_errors.log" -Append | Out-Null
      try { Move-Item $_.FullName (Join-Path $errDir $name) -Force } catch {}
      $errors++
    }
  }
  return @{accepted=$accepted;dup=$dup;errors=$errors;lines=$lines}
}

# === Main ===
Ensure-Dirs

# Kill switch
if ((Test-Path ".trae/disable_autostart") -or ($env:TRAE_AUTOSTART -eq "0")) {
  Write-Log "KILL-SWITCH: disabled"; exit 0
}

# Health guard (best-effort)
try {
  $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
  $freePct = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { 100*($_.FreeSpace/$_.Size) } | Measure-Object -Average).Average
  if ($cpu -ge 85 -or $freePct -le 10) { Write-Log ("SKIP: health cpu={0}% free={1:N1}%" -f $cpu,$freePct); exit 0 }
} catch { Write-Log "HEALTH: skipped ($($_.Exception.Message))" }

# Backoff
$wait = 0
if (Should-Backoff ([ref]$wait)) { Write-Log ("BACKOFF: wait {0:N0}s" -f $wait); exit 0 }

if (-not (Acquire-Lock 30)) { Write-Log "LOCK: busy, exit"; exit 0 }

try {
  Write-Log "RUN: autopatch cycle"

  if (-not $Apply) {
    Write-Log "PLAN: dry-run (tests + ingest would run)"
    Release-Lock
    exit 0
  }

  if (-not (Invoke-Tests -Apply)) { throw "tests failed" }

  # SFT ingest
  $res = Process-Accepted
  Write-Log ("SFT: accepted={0} dup={1} errors={2} lines+={3}" -f $res.accepted,$res.dup,$res.errors,$res.lines)

  # Rotation
  Rotate-Train 200

  Reset-Backoff
  Write-Log "OK"
} catch {
  Write-Log ("ERROR: {0}" -f $_.Exception.Message)
  Bump-Backoff
} finally {
  Release-Lock
}

# Metrics (best-effort)
try {
  $metrics = Join-Path $PSScriptRoot "trae_metrics_simple.ps1"
  if (Test-Path $metrics) { & $metrics -Apply | Out-Null }
} catch { Write-Log "METRICS: skip ($($_.Exception.Message))" }
