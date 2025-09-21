param([switch]$Apply)
$ErrorActionPreference='Stop'
$lock="data/locks/autopatch.lock"
$lockTtlMin=5
$maxSeconds=40
$backoffFile="data/locks/autopatch.backoff"
$logDir="data/logs/current"; if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force $logDir | Out-Null }
$log=Join-Path $logDir ("trae_autostart_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$kill = (Test-Path ".trae/disable_autostart") -or ($env:TRAE_AUTOSTART -eq "0")
if ($kill) { "KILLED" | Tee-Object -FilePath $log; exit 0 }
# stale lock
if (Test-Path $lock) {
  $ageMin = ((Get-Date).ToUniversalTime() - (Get-Item $lock).LastWriteTimeUtc).TotalMinutes
  if ($ageMin -gt $lockTtlMin) { "STALE LOCK -> remove" | Tee-Object -FilePath $log -Append; Remove-Item $lock -Force -ErrorAction SilentlyContinue }
  else { "LOCKED ($([math]::Round($ageMin,1))m) -> skip" | Tee-Object -FilePath $log -Append; exit 0 }
}
# exponential backoff
$now=[DateTime]::UtcNow
if (Test-Path $backoffFile) {
  $backoffContent = (Get-Content $backoffFile -Raw).Trim()
  $nextStr = $backoffContent.Split('|')[0]
  $next=[DateTime]::Parse($nextStr)
  if ($now -lt $next) { "BACKOFF until $($next.ToString("u"))" | Tee-Object -FilePath $log -Append; exit 0 }
}
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$freePct = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { 100*($_.FreeSpace/$_.Size) } | Measure-Object -Average).Average
if ($cpu -ge 85 -or $freePct -le 10) { "SKIP: health cpu=$cpu free=$([math]::Round($freePct,1))%" | Tee-Object -FilePath $log; exit 0 }
$lockOk = New-Item -ItemType File -Path $lock -Force -ErrorAction SilentlyContinue
try {
  $sw=[System.Diagnostics.Stopwatch]::StartNew()
  "RUN: autopatch cycle" | Tee-Object -FilePath $log -Append
  $py=".\.venv\Scripts\python.exe"
  $cmd="$py -m pytest -q --maxfail=1 --strict-markers"
  if (-not $Apply) { "PLAN: $cmd" | Tee-Object -FilePath $log -Append; exit 0 }
  iex $cmd; if ($LASTEXITCODE -ne 0) { throw "tests failed" }
  if ($sw.Elapsed.TotalSeconds -gt $maxSeconds) {
    "TIMEOUT: $([math]::Round($sw.Elapsed.TotalSeconds,1))s > $maxSeconds" | Tee-Object -FilePath $log -Append
  }
  "OK" | Tee-Object -FilePath $log -Append
} catch {
  $n=1; if (Test-Path $backoffFile) { $n=[int](Get-Content $backoffFile -First 1 -ErrorAction SilentlyContinue).Split('|')[-1] }
  $n=[Math]::Min($n+1,5) # 1→5段階
  $mins=(30,60,120,240,480)[$n-1]
  $until=$now.AddMinutes($mins)
  "$($until.ToString('u'))|$n" | Set-Content $backoffFile -Encoding utf8
  "SET BACKOFF $mins min (n=$n)" | Tee-Object -FilePath $log -Append
  throw
} finally {
  Remove-Item $lock -ErrorAction SilentlyContinue
  if ($LASTEXITCODE -eq 0 -and (Test-Path $backoffFile)) { Remove-Item $backoffFile -ErrorAction SilentlyContinue }
}