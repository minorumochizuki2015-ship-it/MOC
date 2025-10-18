<#
 Auto Power Profile — Windows Power Plan Auto Switcher
 目的:
   - 使用不可（入力なし・低CPU）時は省電力（SCHEME_MIN）へ切替
   - 活動再開時はバランス（SCHEME_BALANCED）へ復帰
   - AC/DC に応じてアイドル閾値を調整
 設定:
   - $PSScriptRoot\..\..\config\power_profile.json を参照
 ログ:
   - $PSScriptRoot\..\..\artifacts\power\run.log へ追記
 実行: PowerShell 7+ 推奨（Windows）
#>

param(
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Log {
  param([string]$msg)
  $root = Join-Path $PSScriptRoot '..\..'
  $logDir = Join-Path $root 'artifacts\power'
  if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
  $logPath = Join-Path $logDir 'run.log'
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts] $msg"
  Add-Content -Path $logPath -Value $line -Encoding UTF8
  Write-Host $line
}

# 設定読込
$repoRoot = Join-Path $PSScriptRoot '..\..'
$cfgPath = Join-Path $repoRoot 'config\power_profile.json'
if (!(Test-Path $cfgPath)) {
  throw "設定ファイルが見つかりません: $cfgPath"
}
$cfg = Get-Content -Path $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$global:PowerCfg = $cfg

# 監査対策のための設定デフォルト（平滑化/ドウェル/ローテーション）
$sensorSamples = if ($cfg.sensor.samples) { [int]$cfg.sensor.samples } else { 3 }
$sensorIntervalMs = if ($cfg.sensor.sample_interval_ms) { [int]$cfg.sensor.sample_interval_ms } else { 500 }
$sensorWarnOnce = if ($cfg.sensor.warn_once -ne $null) { [bool]$cfg.sensor.warn_once } else { $true }
$dwellUpSec = if ($cfg.dwell_up_sec) { [int]$cfg.dwell_up_sec } else { 90 }
$dwellDownSec = if ($cfg.dwell_down_sec) { [int]$cfg.dwell_down_sec } else { 45 }
$minSessionSec = if ($cfg.min_session_sec) { [int]$cfg.min_session_sec } else { 120 }
$logRotateEnabled = if ($cfg.log_rotation.enabled -ne $null) { [bool]$cfg.log_rotation.enabled } else { $false }
$logRotatePolicy = if ($cfg.log_rotation.policy) { [string]$cfg.log_rotation.policy } else { 'daily' }
$logRotateMaxDays = if ($cfg.log_rotation.max_days) { [int]$cfg.log_rotation.max_days } else { 14 }
$logRotateMaxMB = if ($cfg.log_rotation.max_mb_per_file) { [int]$cfg.log_rotation.max_mb_per_file } else { 20 }

# アイドル秒取得（GetLastInputInfo）
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class IdleTimeHelper {
  [StructLayout(LayoutKind.Sequential)]
  public struct LASTINPUTINFO {
    public uint cbSize;
    public uint dwTime;
  }
  [DllImport("user32.dll")]
  public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
  public static uint GetIdleMilliseconds() {
    LASTINPUTINFO lastInput = new LASTINPUTINFO();
    lastInput.cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(lastInput);
    if (!GetLastInputInfo(ref lastInput)) return 0;
    return (uint)Environment.TickCount - lastInput.dwTime;
  }
}
"@

function Get-IdleSeconds {
  return [Math]::Round([IdleTimeHelper]::GetIdleMilliseconds()/1000.0)
}

function Get-CPUPercent {
  $c = Get-Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction SilentlyContinue
  return [Math]::Round($c.CounterSamples.CookedValue)
}

# 電源状態取得（AC/DC）
Add-Type -AssemblyName System.Windows.Forms
function Get-PowerLineStatus {
  try {
    return [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus.ToString()
  } catch {
    return 'Unknown'
  }
}

# Foreground window / process helpers
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WinApi {
  [DllImport("user32.dll")]
  public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")]
  public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")]
  public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
"@

function Get-ForegroundProcessName {
  try {
    $h = [WinApi]::GetForegroundWindow()
    if ($h -eq [IntPtr]::Zero) { return '' }
    [uint32]$pid = 0
    [void][WinApi]::GetWindowThreadProcessId($h, [ref]$pid)
    if ($pid -eq 0) { return '' }
    $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($null -eq $p) { return '' }
    return ($p.ProcessName + '.exe')
  } catch { return '' }
}

function Test-ForegroundFullscreen {
  try {
    $h = [WinApi]::GetForegroundWindow()
    if ($h -eq [IntPtr]::Zero) { return $false }
    $r = New-Object RECT
    $ok = [WinApi]::GetWindowRect($h, [ref]$r)
    if (-not $ok) { return $false }
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    # 許容誤差（タスクバー等）。幅・高さが画面に近ければ全画面とみなす
    $w = $r.Right - $r.Left
    $hgt = $r.Bottom - $r.Top
    $dw = [Math]::Abs($bounds.Width - $w)
    $dh = [Math]::Abs($bounds.Height - $hgt)
    return ($dw -le 10 -and $dh -le 40)
  } catch { return $false }
}

function In-TimeBand($band, [datetime]$now) {
  try {
    $start = [datetime]::ParseExact($band.start, 'HH:mm', $null)
    $end   = [datetime]::ParseExact($band.end, 'HH:mm', $null)
    $curr  = [datetime]::ParseExact($now.ToString('HH:mm'), 'HH:mm', $null)
    if ($start -le $end) { return ($curr -ge $start -and $curr -lt $end) }
    else { return ($curr -ge $start -or $curr -lt $end) } # wrap over midnight
  } catch { return $false }
}

function Ensure-TelemetryRotation {
  $root = Join-Path $PSScriptRoot '..\..'
  $dir  = Join-Path $root 'artifacts\power'
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $csv  = Join-Path $dir 'telemetry.csv'
  if ($logRotateEnabled) {
    try {
      # 日次ローテーション
      if (Test-Path $csv) {
        $info = Get-Item $csv
        if ($info.LastWriteTime.Date -lt (Get-Date).Date) {
          $dst = Join-Path $dir ("telemetry_" + $info.LastWriteTime.ToString('yyyyMMdd') + ".csv")
          Move-Item -Path $csv -Destination $dst -Force
        }
      }
      # サイズローテーション
      if (Test-Path $csv) {
        $sizeMB = (Get-Item $csv).Length / 1MB
        if ($sizeMB -ge $logRotateMaxMB) {
          $dst = Join-Path $dir ("telemetry_" + (Get-Date).ToString('yyyyMMdd_HHmmss') + ".csv")
          Move-Item -Path $csv -Destination $dst -Force
        }
      }
      # 世代削除
      Get-ChildItem -Path $dir -Filter 'telemetry_*.csv' | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$logRotateMaxDays) } | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Write-Log "WARN: telemetry ローテーション失敗: $($_.Exception.Message)"
    }
  }
  if (!(Test-Path $csv)) {
    $header = 'timestamp,input_idle_sec,cpu_pct,gpu_pct,gpu_pct_avg,net_kBps,net_kBps_avg,disk_kBps,disk_kBps_avg,active_scheme,line_status,fg_process,is_fullscreen,canIdle,isIdle,idle_min,cpu_th'
    Set-Content -Path $csv -Value $header -Encoding UTF8
  }
  return $csv
}

function Write-Telemetry($row) {
  $csv = Ensure-TelemetryRotation
  Add-Content -Path $csv -Value $row -Encoding UTF8
}

function Get-ActiveSchemeName {
  $out = powercfg -getactivescheme 2>$null
  if ($out -match '\(([^\)]+)\)') { return $Matches[1] }
  return $out
}

function Set-ActiveScheme([string]$schemeAlias) {
  if ($DryRun) { Write-Log "DryRun: powercfg -setactive $schemeAlias"; return }
  powercfg -setactive $schemeAlias 2>$null
}

# ドウェル（最小滞在）制御
$lastSwitch = Get-Date
$idleCandidateSince = $null
$activeCandidateSince = $null

# WARN一度だけ（nvidia-smi不在）用の状態ファイル
$statePath = Join-Path (Join-Path $PSScriptRoot '..\..') 'artifacts\power\state.json'
try {
  if (!(Test-Path $statePath)) {
    '{"warned_nvidia": false}' | Set-Content -Path $statePath -Encoding UTF8
  }
  $state = Get-Content -Path $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
  $state = @{ warned_nvidia = $false } | ConvertTo-Json | ConvertFrom-Json
}
$currentScheme = Get-ActiveSchemeName
Write-Log "開始: ActiveScheme='$currentScheme', DryRun=$DryRun"

while ($true) {
  $idleSec = Get-IdleSeconds
  $cpuPct  = Get-CPUPercent
  $line    = Get-PowerLineStatus
  $onAC    = ($line -eq 'Online')

  # センサー移動平均（Nサンプル / sensor.sample_interval_ms）
  $gpuSum = 0; $netSum = 0; $diskSum = 0
  for ($i=0; $i -lt $sensorSamples; $i++) {
    # GPU（nvidia-smi 不在時はWARN一度のみ）
    try {
      $gpuUtilStr = & nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>$null | Select-Object -First 1
      if ($gpuUtilStr) { $gpuSum += [int]$gpuUtilStr } else { $gpuSum += 0 }
    } catch {
      if ($sensorWarnOnce -and -not $state.warned_nvidia) {
        Write-Log 'WARN: nvidia-smi が見つからない/失敗。GPU利用率は0として継続（以降WARN抑止）'
        $state.warned_nvidia = $true
        ($state | ConvertTo-Json -Depth 3) | Set-Content -Path $statePath -Encoding UTF8
      }
      $gpuSum += 0
    }
    # NET
    try {
      $net = (Get-Counter '\\Network Interface(*)\\Bytes Total/sec').CounterSamples | Measure-Object -Property CookedValue -Sum
      $netSum += [int]($net.Sum / 1024)
    } catch { $netSum += 0 }
    # DISK
    try {
      $disk = (Get-Counter '\\PhysicalDisk(_Total)\\Disk Bytes/sec').CounterSamples | Select-Object -ExpandProperty CookedValue
      $diskSum += [int]($disk / 1024)
    } catch { $diskSum += 0 }
    Start-Sleep -Milliseconds $sensorIntervalMs
  }
  $gpuUtil = [int]([math]::Round($gpuSum / $sensorSamples))
  $netKBps = [int]([math]::Round($netSum / $sensorSamples))
  $diskKBps = [int]([math]::Round($diskSum / $sensorSamples))

  # 前景プロセス・全画面判定
  $fgName = Get-ForegroundProcessName
  $isFullscreen = Test-ForegroundFullscreen
  $exempt = $false
  try {
    $exempt = ($cfg.foreground_exempt_processes -contains $fgName) -or ($cfg.fullscreen_exempt -and $isFullscreen)
  } catch { $exempt = $false }

  # 時間帯ポリシー適用
  $idleMinAC = [int]$cfg.idle_minutes_ac
  $cpuTh     = [int]$cfg.cpu_threshold_percent
  try {
    $band = $cfg.timeband_rules | Where-Object { In-TimeBand $_ (Get-Date) } | Select-Object -First 1
    if ($band) {
      if ($band.idle_minutes_ac) { $idleMinAC = [int]$band.idle_minutes_ac }
      if ($band.cpu_threshold_percent) { $cpuTh = [int]$band.cpu_threshold_percent }
    }
  } catch {}

  # 時間帯境界 ±1分の保持（フラップ抑止）
  $holdNearBoundary = $false
  try {
    $now = Get-Date
    foreach ($b in $cfg.timeband_rules) {
      $startDT = [datetime]::ParseExact(($now.ToString('yyyy-MM-dd') + ' ' + $b.start), 'yyyy-MM-dd HH:mm', $null)
      $endDT   = [datetime]::ParseExact(($now.ToString('yyyy-MM-dd') + ' ' + $b.end),   'yyyy-MM-dd HH:mm', $null)
      if ([Math]::Abs(($now - $startDT).TotalMinutes) -le 1 -or [Math]::Abs(($now - $endDT).TotalMinutes) -le 1) { $holdNearBoundary = $true; break }
    }
  } catch { $holdNearBoundary = $false }

  $idleMinThreshold = if ($onAC) { $idleMinAC } else { [int]$cfg.idle_minutes_dc }
  $underThresholds   = ($gpuUtil -lt [int]$cfg.gpu_threshold_percent) -and ($netKBps -lt [int]$cfg.net_kBps_threshold) -and ($diskKBps -lt [int]$cfg.disk_kBps_threshold)
  $canIdle           = $underThresholds -and (-not $exempt)
  $isIdle            = ($idleSec -ge ($idleMinThreshold*60)) -and ($cpuPct -le $cpuTh)

  $elapsed = (Get-Date) - $lastSwitch
  $canSwitchBySession = ($elapsed.TotalSeconds -ge $minSessionSec)

  $activeName = Get-ActiveSchemeName

  # Telemetry 出力（平滑化値も含めて記録）
  $teleRow = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15}" -f \
    (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $idleSec, $cpuPct, $gpuUtil, $gpuUtil, $netKBps, $netKBps, $diskKBps, $diskKBps, $activeName, $line, $fgName, $isFullscreen, $canIdle, $isIdle, $idleMinThreshold, $cpuTh
  Write-Telemetry $teleRow

  # 非対称ドウェル + 境界保持（フラップ抑止）
  if (-not $holdNearBoundary) {
    if ($isIdle -and $canIdle) {
      if ($null -eq $idleCandidateSince) { $idleCandidateSince = Get-Date }
      $idleDwellOk = ((Get-Date) - $idleCandidateSince).TotalSeconds -ge $dwellUpSec
      if ($idleDwellOk -and $canSwitchBySession -and ($activeName -ne 'Power saver')) {
        Write-Log "条件一致: IdleSec=$idleSec CPU=$cpuPct% GPU=$gpuUtil% Net=${netKBps}KB/s Disk=${diskKBps}KB/s FG=$fgName FullScreen=$isFullscreen Line=$line → 省電力へ切替"
        Set-ActiveScheme $cfg.on_idle_scheme
        $lastSwitch = Get-Date
        $idleCandidateSince = $null; $activeCandidateSince = $null
      }
    } else {
      $idleCandidateSince = $null
    }

    if ((-not $isIdle -or -not $canIdle)) {
      if ($null -eq $activeCandidateSince) { $activeCandidateSince = Get-Date }
      $activeDwellOk = ((Get-Date) - $activeCandidateSince).TotalSeconds -ge $dwellDownSec
      if ($activeDwellOk -and $canSwitchBySession -and ($activeName -ne 'Balanced')) {
        $target = $cfg.on_ac_active_scheme
        Write-Log "条件一致: Activity検知 IdleSec=$idleSec CPU=$cpuPct% GPU=$gpuUtil% Net=${netKBps}KB/s Disk=${diskKBps}KB/s FG=$fgName FullScreen=$isFullscreen Line=$line → バランスへ復帰"
        Set-ActiveScheme $target
        $lastSwitch = Get-Date
        $idleCandidateSince = $null; $activeCandidateSince = $null
      }
    } else {
      $activeCandidateSince = $null
    }
  } else {
    Write-Log "境界±1分: 現行モード保持 (Active='$activeName')"
  }

  Start-Sleep -Seconds ([int]$cfg.check_interval_sec)
}