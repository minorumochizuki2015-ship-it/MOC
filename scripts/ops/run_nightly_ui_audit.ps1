Param(
  [int]$Port = 5001,
  [string]$HostName = "127.0.0.1",
  [string]$OutDir = "artifacts/nightly-ui-audit"
)

$ErrorActionPreference = "Stop"

Write-Host "[Nightly UI Audit] Starting..." -ForegroundColor Cyan

# Ensure output directory exists
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptsDir = Split-Path -Parent $scriptDir
$repoRoot = Split-Path -Parent $scriptsDir
$outPath = Join-Path $repoRoot $OutDir
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

function Write-HeaderTable([hashtable]$headers, [string]$outputPath) {
  $out = "Key                           Value" + [Environment]::NewLine +
         "---                           -----" + [Environment]::NewLine
  foreach ($k in $headers.Keys) {
    $v = $headers[$k]
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { $v = ($v -join ", ") }
    $out += ("{0,-28} {1}" -f $k, $v) + [Environment]::NewLine
  }
  $out | Set-Content $outputPath
}

# Gate tracking
$failures = New-Object System.Collections.Generic.List[string]
function Add-Failure([string]$msg) { $failures.Add($msg) | Out-Null; Write-Warning $msg }
function Check-VaryOriginDedup([string]$varyVal, [string]$context) {
  if (-not $varyVal) { Add-Failure ("[$context] Vary ヘッダがありません") ; return }
  $list = $varyVal -split "," | ForEach-Object { $_.Trim() }
  $count = ($list | Where-Object { $_ -eq "Origin" }).Count
  if ($count -eq 0) { Add-Failure ("[$context] Vary に Origin が含まれていません") }
  elseif ($count -gt 1) { Add-Failure ("[$context] Vary の Origin が重複しています") }
}

# 1) Health check
try {
  $healthUrl = "http://${HostName}:${Port}/healthz"
  Write-Host "[Health] GET $healthUrl" -ForegroundColor DarkCyan
  $resp = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 5
  "StatusCode: $($resp.StatusCode)" | Set-Content (Join-Path $outPath "health.txt")
} catch {
  Add-Failure ("[Health] ${HostName}:${Port} へのアクセスに失敗: " + $_.Exception.Message)
  "ERROR: $($_.Exception.Message)" | Set-Content (Join-Path $outPath "health.txt")
}

# 2) Preview success headers (+ gate: Vary: Origin dedup)
try {
  $previewUrl = "http://${HostName}:${Port}/preview?target=http%3A%2F%2F${HostName}%3A${Port}%2Fstatic%2Ftest_preview_ext.html"
  Write-Host "[Preview] GET $previewUrl" -ForegroundColor DarkCyan
  $resp2 = Invoke-WebRequest -UseBasicParsing -Uri $previewUrl -TimeoutSec 10 -Headers @{ Origin = "http://${HostName}:${Port}" }
  $headersSuccess = $resp2.Headers | Out-String
  $headersSuccess | Set-Content (Join-Path $outPath "preview_success_headers.txt")
  Check-VaryOriginDedup $resp2.Headers["Vary"] "preview(success)"
  # Preview(success) expose gates
  $expose2 = $resp2.Headers["Access-Control-Expose-Headers"]
  if (-not $expose2 -or -not ($expose2 -match "\bETag\b")) { Add-Failure "[preview(success)] Access-Control-Expose-Headers に ETag が含まれていません" }
  if (-not $expose2 -or -not ($expose2 -match "X-Preview-")) { Add-Failure "[preview(success)] Access-Control-Expose-Headers に X-Preview-* が含まれていません" }
} catch {
  Add-Failure ("[Preview success] ヘッダ取得失敗: " + $_.Exception.Message)
  "ERROR: $($_.Exception.Message)" | Set-Content (Join-Path $outPath "preview_success_headers.txt")
}

# 3) Preview 400 headers (+ gate: Vary: Origin dedup)
$null = $HostName; $null = $Port
Write-Host ("[Preview-400] GET http://{0}:{1}/preview" -f $HostName, $Port) -ForegroundColor DarkCyan

$targetFile = Join-Path $outPath "preview_400_headers.txt"
$headersTable = @{}

# Try 1: Invoke-WebRequest
$resp3 = $null
try { $resp3 = Invoke-WebRequest -UseBasicParsing -Uri ("http://{0}:{1}/preview" -f $HostName, $Port) -TimeoutSec 10 -Headers @{ Origin = ("http://{0}:{1}" -f $HostName, $Port) } -ErrorAction Stop } catch { $resp3 = $null }

if ($resp3 -and $resp3.Headers) {
  foreach ($key in $resp3.Headers.Keys) { $headersTable[$key] = $resp3.Headers[$key] }
  Write-HeaderTable $headersTable $targetFile
  Check-VaryOriginDedup $resp3.Headers["Vary"] "preview(400)"
} else {
  # Try 2: HttpWebRequest
  $request = [System.Net.WebRequest]::Create(("http://{0}:{1}/preview" -f $HostName, $Port))
  try { $request.Headers.Add("Origin", ("http://{0}:{1}" -f $HostName, $Port)) } catch {}
  $response = $null
  try { $response = $request.GetResponse() } catch { $webex = $_.Exception; if ($webex -and $webex.Response) { $response = $webex.Response } }
  if ($response -and $response.Headers) {
    foreach ($key in $response.Headers.Keys) { $headersTable[$key] = $response.Headers[$key] }
    Write-HeaderTable $headersTable $targetFile
    Check-VaryOriginDedup $response.Headers["Vary"] "preview(400)"
    $null = $response.Close()
  } else {
    # Try 3: curl -I (raw header capture)
    try {
      $curlLines = & curl.exe -s -I -H ("Origin: http://{0}:{1}" -f $HostName, $Port) ("http://{0}:{1}/preview" -f $HostName, $Port)
      foreach ($line in $curlLines) {
        if ($line -match "^[A-Za-z0-9-]+:") {
          $parts = $line -split ":", 2
          if ($parts.Length -eq 2) { $headersTable[$parts[0].Trim()] = $parts[1].Trim() }
        }
      }
      if ($headersTable.Count -gt 0) {
        Write-HeaderTable $headersTable $targetFile
        if ($headersTable.ContainsKey("Vary")) { Check-VaryOriginDedup $headersTable["Vary"] "preview(400)" } else { Add-Failure "[preview(400)] Vary ヘッダが取得できませんでした" }
      } else {
        Add-Failure "[preview(400)] ヘッダの取得に失敗"
        "ERROR: Failed to capture headers for 400 response" | Set-Content $targetFile
      }
    } catch {
      Add-Failure ("[preview(400)] ヘッダ取得失敗: " + $_.Exception.Message)
      "ERROR: Failed to capture headers for 400 response" | Set-Content $targetFile
    }
  }
}

# 4) Styles (ETag exposure + gate: expose includes ETag and X-Preview-)
try {
  $stylesUrl = "http://${HostName}:${Port}/api/styles"
  Write-Host "[Styles] GET $stylesUrl" -ForegroundColor DarkCyan
  $resp4 = Invoke-WebRequest -UseBasicParsing -Uri $stylesUrl -TimeoutSec 5
  $etag = $resp4.Headers["ETag"]
  "ETag: $etag" | Set-Content (Join-Path $outPath "styles_etag.txt")
  # Save full headers
  $headersTable2 = @{}
  foreach ($key in $resp4.Headers.Keys) { $headersTable2[$key] = $resp4.Headers[$key] }
  Write-HeaderTable $headersTable2 (Join-Path $outPath "styles_headers.txt")
  # Gates
  if (-not $etag -or $etag.Trim().Length -eq 0) { Add-Failure "[styles] ETag が空です" }
  $expose = $resp4.Headers["Access-Control-Expose-Headers"]
  if (-not $expose -or -not ($expose -match "\bETag\b")) { Add-Failure "[styles] Access-Control-Expose-Headers に ETag が含まれていません" }
  if (-not $expose -or -not ($expose -match "X-Preview-")) { Add-Failure "[styles] Access-Control-Expose-Headers に X-Preview-* が含まれていません" }
} catch {
  Add-Failure ("[styles] ヘッダ取得失敗: " + $_.Exception.Message)
  "ERROR: $($_.Exception.Message)" | Set-Content (Join-Path $outPath "styles_etag.txt")
}

# 5) SSE health headers (+ gate)
try {
  $sseUrl = "http://${HostName}:${Port}/events/health"
  Write-Host "[SSE] GET $sseUrl" -ForegroundColor DarkCyan
  $lines = & curl.exe -i --max-time 2 $sseUrl
  $target = Join-Path $outPath "sse_headers.txt"
  $lines | Set-Content $target
  # parse
  $ct = ($lines | Where-Object { $_ -match "^Content-Type:" } | Select-Object -First 1)
  $cc = ($lines | Where-Object { $_ -match "^Cache-Control:" } | Select-Object -First 1)
  $xab= ($lines | Where-Object { $_ -match "^X-Accel-Buffering:" } | Select-Object -First 1)
  $ex = ($lines | Where-Object { $_ -match "^Access-Control-Expose-Headers:" } | Select-Object -First 1)
  if (-not ($ct -match "text/event-stream")) { Add-Failure "[SSE] Content-Type が text/event-stream ではありません" }
  if (-not ($cc -match "no-cache")) { Add-Failure "[SSE] Cache-Control が no-cache ではありません" }
  if (-not ($xab -match "no")) { Add-Failure "[SSE] X-Accel-Buffering が 'no' ではありません" }
  if (-not ($ex -match "\bETag\b")) { Add-Failure "[SSE] Access-Control-Expose-Headers に ETag が含まれていません" }
} catch {
  Add-Failure ("[SSE] ヘッダ取得失敗: " + $_.Exception.Message)
  "ERROR: $($_.Exception.Message)" | Set-Content (Join-Path $outPath "sse_headers.txt")
}

# Result
if ($failures.Count -gt 0) {
  $msg = "[Nightly UI Audit] FAIL" + [Environment]::NewLine + ($failures -join ([Environment]::NewLine))
  Write-Host $msg -ForegroundColor Red
  $msg | Set-Content (Join-Path $outPath "audit_failures.txt")
  throw "Nightly UI Audit failed"
} else {
  Write-Host "[Nightly UI Audit] PASSED. Output: $outPath" -ForegroundColor Green
  exit 0
}