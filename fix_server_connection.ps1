param([switch]$Apply, [switch]$FixEnv, [switch]$KillZombies)

$ErrorActionPreference = 'Stop'
$py = ".\.venv\Scripts\python.exe"
$baseWanted = "http://127.0.0.1:8080"
$model = "/models/qwen2-7b-instruct-q4_k_m.gguf"

# 0) 事前
if (-not (Test-Path $py)) { throw "venv python missing: $py" }

# 1) 環境変数チェック（/v1混入検出）
$envBase = [Environment]::GetEnvironmentVariable("OPENAI_COMPAT_BASE", "Process")
if (-not $envBase) { $envBase = [Environment]::GetEnvironmentVariable("OPENAI_COMPAT_BASE", "User") }
if (-not $envBase) { $envBase = [Environment]::GetEnvironmentVariable("OPENAI_COMPAT_BASE", "Machine") }
$envBase = $envBase ?? "<unset>"
Write-Host "OPENAI_COMPAT_BASE = $envBase"
$hasV1 = $envBase -match '/v1/?$'
if ($hasV1) { Write-Warning "ENV includes /v1 → 二重パス原因になり得ます" }

if ($FixEnv) {
    if ($Apply) {
        [Environment]::SetEnvironmentVariable("OPENAI_COMPAT_BASE", $baseWanted, "User")
        Write-Host "[FIXED] OPENAI_COMPAT_BASE -> $baseWanted (User)"
    }
    else { Write-Host "DRYRUN: set OPENAI_COMPAT_BASE=$baseWanted (User)" }
}

# 2) 8080占有状況
$owners = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue |
Select-Object -ExpandProperty OwningProcess -Unique
if ($owners) {
    $plist = $owners | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }
    Write-Host "8080 LISTENERS:"; $plist | Select Id, ProcessName, StartTime | Format-Table -Auto
    if ($KillZombies -and $Apply) {
        $plist | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "[KILLED] stale listeners on 8080"
    }
}
else {
    Write-Host "8080: no listener"
}

# 3) ヘルスチェック
function Test-Health([string]$base) {
    try {
        $r = Invoke-RestMethod -Method Get -Uri ($base + "/v1/models") -TimeoutSec 3
        return $true
    }
    catch { return $false }
}
$ok = Test-Health $baseWanted
Write-Host "HEALTH(/v1/models @ $baseWanted) = $ok"

# 4) 起動（未稼働時のみ）
if (-not $ok) {
    $args = @(
        "-m", "llama_cpp.server",
        "--model", $model,
        "--host", "127.0.0.1", "--port", "8080",
        "--gpu-layers", "64", "--ctx-size", "2048", "--batch-size", "512",
        "--threads", "8", "--kv-type", "q8_0"
    )
    if ($Apply) {
        Start-Process -FilePath $py -ArgumentList $args -WindowStyle Minimized | Out-Null
        Start-Sleep 2
        $ok = Test-Health $baseWanted
        Write-Host "POST-START HEALTH = $ok"
        if (-not $ok) { Write-Warning "server failed to come up. モデルパス/VRAM/依存を確認してください: $model" }
    }
    else {
        Write-Host "DRYRUN START: $py $($args -join ' ')"
    }
}

# 5) まとめ
if ($hasV1) { Write-Warning "→ 環境変数から /v1 を外してください（-FixEnv -Apply で修正可）" }
if (-not $ok) { Write-Warning "→ 依然NG。次: ①Windows防火壁の受信規則 ②モデル実在 `$(Resolve-Path -LiteralPath .\ | Out-Null; $model)` ③イベントログ(Application) を確認" }
