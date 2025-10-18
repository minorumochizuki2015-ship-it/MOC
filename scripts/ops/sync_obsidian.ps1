param(
    [Parameter(Mandatory=$true)][string]$VaultPath,
    [string]$ProjectRoot = (Resolve-Path ".").Path
)

Write-Host "[Sync] ProjectRoot: $ProjectRoot"
Write-Host "[Sync] VaultPath   : $VaultPath"

if (!(Test-Path $VaultPath)) {
    Write-Error "VaultPath not found: $VaultPath"
    exit 1
}

$items = @(
    "docs",
    "ORCH/STATE",
    "ORCH/REPORTS",
    "ORCH/LOGS"
)

foreach ($item in $items) {
    $src = Join-Path $ProjectRoot $item
    $dst = Join-Path $VaultPath $item
    if (!(Test-Path $src)) {
        Write-Warning "Skip missing: $src"
        continue
    }
    Write-Host "[Sync] Copying $src -> $dst"
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    robocopy $src $dst /E /NFL /NDL /NP /XO | Out-Null
}

Write-Host "[Sync] Completed."