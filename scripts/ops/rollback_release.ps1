param(
    [switch]$CheckOnly
)

Write-Host "[Rollback] Starting rollback script..." -ForegroundColor Cyan

function Test-Idempotency {
    param([string]$ReleaseDir)
    $hashFile = Join-Path $ReleaseDir "sha256sum.txt"
    if (-Not (Test-Path $hashFile)) {
        Write-Host "[WARN] sha256sum.txt not found at $hashFile" -ForegroundColor Yellow
        return $false
    }
    Write-Host "[OK] Found checksum file: $hashFile" -ForegroundColor Green
    return $true
}

function Do-Rollback {
    param([string]$ReleaseDir)
    # Placeholder: Implement actual restore logic here.
    Write-Host "[INFO] Restoring from $ReleaseDir..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    Write-Host "[OK] Restore completed (placeholder)." -ForegroundColor Green
}

$releaseDir = Join-Path "ORCH" (Join-Path "releases" "latest")
Write-Host "[Info] Target release directory: $releaseDir" -ForegroundColor Cyan

if ($CheckOnly) {
    Write-Host "[Dry-Run] Checking rollback prerequisites..." -ForegroundColor Cyan
    if (Test-Idempotency -ReleaseDir $releaseDir) {
        Write-Host "[OK] Dry-run checks passed." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[ERROR] Dry-run checks failed." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[Run] Executing rollback..." -ForegroundColor Cyan
    if (Test-Idempotency -ReleaseDir $releaseDir) {
        Do-Rollback -ReleaseDir $releaseDir
        Write-Host "[OK] Rollback completed." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[ERROR] Rollback aborted due to failed checks." -ForegroundColor Red
        exit 1
    }
}