# UTF-8
param([switch]$Apply)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$branch = "checkpoint_$timestamp"

if ($Apply) {
    git add -A
    git commit -m "checkpoint_$timestamp" --no-verify
    git tag "SAFEPOINT_$timestamp"
    Write-Host "✓ Checkpoint created: $branch"
} else {
    Write-Host "Dry-Run: Would create checkpoint $branch"
}
