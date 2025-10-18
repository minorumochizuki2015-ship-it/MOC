param(
    [int]$Port = 5000
)

function Get-HealthStatus {
    try {
        $resp = Invoke-WebRequest "http://localhost:$Port/healthz" -UseBasicParsing -TimeoutSec 3
        return @{ status = $resp.StatusCode; body = $resp.Content }
    } catch {
        return @{ status = "ERR"; body = "$($_.Exception.Message)" }
    }
}

$date = Get-Date -Format "yyyy-MM-dd"
$outDir = "ORCH/STATE"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outFile = Join-Path $outDir ("PORTS_" + ($date -replace "-", "") + ".md")

Write-Host "[Snapshot] Writing $outFile"

$portCheck = (python scripts/ops/check_port.py $Port) 2>&1
$health = Get-HealthStatus

$content = @()
$content += "# Port Status Snapshot ($date)"
$content += ""
$content += "- Port: $Port"
$content += "- PortCheck: $portCheck" 
$content += "- Health: $($health.status)"
$content += "- Body: $($health.body)"
$content += ""
$content += "Visible URLs:" 
$content += "- http://localhost:$Port/dashboard"
$content += "- http://localhost:$Port/style-manager"
$content += "- http://localhost:$Port/tasks"

Set-Content -Path $outFile -Value ($content -join "`n")

Write-Host "[Snapshot] Done."