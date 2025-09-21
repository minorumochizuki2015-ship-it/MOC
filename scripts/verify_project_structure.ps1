param([switch]$Apply)
$ErrorActionPreference='Stop'

Write-Host "=== Project Structure Verification ===" -ForegroundColor Green

# 1. 構造検査
Write-Host "`n1. Checking project structure..." -ForegroundColor Yellow

$requiredFiles = @(
    ".gitattributes",
    ".pre-commit-config.yaml",
    "scripts\hooks\pre-push.ps1",
    "scripts\trae_autostart.ps1",
    ".github\workflows\ci.yml",
    ".trae\rules\project_rules.md"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "  ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $file" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "`nMissing files detected:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    if (-not $Apply) { 
        Write-Host "`nRun with -Apply to continue despite missing files" -ForegroundColor Yellow
        exit 1 
    }
}

# 2. フック導入チェック
Write-Host "`n2. Checking Git hooks configuration..." -ForegroundColor Yellow
$hooksPath = git config core.hooksPath
if ($hooksPath -eq "scripts/hooks") {
    Write-Host "  ✅ Git hooks path configured: $hooksPath" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Git hooks path not configured. Current: $hooksPath" -ForegroundColor Yellow
    Write-Host "  Run: git config core.hooksPath scripts/hooks" -ForegroundColor Cyan
}

# 3. pre-push試走
Write-Host "`n3. Testing pre-push script..." -ForegroundColor Yellow
if (Test-Path "scripts\hooks\pre-push.ps1") {
    Write-Host "  Running pre-push dry-run..." -ForegroundColor Cyan
    try {
        & "scripts\hooks\pre-push.ps1"
        Write-Host "  ✅ pre-push script executed successfully" -ForegroundColor Green
    } catch {
        Write-Host "  ❌ pre-push script failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  ❌ pre-push.ps1 not found" -ForegroundColor Red
}

# 4. Autostart試走
Write-Host "`n4. Testing autostart script..." -ForegroundColor Yellow
if (Test-Path "scripts\trae_autostart.ps1") {
    Write-Host "  Running autostart dry-run..." -ForegroundColor Cyan
    try {
        & "scripts\trae_autostart.ps1"
        Write-Host "  ✅ autostart script executed successfully" -ForegroundColor Green
    } catch {
        Write-Host "  ❌ autostart script failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  ❌ trae_autostart.ps1 not found" -ForegroundColor Red
}

# 5. 必要なディレクトリ作成
Write-Host "`n5. Checking required directories..." -ForegroundColor Yellow
$requiredDirs = @(
    "data\locks",
    "data\logs\current",
    "observability\coverage",
    "observability\sbom"
)

foreach ($dir in $requiredDirs) {
    if (Test-Path $dir) {
        Write-Host "  ✅ $dir" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Creating $dir" -ForegroundColor Yellow
        if ($Apply) {
            New-Item -ItemType Directory -Force $dir | Out-Null
            Write-Host "  ✅ Created $dir" -ForegroundColor Green
        } else {
            Write-Host "  📋 Would create $dir (use -Apply to create)" -ForegroundColor Cyan
        }
    }
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Green
if (-not $Apply) {
    Write-Host "This was a dry-run. Use -Apply to make actual changes." -ForegroundColor Yellow
}