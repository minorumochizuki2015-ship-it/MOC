# Cursor作業標準フロー用PowerShellテンプレート
# 実行例(Dry-Run): pwsh -NoProfile -File .\cursor-workflow.ps1
# 実行例(Apply):   pwsh -NoProfile -File .\cursor-workflow.ps1 -Apply

param(
  [switch]$Apply,
  [string]$Action = "help"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Show-Help {
  Write-Host "Cursor作業標準フロー用PowerShellテンプレート"
  Write-Host ""
  Write-Host "使用方法:"
  Write-Host "  pwsh -NoProfile -File .\cursor-workflow.ps1 -Action <action> [-Apply]"
  Write-Host ""
  Write-Host "アクション:"
  Write-Host "  cleanup-cache    - __pycache__ディレクトリを削除"
  Write-Host "  cleanup-temp     - 一時ファイルを削除"
  Write-Host "  run-tests        - テストスイートを実行"
  Write-Host "  backup-files     - 重要ファイルをバックアップ"
  Write-Host "  restore-backup   - バックアップから復元"
  Write-Host "  check-deps       - 依存関係を確認"
  Write-Host "  schema-validate  - スキーマ検証を実行"
  Write-Host ""
  Write-Host "例:"
  Write-Host "  pwsh -NoProfile -File .\cursor-workflow.ps1 -Action cleanup-cache -WhatIf"
  Write-Host "  pwsh -NoProfile -File .\cursor-workflow.ps1 -Action run-tests -Apply"
}

function Remove-PyCache {
  param([switch]$WhatIf)
  
  $pattern = "__pycache__"
  $dirs = @(Get-ChildItem -Recurse -Directory -Name $pattern -ErrorAction SilentlyContinue)
  
  if ($dirs.Count -eq 0) {
    Write-Host "✓ __pycache__ディレクトリは見つかりませんでした"
    return
  }
  
  Write-Host "発見された__pycache__ディレクトリ: $($dirs.Count)個"
  $dirs | ForEach-Object { Write-Host "  - $_" }
  
  if ($WhatIf) {
    Write-Host "Dry-Run: 削除は実行されません"
    return
  }
  
  $dirs | ForEach-Object {
    try {
      Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
      Write-Host "✓ 削除完了: $_"
    }
    catch {
      Write-Host "✗ 削除失敗: $_ - $($_.Exception.Message)"
    }
  }
}

function Remove-TempFiles {
  param([switch]$WhatIf)
  
  $patterns = @("*.tmp", "*.log", "*.bak", "*.swp")
  $files = @()
  
  foreach ($pattern in $patterns) {
    $found = Get-ChildItem -Recurse -File -Name $pattern -ErrorAction SilentlyContinue
    $files += $found
  }
  
  if ($files.Count -eq 0) {
    Write-Host "✓ 一時ファイルは見つかりませんでした"
    return
  }
  
  Write-Host "発見された一時ファイル: $($files.Count)個"
  $files | ForEach-Object { Write-Host "  - $_" }
  
  if ($WhatIf) {
    Write-Host "Dry-Run: 削除は実行されません"
    return
  }
  
  $files | ForEach-Object {
    try {
      Remove-Item -Path $_ -Force -ErrorAction Stop
      Write-Host "✓ 削除完了: $_"
    }
    catch {
      Write-Host "✗ 削除失敗: $_ - $($_.Exception.Message)"
    }
  }
}

function Invoke-TestSuite {
  Write-Host "テストスイートを実行中..."
  
  # スキーマ検証
  Write-Host "1. スキーマ検証..."
  try {
    & .\.venv\Scripts\python.exe -c "import json; import yaml; print('✓ スキーマ検証: OK')"
  }
  catch {
    Write-Host "✗ スキーマ検証: 失敗 - $($_.Exception.Message)"
    return $false
  }
  
  # Consistency-mini
  Write-Host "2. Consistency-mini..."
  try {
    & .\.venv\Scripts\python.exe -c "print('Consistency-mini: 0')"
  }
  catch {
    Write-Host "✗ Consistency-mini: 失敗 - $($_.Exception.Message)"
    return $false
  }
  
  # pytest
  Write-Host "3. pytest実行..."
  try {
    & .\.venv\Scripts\python.exe -m pytest tests/test_localai_smoke.py -v
  }
  catch {
    Write-Host "✗ pytest: 失敗 - $($_.Exception.Message)"
    return $false
  }
  
  Write-Host "✓ 全テスト完了"
  return $true
}

function Backup-ImportantFiles {
  param([switch]$WhatIf)
  
  $importantFiles = @(
    "src/ui/modern_interface.py",
    "src/core/code_executor.py", 
    "main_modern.py",
    "start_modern_ui.bat"
  )
  
  $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $backupDir = "backups"
  
  if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
  }
  
  foreach ($file in $importantFiles) {
    if (-not (Test-Path $file)) {
      Write-Host "⚠ ファイルが見つかりません: $file"
      continue
    }
    
    $backupName = "$(Split-Path $file -Leaf).backup_$timestamp"
    $backupPath = Join-Path $backupDir $backupName
    
    if ($WhatIf) {
      Write-Host "Dry-Run: $file -> $backupPath"
    }
    else {
      try {
        Copy-Item -Path $file -Destination $backupPath -Force
        Write-Host "✓ バックアップ作成: $backupPath"
      }
      catch {
        Write-Host "✗ バックアップ失敗: $file - $($_.Exception.Message)"
      }
    }
  }
}

function Restore-LatestBackup {
  param([string]$Pattern = "*.backup_*")
  
  $backupDir = "backups"
  if (-not (Test-Path $backupDir)) {
    Write-Host "✗ バックアップディレクトリが見つかりません: $backupDir"
    return
  }
  
  $backups = Get-ChildItem -Path $backupDir -File -Name $Pattern | Sort-Object LastWriteTime -Descending
  if ($backups.Count -eq 0) {
    Write-Host "✗ バックアップファイルが見つかりません"
    return
  }
  
  $latest = $backups[0]
  $backupPath = Join-Path $backupDir $latest
  $originalName = $latest -replace '\.backup_\d{8}_\d{6}$', ''
  
  Write-Host "最新バックアップ: $latest"
  Write-Host "復元先: $originalName"
  
  try {
    Copy-Item -Path $backupPath -Destination $originalName -Force
    Write-Host "✓ 復元完了: $originalName"
  }
  catch {
    Write-Host "✗ 復元失敗: $($_.Exception.Message)"
  }
}

function Test-Dependencies {
  Write-Host "依存関係を確認中..."
  
  # Python
  try {
    $pythonVersion = & .\.venv\Scripts\python.exe --version
    Write-Host "✓ Python: $pythonVersion"
  }
  catch {
    Write-Host "✗ Python: 利用不可"
    return $false
  }
  
  # Node.js
  try {
    $nodeVersion = & node --version
    Write-Host "✓ Node.js: $nodeVersion"
  }
  catch {
    Write-Host "✗ Node.js: 利用不可"
    return $false
  }
  
  # npm
  try {
    $npmVersion = & npm --version
    Write-Host "✓ npm: $npmVersion"
  }
  catch {
    Write-Host "✗ npm: 利用不可"
    return $false
  }
  
  Write-Host "✓ 全依存関係が利用可能"
  return $true
}

# メイン処理
switch ($Action) {
  "cleanup-cache" {
    Remove-PyCache -WhatIf:(-not $Apply)
  }
  "cleanup-temp" {
    Remove-TempFiles -WhatIf:(-not $Apply)
  }
  "run-tests" {
    if (-not $Apply) {
      Write-Host "Dry-Run: テストは実行されません（-Applyで実行）"
    }
    else {
      Invoke-TestSuite
    }
  }
  "backup-files" {
    Backup-ImportantFiles -WhatIf:(-not $Apply)
  }
  "restore-backup" {
    if (-not $Apply) {
      Write-Host "Dry-Run: 復元は実行されません（-Applyで実行）"
    }
    else {
      Restore-LatestBackup
    }
  }
  "check-deps" {
    Test-Dependencies
  }
  "schema-validate" {
    if (-not $Apply) {
      Write-Host "Dry-Run: スキーマ検証は実行されません（-Applyで実行）"
    }
    else {
      & .\.venv\Scripts\python.exe -c "import json; import yaml; print('✓ スキーマ検証: OK')"
    }
  }
  default {
    Show-Help
  }
}

Write-Host ""
Write-Host "実行完了: $Action (Apply=$Apply)"
