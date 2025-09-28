#requires -Version 7.0
param(
    [switch]$Apply,
    [string]$Label = "$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# パス設定
$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path
$bkDir = Join-Path $root "backups"
$zip = Join-Path $bkDir "checkpoint_$Label.zip"
$logDir = Join-Path $root "data\logs\current"
$logFile = Join-Path $logDir "checkpoint_$(Get-Date -Format 'yyyyMMdd').log"

# ログ関数
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    if (Test-Path $logDir) {
        Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
    }
}

# プリフライトチェック
function Test-Prerequisites {
    $errors = @()
    
    # バックアップディレクトリ作成
    if (-not (Test-Path $bkDir)) {
        New-Item -ItemType Directory $bkDir -Force | Out-Null
        Write-Log "Created backup directory: $bkDir"
    }
    
    # ログディレクトリ作成
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory $logDir -Force | Out-Null
        Write-Log "Created log directory: $logDir"
    }
    
    # Git状態チェック
    try {
        git diff --quiet
        if ($LASTEXITCODE -ne 0) {
            $errors += "Uncommitted changes exist. Please commit or stash changes first."
        }
    }
    catch {
        $errors += "Git is not available or not in a git repository."
    }
    
    # ディスク容量チェック
    try {
        $drive = (Get-Location).Drive
        $freeSpace = (Get-PSDrive $drive.Name).Free
        $freeSpaceGB = [math]::Round($freeSpace / 1GB, 2)
        
        if ($freeSpaceGB -lt 1) {
            $errors += "Low disk space: ${freeSpaceGB}GB available. At least 1GB recommended."
        } else {
            Write-Log "Disk space check passed: ${freeSpaceGB}GB available"
        }
    }
    catch {
        Write-Log "Could not check disk space" "WARN"
    }
    
    # ブランチ状態チェック
    try {
        $currentBranch = git branch --show-current
        Write-Log "Current branch: $currentBranch"
    }
    catch {
        $errors += "Could not determine current git branch."
    }
    
    return $errors
}

# メイン処理
function Invoke-Checkpoint {
    param([bool]$Execute)
    
    Write-Log "Starting checkpoint creation process"
    Write-Log "Label: $Label"
    Write-Log "Target: $zip"
    
    if ($Execute) {
        Write-Log "APPLY MODE: Creating actual checkpoint" "INFO"
        
        try {
            # 一時ディレクトリでアーカイブ作成
            $tempZip = Join-Path $env:TEMP "checkpoint_temp_$Label.zip"
            
            Write-Log "Creating git archive..."
            git archive --format=zip -o $tempZip HEAD
            
            if ($LASTEXITCODE -ne 0) {
                throw "Git archive failed with exit code $LASTEXITCODE"
            }
            
            # 最終的な場所に移動
            Move-Item $tempZip $zip -Force
            Write-Log "Archive created: $zip"
            
            # Gitタグ作成
            $tagName = "pre/$Label"
            Write-Log "Creating git tag: $tagName"
            git tag $tagName -m "checkpoint $Label"
            
            if ($LASTEXITCODE -ne 0) {
                Write-Log "Git tag creation failed, but archive was created successfully" "WARN"
            } else {
                Write-Log "Git tag created successfully: $tagName"
                
                # リモートにプッシュ（オプション）
                try {
                    git push --tags 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "Tags pushed to remote successfully"
                    } else {
                        Write-Log "Could not push tags to remote (this is normal if no remote is configured)" "WARN"
                    }
                }
                catch {
                    Write-Log "Could not push tags to remote: $_" "WARN"
                }
            }
            
            # ファイルサイズ確認
            if (Test-Path $zip) {
                $fileSize = (Get-Item $zip).Length
                $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
                Write-Log "Checkpoint completed successfully. Archive size: ${fileSizeMB}MB"
            }
            
        }
        catch {
            Write-Log "APPLY FAILED: $_" "ERROR"
            
            # クリーンアップ
            if (Test-Path $tempZip) {
                Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
            }
            
            throw $_
        }
    }
    else {
        Write-Log "DRY-RUN MODE: Would create checkpoint but not executing" "INFO"
        Write-Log "Would create archive: $zip"
        Write-Log "Would create git tag: pre/$Label"
        Write-Log "Use -Apply flag to execute actual checkpoint creation"
    }
}

# メイン実行
try {
    Write-Log "=== New-Checkpoint.ps1 Started ==="
    Write-Log "Parameters: Apply=$Apply, Label=$Label"
    
    # プリフライトチェック
    $errors = Test-Prerequisites
    
    if (@($errors).Count -gt 0) {
        Write-Log "PREFLIGHT FAILED:" "ERROR"
        foreach ($error in $errors) {
            Write-Log "  - $error" "ERROR"
        }
        exit 1
    }
    
    Write-Log "Preflight checks passed"
    
    # チェックポイント実行
    Invoke-Checkpoint -Execute $Apply
    
    Write-Log "=== New-Checkpoint.ps1 Completed Successfully ==="
    exit 0
}
catch {
    Write-Log "=== New-Checkpoint.ps1 Failed ===" "ERROR"
    Write-Log "Error: $_" "ERROR"
    exit 1
}