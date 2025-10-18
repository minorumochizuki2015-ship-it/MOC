# ORCH-Next 本番環境デプロイスクリプト
# Version: 1.0.0
# Author: WORK
# Date: 2025-10-07

param(
    [switch]$DryRun = $false,
    [switch]$SkipTests = $false,
    [string]$Environment = "production",
    [switch]$Force = $false
)

# エラー時停止
$ErrorActionPreference = "Stop"

# ログ設定
$LogFile = "data\logs\deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

# ダッシュボードポート（環境変数 ORCH_PORT 優先、未設定時は 5001 を既定）
$DashboardPort = if ($env:ORCH_PORT) { $env:ORCH_PORT } else { 5001 }

function Test-Prerequisites {
    Write-Log "前提条件チェック開始"
    
    # Python仮想環境確認
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        throw "Python仮想環境が見つかりません: .venv\Scripts\python.exe"
    }
    
    # 設定ファイル確認
    if (-not (Test-Path "config\monitoring.json")) {
        throw "監視設定ファイルが見つかりません: config\monitoring.json"
    }
    
    # 必須ディレクトリ作成
    @("data", "data\logs", "data\metrics", "backups") | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
            Write-Log "ディレクトリ作成: $_"
        }
    }
    
    Write-Log "前提条件チェック完了"
}

function Install-Dependencies {
    Write-Log "依存関係インストール開始"
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] 依存関係インストールをスキップ"
        return
    }
    
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    
    Write-Log "依存関係インストール完了"
}

function Run-Tests {
    if ($SkipTests) {
        Write-Log "テスト実行をスキップ"
        return $true
    }
    
    Write-Log "統合テスト実行開始"
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] テスト実行をスキップ"
        return $true
    }
    
    try {
        $env:PYTHONPATH = $PWD.Path
        $TestResult = & .\.venv\Scripts\python.exe quick_integration_test.py
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "統合テスト成功"
            return $true
        } else {
            Write-Log "統合テスト失敗" "ERROR"
            return $false
        }
    } catch {
        Write-Log "統合テスト実行エラー: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-AISystem {
    Write-Log "AI予測システム起動開始"
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] AI予測システム起動をスキップ"
        return
    }
    
    try {
        $env:PYTHONPATH = $PWD.Path
        & .\.venv\Scripts\python.exe -c "from src.ai_prediction import QualityPredictor; ai = QualityPredictor(); ai.train_model(); print('AI予測システム準備完了')"
        Write-Log "AI予測システム起動完了"
    } catch {
        Write-Log "AI予測システム起動エラー: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-MonitoringSystem {
    Write-Log "監視システム起動開始"
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] 監視システム起動をスキップ"
        return
    }
    
    try {
        $env:PYTHONPATH = $PWD.Path
        $MonitorJob = Start-Job -ScriptBlock {
            param($WorkingDir)
            Set-Location $WorkingDir
            $env:PYTHONPATH = $WorkingDir
            & .\.venv\Scripts\python.exe -c "from src.monitoring_system import MonitoringSystem; m = MonitoringSystem(); m.start_monitoring()"
        } -ArgumentList $PWD.Path
        
        Write-Log "監視システムバックグラウンド起動完了 (Job ID: $($MonitorJob.Id))"
        return $MonitorJob
    } catch {
        Write-Log "監視システム起動エラー: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-Dashboard {
    Write-Log "ダッシュボード起動開始"
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] ダッシュボード起動をスキップ"
        return
    }
    
    try {
        $env:PYTHONPATH = $PWD.Path
        $DashboardJob = Start-Job -ScriptBlock {
            param($WorkingDir)
            Set-Location $WorkingDir
            $env:PYTHONPATH = $WorkingDir
            & .\.venv\Scripts\python.exe src\dashboard.py
        } -ArgumentList $PWD.Path
        
        # 起動確認（5秒待機）
        Start-Sleep -Seconds 5
        try {
            $Response = Invoke-WebRequest -Uri "http://localhost:$DashboardPort" -TimeoutSec 10
            if ($Response.StatusCode -eq 200) {
                Write-Log "ダッシュボード起動確認完了 (http://localhost:$DashboardPort)"
            }
        } catch {
            Write-Log "ダッシュボード接続確認失敗: $($_.Exception.Message)" "WARN"
        }
        
        Write-Log "ダッシュボード起動完了 (Job ID: $($DashboardJob.Id))"
        return $DashboardJob
    } catch {
        Write-Log "ダッシュボード起動エラー: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Create-Backup {
    Write-Log "バックアップ作成開始"
    
    $BackupDir = "backups\deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    
    # 重要ファイルのバックアップ
    @("config", "data", "src") | ForEach-Object {
        if (Test-Path $_) {
            Copy-Item -Path $_ -Destination "$BackupDir\" -Recurse -Force
            Write-Log "バックアップ作成: $_ -> $BackupDir"
        }
    }
    
    Write-Log "バックアップ作成完了: $BackupDir"
    return $BackupDir
}

function Show-Status {
    Write-Log "システム状態確認"
    
    # プロセス確認
    $Jobs = Get-Job | Where-Object { $_.State -eq "Running" }
    Write-Log "実行中ジョブ数: $($Jobs.Count)"
    
    # ポート確認
    try {
        $Response = Invoke-WebRequest -Uri "http://localhost:$DashboardPort" -TimeoutSec 5
        Write-Log "ダッシュボード: 正常 (HTTP $($Response.StatusCode))"
    } catch {
        Write-Log "ダッシュボード: 接続不可" "WARN"
    }
    
    # ディスク使用量
    $DiskUsage = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
    $FreeSpaceGB = [math]::Round($DiskUsage.FreeSpace / 1GB, 2)
    Write-Log "ディスク空き容量: ${FreeSpaceGB}GB"
}

# メイン処理
try {
    Write-Log "ORCH-Next デプロイメント開始 (Environment: $Environment, DryRun: $DryRun)"
    
    # 前提条件チェック
    Test-Prerequisites
    
    # バックアップ作成
    $BackupPath = Create-Backup
    
    # 依存関係インストール
    Install-Dependencies
    
    # テスト実行
    if (-not (Run-Tests)) {
        if (-not $Force) {
            throw "テスト失敗のためデプロイメントを中止"
        } else {
            Write-Log "テスト失敗を無視してデプロイメント継続 (-Force指定)" "WARN"
        }
    }
    
    if (-not $DryRun) {
        # AI予測システム起動
        Start-AISystem
        
        # 監視システム起動
        $MonitorJob = Start-MonitoringSystem
        
        # ダッシュボード起動
        $DashboardJob = Start-Dashboard
        
        # 状態確認
        Show-Status
        
        Write-Log "デプロイメント完了"
        Write-Log "ダッシュボードURL: http://localhost:$DashboardPort"
        Write-Log "ログファイル: $LogFile"
        Write-Log "バックアップ: $BackupPath"
        
        if ($MonitorJob) {
            Write-Log "監視システムJob ID: $($MonitorJob.Id)"
        }
        if ($DashboardJob) {
            Write-Log "ダッシュボードJob ID: $($DashboardJob.Id)"
        }
        
        Write-Log "システム停止: Get-Job | Stop-Job; Get-Job | Remove-Job"
    } else {
        Write-Log "[DRY-RUN] デプロイメント完了（実際の変更なし）"
    }
    
} catch {
    Write-Log "デプロイメントエラー: $($_.Exception.Message)" "ERROR"
    Write-Log "バックアップから復旧可能: $BackupPath" "INFO"
    exit 1
}