# ORCH-Next ヘルスチェック・監視スクリプト
# Version: 1.0.0
# Author: WORK
# Date: 2025-10-07

param(
    [switch]$Continuous = $false,
    [int]$IntervalSeconds = 30,
    [string]$ConfigPath = "config\production.json",
    [switch]$AlertOnly = $false,
    [string]$OutputFormat = "console"  # console, json, csv
)

# エラー時継続
$ErrorActionPreference = "Continue"

# 設定読み込み
if (Test-Path $ConfigPath) {
    $Config = Get-Content $ConfigPath | ConvertFrom-Json
} else {
    Write-Warning "設定ファイルが見つかりません: $ConfigPath"
    $Config = @{
        monitoring = @{
            emergency_mode_threshold = @{
                cpu_percent = 85
                memory_percent = 80
                disk_percent = 90
                error_rate_percent = 10
            }
        }
    }
}

function Get-SystemMetrics {
    $Metrics = @{}
    
    try {
        # CPU使用率
        $CPU = Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average
        $Metrics.cpu_percent = [math]::Round($CPU.Average, 2)
        
        # メモリ使用率
        $OS = Get-WmiObject -Class Win32_OperatingSystem
        $TotalMemory = $OS.TotalVisibleMemorySize
        $FreeMemory = $OS.FreePhysicalMemory
        $UsedMemory = $TotalMemory - $FreeMemory
        $Metrics.memory_percent = [math]::Round(($UsedMemory / $TotalMemory) * 100, 2)
        $Metrics.memory_used_gb = [math]::Round($UsedMemory / 1MB, 2)
        $Metrics.memory_total_gb = [math]::Round($TotalMemory / 1MB, 2)
        
        # ディスク使用率
        $Disk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
        $Metrics.disk_percent = [math]::Round((($Disk.Size - $Disk.FreeSpace) / $Disk.Size) * 100, 2)
        $Metrics.disk_free_gb = [math]::Round($Disk.FreeSpace / 1GB, 2)
        $Metrics.disk_total_gb = [math]::Round($Disk.Size / 1GB, 2)
        
        # プロセス情報
        $PythonProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue
        $Metrics.python_processes = $PythonProcesses.Count
        if ($PythonProcesses) {
            $Metrics.python_memory_mb = [math]::Round(($PythonProcesses | Measure-Object -Property WorkingSet -Sum).Sum / 1MB, 2)
        } else {
            $Metrics.python_memory_mb = 0
        }
        
        # ネットワーク接続
        try {
            $DashboardResponse = Invoke-WebRequest -Uri "http://localhost:5001" -TimeoutSec 5 -UseBasicParsing
            $Metrics.dashboard_status = "OK"
            $Metrics.dashboard_response_code = $DashboardResponse.StatusCode
        } catch {
            $Metrics.dashboard_status = "ERROR"
            $Metrics.dashboard_response_code = 0
            $Metrics.dashboard_error = $_.Exception.Message
        }
        
        # ファイルシステム
        $LogFiles = Get-ChildItem -Path "data\logs" -Filter "*.log" -ErrorAction SilentlyContinue
        $Metrics.log_files_count = $LogFiles.Count
        if ($LogFiles) {
            $Metrics.log_files_size_mb = [math]::Round(($LogFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        } else {
            $Metrics.log_files_size_mb = 0
        }
        
        # データベース
        if (Test-Path "data\orch_production.db") {
            $DBFile = Get-Item "data\orch_production.db"
            $Metrics.database_size_mb = [math]::Round($DBFile.Length / 1MB, 2)
            $Metrics.database_status = "OK"
        } else {
            $Metrics.database_size_mb = 0
            $Metrics.database_status = "MISSING"
        }
        
        # タイムスタンプ
        $Metrics.timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        $Metrics.check_duration_ms = 0  # 後で設定
        
    } catch {
        Write-Error "メトリクス取得エラー: $($_.Exception.Message)"
        $Metrics.error = $_.Exception.Message
    }
    
    return $Metrics
}

function Test-HealthStatus {
    param($Metrics)
    
    $Health = @{
        overall_status = "OK"
        alerts = @()
        warnings = @()
    }
    
    $Thresholds = $Config.monitoring.emergency_mode_threshold
    
    # CPU チェック
    if ($Metrics.cpu_percent -gt $Thresholds.cpu_percent) {
        $Health.alerts += "CPU使用率が閾値を超過: $($Metrics.cpu_percent)% > $($Thresholds.cpu_percent)%"
        $Health.overall_status = "CRITICAL"
    } elseif ($Metrics.cpu_percent -gt ($Thresholds.cpu_percent * 0.8)) {
        $Health.warnings += "CPU使用率が警告レベル: $($Metrics.cpu_percent)%"
    }
    
    # メモリ チェック
    if ($Metrics.memory_percent -gt $Thresholds.memory_percent) {
        $Health.alerts += "メモリ使用率が閾値を超過: $($Metrics.memory_percent)% > $($Thresholds.memory_percent)%"
        $Health.overall_status = "CRITICAL"
    } elseif ($Metrics.memory_percent -gt ($Thresholds.memory_percent * 0.8)) {
        $Health.warnings += "メモリ使用率が警告レベル: $($Metrics.memory_percent)%"
    }
    
    # ディスク チェック
    if ($Metrics.disk_percent -gt $Thresholds.disk_percent) {
        $Health.alerts += "ディスク使用率が閾値を超過: $($Metrics.disk_percent)% > $($Thresholds.disk_percent)%"
        $Health.overall_status = "CRITICAL"
    } elseif ($Metrics.disk_percent -gt ($Thresholds.disk_percent * 0.8)) {
        $Health.warnings += "ディスク使用率が警告レベル: $($Metrics.disk_percent)%"
    }
    
    # ダッシュボード チェック
    if ($Metrics.dashboard_status -ne "OK") {
        $Health.alerts += "ダッシュボードが応答しません: $($Metrics.dashboard_error)"
        $Health.overall_status = "CRITICAL"
    }
    
    # データベース チェック
    if ($Metrics.database_status -ne "OK") {
        $Health.alerts += "データベースファイルが見つかりません"
        $Health.overall_status = "CRITICAL"
    }
    
    # Python プロセス チェック
    if ($Metrics.python_processes -eq 0) {
        $Health.warnings += "Pythonプロセスが実行されていません"
    }
    
    return $Health
}

function Write-Output {
    param($Metrics, $Health)
    
    switch ($OutputFormat.ToLower()) {
        "json" {
            $Output = @{
                metrics = $Metrics
                health = $Health
            }
            $Output | ConvertTo-Json -Depth 3
        }
        "csv" {
            $CsvData = [PSCustomObject]@{
                Timestamp = $Metrics.timestamp
                OverallStatus = $Health.overall_status
                CPUPercent = $Metrics.cpu_percent
                MemoryPercent = $Metrics.memory_percent
                DiskPercent = $Metrics.disk_percent
                DashboardStatus = $Metrics.dashboard_status
                DatabaseStatus = $Metrics.database_status
                PythonProcesses = $Metrics.python_processes
                AlertCount = $Health.alerts.Count
                WarningCount = $Health.warnings.Count
            }
            $CsvData | ConvertTo-Csv -NoTypeInformation
        }
        default {
            # コンソール出力
            if (-not $AlertOnly -or $Health.overall_status -ne "OK") {
                Write-Host "=== ORCH-Next ヘルスチェック ===" -ForegroundColor Cyan
                Write-Host "時刻: $($Metrics.timestamp)"
                Write-Host "全体状態: $($Health.overall_status)" -ForegroundColor $(if ($Health.overall_status -eq "OK") { "Green" } else { "Red" })
                Write-Host ""
                
                Write-Host "システムメトリクス:" -ForegroundColor Yellow
                Write-Host "  CPU使用率: $($Metrics.cpu_percent)%"
                Write-Host "  メモリ使用率: $($Metrics.memory_percent)% ($($Metrics.memory_used_gb)GB / $($Metrics.memory_total_gb)GB)"
                Write-Host "  ディスク使用率: $($Metrics.disk_percent)% (空き: $($Metrics.disk_free_gb)GB)"
                Write-Host "  Pythonプロセス: $($Metrics.python_processes)個 ($($Metrics.python_memory_mb)MB)"
                Write-Host ""
                
                Write-Host "サービス状態:" -ForegroundColor Yellow
                Write-Host "  ダッシュボード: $($Metrics.dashboard_status) (HTTP $($Metrics.dashboard_response_code))"
                Write-Host "  データベース: $($Metrics.database_status) ($($Metrics.database_size_mb)MB)"
                Write-Host "  ログファイル: $($Metrics.log_files_count)個 ($($Metrics.log_files_size_mb)MB)"
                Write-Host ""
                
                if ($Health.alerts.Count -gt 0) {
                    Write-Host "🚨 アラート:" -ForegroundColor Red
                    $Health.alerts | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                    Write-Host ""
                }
                
                if ($Health.warnings.Count -gt 0) {
                    Write-Host "⚠️  警告:" -ForegroundColor Yellow
                    $Health.warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                    Write-Host ""
                }
                
                if ($Health.overall_status -eq "OK" -and $Health.warnings.Count -eq 0) {
                    Write-Host "✅ すべて正常です" -ForegroundColor Green
                }
                
                Write-Host "================================" -ForegroundColor Cyan
                Write-Host ""
            }
        }
    }
}

function Save-Metrics {
    param($Metrics, $Health)
    
    # メトリクスファイルに保存
    $MetricsFile = "data\metrics\health_$(Get-Date -Format 'yyyyMMdd').json"
    New-Item -Path (Split-Path $MetricsFile) -ItemType Directory -Force | Out-Null
    
    $LogEntry = @{
        timestamp = $Metrics.timestamp
        metrics = $Metrics
        health = $Health
    }
    
    Add-Content -Path $MetricsFile -Value ($LogEntry | ConvertTo-Json -Compress)
}

# メイン処理
do {
    $StartTime = Get-Date
    
    try {
        # メトリクス取得
        $Metrics = Get-SystemMetrics
        $Metrics.check_duration_ms = [math]::Round(((Get-Date) - $StartTime).TotalMilliseconds, 2)
        
        # ヘルス判定
        $Health = Test-HealthStatus -Metrics $Metrics
        
        # 出力
        Write-Output -Metrics $Metrics -Health $Health
        
        # メトリクス保存
        Save-Metrics -Metrics $Metrics -Health $Health
        
        # アラート時の追加処理
        if ($Health.overall_status -eq "CRITICAL") {
            # 緊急時ログ
            $AlertLog = "data\logs\alerts_$(Get-Date -Format 'yyyyMMdd').log"
            $AlertEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [CRITICAL] $($Health.alerts -join '; ')"
            Add-Content -Path $AlertLog -Value $AlertEntry
        }
        
    } catch {
        Write-Error "ヘルスチェック実行エラー: $($_.Exception.Message)"
    }
    
    if ($Continuous) {
        Start-Sleep -Seconds $IntervalSeconds
    }
    
} while ($Continuous)

Write-Host "ヘルスチェック完了" -ForegroundColor Green