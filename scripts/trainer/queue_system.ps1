# 学習キューシステム（手動→準自動）
param(
    [string]$Action = "status",  # status, add, process, list
    [string]$PlanPath = "",
    [string]$Priority = "normal"  # low, normal, high
)

$queueFile = "data/logs/training/queue.jsonl"
$statusFile = "data/logs/training/status.json"

# キュー管理関数
function Get-Queue {
    if (Test-Path $queueFile) {
        Get-Content $queueFile | ForEach-Object { $_ | ConvertFrom-Json }
    } else {
        @()
    }
}

function Add-ToQueue {
    param($planPath, $priority)
    
    $queue = Get-Queue
    $newJob = @{
        id = [guid]::NewGuid().ToString()
        plan = $planPath
        priority = $priority
        status = "queued"
        created = (Get-Date).ToString('o')
        started = $null
        completed = $null
        error = $null
    }
    
    $queue += $newJob
    $queue | ConvertTo-Json -Depth 3 | Set-Content $queueFile -Encoding UTF8
    Write-Host "✅ Job added to queue: $($newJob.id)"
}

function Process-Queue {
    $queue = Get-Queue
    $running = $queue | Where-Object { $_.status -eq "running" }
    
    if ($running.Count -gt 0) {
        Write-Host "⚠️  Job already running: $($running[0].id)"
        return
    }
    
    $next = $queue | Where-Object { $_.status -eq "queued" } | Sort-Object { $_.priority -eq "high" }, { $_.priority -eq "normal" }, { $_.created } | Select-Object -First 1
    
    if (-not $next) {
        Write-Host "ℹ️  No jobs in queue"
        return
    }
    
    # ジョブを実行中にマーク
    $next.status = "running"
    $next.started = (Get-Date).ToString('o')
    $queue | ConvertTo-Json -Depth 3 | Set-Content $queueFile -Encoding UTF8
    
    Write-Host "🚀 Starting job: $($next.id)"
    
    try {
        # 学習実行
        & (Join-Path $PSScriptRoot "..\trigger-training.ps1")
        
        if ($LASTEXITCODE -eq 0) {
            $next.status = "completed"
            $next.completed = (Get-Date).ToString('o')
            Write-Host "✅ Job completed: $($next.id)"
        } else {
            $next.status = "failed"
            $next.error = "Training failed with exit code $LASTEXITCODE"
            Write-Host "❌ Job failed: $($next.id)"
        }
    }
    catch {
        $next.status = "failed"
        $next.error = $_.Exception.Message
        Write-Host "❌ Job failed: $($next.id) - $($_.Exception.Message)"
    }
    
    # キューを更新
    $queue | ConvertTo-Json -Depth 3 | Set-Content $queueFile -Encoding UTF8
}

# メイン処理
switch ($Action.ToLower()) {
    "add" {
        if (-not $PlanPath) {
            Write-Error "PlanPath is required for add action"
            exit 1
        }
        Add-ToQueue $PlanPath $Priority
    }
    "process" {
        Process-Queue
    }
    "list" {
        $queue = Get-Queue
        if ($queue.Count -eq 0) {
            Write-Host "Queue is empty"
        } else {
            $queue | Format-Table id, status, priority, created, started, completed -AutoSize
        }
    }
    "status" {
        $queue = Get-Queue
        $stats = @{
            total = $queue.Count
            queued = ($queue | Where-Object { $_.status -eq "queued" }).Count
            running = ($queue | Where-Object { $_.status -eq "running" }).Count
            completed = ($queue | Where-Object { $_.status -eq "completed" }).Count
            failed = ($queue | Where-Object { $_.status -eq "failed" }).Count
        }
        $stats | ConvertTo-Json | Write-Host
    }
    default {
        Write-Host "Usage: .\queue_system.ps1 -Action <status|add|process|list> [-PlanPath <path>] [-Priority <low|normal|high>]"
    }
}
