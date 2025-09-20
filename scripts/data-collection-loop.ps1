$ErrorActionPreference = 'Stop'
function Find-Python {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'),
        $env:PYTHON, 'py -3', 'python'
    ) | Where-Object { $_ -and $_ -ne '' }
    foreach ($p in $candidates) {
        try { & $p -V *> $null; return $p } catch {}
    }
    throw "Python not found."
}

$py = Find-Python
Write-Host "Data collection loop: safe task execution"

# 安全タスクのリスト（30分毎に1つずつ実行）
$timestamp = Get-Date -Format 'yyyyMMdd_HHmm'
$safe_tasks = @(
    "Create summary of docs/README.md and save to data/outputs/summary_$timestamp.md",
    "List Python files in src/core/ directory and save to data/outputs/core_files_$timestamp.txt",
    "Create description of tools/ directory functions and save to data/outputs/tools_desc_$timestamp.md",
    "List project config files and save to data/outputs/config_files_$timestamp.txt",
    "Analyze recent mini_eval results and save to data/outputs/eval_analysis_$timestamp.md",
    "Create project structure overview and save to data/outputs/structure_$timestamp.md"
)

# 重複率チェック（直近5回のmini_eval履歴を確認）
$historyFile = Join-Path $PSScriptRoot '..\data\logs\current\mini_eval_history.jsonl'
if (Test-Path $historyFile) {
    $recent = Get-Content $historyFile -Tail 5 | ForEach-Object { $_ | ConvertFrom-Json }
    $perfectScores = ($recent | Where-Object { $_.score -eq $_.total }).Count
    if ($perfectScores -eq 5) {
        Write-Host "All recent mini_eval scores are perfect (5/5), running in lightweight mode"
        # 軽量モード: 収集のみ、SFT再生成はスキップ
        $lightweightMode = $true
    } else {
        $lightweightMode = $false
    }
} else {
    $lightweightMode = $false
}

# ランダムにタスクを選択
$task = $safe_tasks | Get-Random
Write-Host "Selected task: $task"

# 安全タスク実行（max-steps 1で制限）
& $py -X utf8 -u tools/agent_cli.py --goal $task --apply --max-steps 1

if ($LASTEXITCODE -eq 0) {
    Write-Host "Task completed successfully"
} else {
    Write-Warning "Task execution failed"
}

# 軽量モードでない場合のみSFT再生成
if (-not $lightweightMode) {
    Write-Host "Regenerating SFT dataset..."
    & $py -X utf8 -u tools/export_sft_dataset.py --min_chars 16 --split 0.9
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SFT regeneration completed"
    } else {
        Write-Error "SFT regeneration failed"
        exit 1
    }
} else {
    Write-Host "Lightweight mode: skipping SFT regeneration"
}

Write-Host "Data collection loop completed"
exit $LASTEXITCODE
