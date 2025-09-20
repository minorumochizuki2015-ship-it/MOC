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
    "List project config files and save to data/outputs/config_files_$timestamp.txt"
)

# ランダムにタスクを選択
$task = $safe_tasks | Get-Random
Write-Host "Selected task: $task"

# 安全タスク実行（max-steps 1で制限）
& $py -X utf8 -u tools/agent_cli.py --goal $task --apply --max-steps 1

if ($LASTEXITCODE -eq 0) {
    Write-Host "Task completed successfully"
    
    # SFT再生成
    Write-Host "Regenerating SFT dataset..."
    & $py -X utf8 -u tools/export_sft_dataset.py --min_chars 8 --split 0.9
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SFT regeneration completed"
    } else {
        Write-Warning "SFT regeneration failed"
    }
} else {
    Write-Warning "Task execution failed"
}

Write-Host "Data collection loop completed"
exit $LASTEXITCODE
