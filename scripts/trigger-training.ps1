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
Write-Host "Training trigger: LoRA plan generation and execution"

# 学習計画生成
Write-Host "Generating training plan..."
& $py -X utf8 -u tools/train_local.py --plan-only

if ($LASTEXITCODE -ne 0) {
    Write-Error "Training plan generation failed"
    exit 1
}

# 計画ファイルの存在確認
$planFile = "dist/lora/train_plan.json"
if (-not (Test-Path $planFile)) {
    Write-Warning "Training plan file not found: $planFile"
    Write-Host "Creating dummy plan for testing..."
    New-Item -ItemType Directory -Path "dist/lora" -Force | Out-Null
    @{
        "train" = "data/sft/train.jsonl"
        "val" = "data/sft/val.jsonl"
        "epochs" = 1
        "lr" = 2e-4
        "r" = 8
        "bf16" = $false
    } | ConvertTo-Json | Set-Content $planFile -Encoding UTF8
}

Write-Host "Training plan generated: $planFile"

# 外部バックエンドの起動（環境変数から取得）
$trainerCmd = $env:LOCAL_LORA_TRAINER
if (-not $trainerCmd) {
    Write-Warning "LOCAL_LORA_TRAINER not set. Plan generated only."
    Write-Host "To enable training, set: setx LOCAL_LORA_TRAINER 'python scripts/train_lora_local.py --train {train} --val {val} --out {outdir}'"
    exit 0
}

Write-Host "Starting training with: $trainerCmd"
& $py -X utf8 -u tools/train_local.py --trainer-cmd $trainerCmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "Training completed successfully"
} else {
    Write-Warning "Training failed"
}

Write-Host "Training trigger completed"
exit $LASTEXITCODE
