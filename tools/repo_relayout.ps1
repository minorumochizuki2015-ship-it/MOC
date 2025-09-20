# tools/repo_relayout.ps1
$ErrorActionPreference='Stop'

Write-Host "=== リポジトリ整理開始 ===" -ForegroundColor Green

# 移動マップ定義
$map = @{
  "README.md"="docs"
  "AI_SHARING_README.md"="docs"
  "manual_test_guide.md"="docs"
  "PROGRESS_SUMMARY.md"="docs"
  "work_rules_lessons_learned.md"="docs"
  "test_button_stability.py"="tests\ui"
  "incremental_test.py"="tests\integration"
  "debug_server_connection.py"="tests\integration"
  "test_docker_startup.py"="tests\integration"
  "simple_test.py"="tests\unit"
  "validation_tests.py"="tests\unit"
  "cr_verify.py"="tests\unit"
  "lintcheck.py"="tests\unit"
  "ultimate_cleanup.py"="tools"
  "robust_test_system.py"="tools"
  "reset_conversation.py"="tools"
  "analyze_kernel_structure.py"="tools"
  "apply_patches.py"="tools"
  "create_auto_execution_system.py"="tools"
  "create_stable_launcher.py"="tools"
  "create_startup_scripts.py"="tools"
  "fix_server_connection.ps1"="scripts\server"
  "cursor-workflow.ps1"="scripts\ops"
  "bench_cpu.json"="data\benchmarks"
  "bench_gpu.json"="data\benchmarks"
  "commitlint.config.js"="config"
  "package.json"="config"
  "package-lock.json"="config"
  "mypy.ini"="config"
  "pyproject.toml"="config"
  "requirements.txt"="config"
  "requirements_localai.txt"="config"
}

# ディレクトリ作成
$directories = @("docs", "tests\ui", "tests\integration", "tests\unit", "config", "data\benchmarks")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "✓ ディレクトリ作成: $dir" -ForegroundColor Yellow
    }
}

# ファイル移動
$moved = 0
$map.GetEnumerator() | ForEach-Object {
    $src = Join-Path -Path "." -ChildPath $_.Key
    if (Test-Path $src) {
        $dstDir = $_.Value
        $dstFile = Join-Path $dstDir (Split-Path $src -Leaf)
        
        try {
            git mv $src $dstFile
            Write-Host "✓ 移動: $($_.Key) → $dstFile" -ForegroundColor Green
            $moved++
        } catch {
            Write-Host "❌ 移動失敗: $($_.Key) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 30日超バックアップの掃除
if (Test-Path "backups") {
    $oldBackups = Get-ChildItem backups -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
    if ($oldBackups) {
        $oldBackups | Remove-Item -Force -Recurse
        Write-Host "✓ 古いバックアップ削除: $($oldBackups.Count) ファイル" -ForegroundColor Yellow
    }
}

Write-Host "=== 整理完了: $moved ファイル移動 ===" -ForegroundColor Green
