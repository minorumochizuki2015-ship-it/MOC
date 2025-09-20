# データ収集ループのTask Scheduler設定
# 管理者権限で実行してください

$taskName = "gc-data-loop"
$scriptPath = Join-Path $PWD "scripts\data-collection-loop.ps1"
$workingDir = $PWD

Write-Host "Setting up data collection task: $taskName"
Write-Host "Script: $scriptPath"
Write-Host "Working Directory: $workingDir"

# 既存タスクを削除（存在する場合）
schtasks /Delete /TN $taskName /F 2>$null

# 新しいタスクを作成（1時間毎実行）
$command = "powershell -ExecutionPolicy Bypass -File `"$scriptPath`""
schtasks /Create /TN $taskName /TR $command /SC HOURLY /RU SYSTEM /RP "" /F /WD $workingDir

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Data collection task created successfully"
    Write-Host "Task will run every hour from: $workingDir"
}
else {
    Write-Error "❌ Failed to create data collection task"
    exit 1
}

# タスクの確認
Write-Host "`nTask details:"
schtasks /Query /TN $taskName /FO LIST

Write-Host "`nTo start immediately: schtasks /Run /TN $taskName"
Write-Host "To stop: schtasks /End /TN $taskName"
Write-Host "To delete: schtasks /Delete /TN $taskName /F"
