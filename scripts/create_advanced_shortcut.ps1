# 統治核AI v5の詳細な起動アイコンを作成
param(
    [string]$TargetPath = (Get-Location).Path,
    [string]$DesktopPath = [Environment]::GetFolderPath("Desktop")
)

# 1. メイン起動アイコン
$WshShell = New-Object -ComObject WScript.Shell

# 統治核AI v5 - メイン起動
$MainShortcut = $WshShell.CreateShortcut("$DesktopPath\統治核AI v5.lnk")
$MainShortcut.TargetPath = "powershell.exe"
$MainShortcut.Arguments = "-ExecutionPolicy Bypass -File `"$TargetPath\scripts\start_modern_ui.bat`""
$MainShortcut.WorkingDirectory = $TargetPath
$MainShortcut.Description = "統治核AI v5 - Cursor AI同等システム（モダンUI）"
$MainShortcut.Save()

# 2. 開発者用起動アイコン
$DevShortcut = $WshShell.CreateShortcut("$DesktopPath\統治核AI v5 (開発者).lnk")
$DevShortcut.TargetPath = "cmd.exe"
$DevShortcut.Arguments = "/k `"cd /d $TargetPath`""
$DevShortcut.WorkingDirectory = $TargetPath
$DevShortcut.Description = "統治核AI v5 - 開発者モード（コンソール表示）"
$DevShortcut.Save()

# 3. 設定フォルダを開くアイコン
$ConfigShortcut = $WshShell.CreateShortcut("$DesktopPath\統治核AI v5 設定.lnk")
$ConfigShortcut.TargetPath = "explorer.exe"
$ConfigShortcut.Arguments = "`"$TargetPath\config`""
$ConfigShortcut.WorkingDirectory = $TargetPath
$ConfigShortcut.Description = "統治核AI v5 - 設定フォルダを開く"
$ConfigShortcut.Save()

# 4. ドキュメントを開くアイコン
$DocsShortcut = $WshShell.CreateShortcut("$DesktopPath\統治核AI v5 ドキュメント.lnk")
$DocsShortcut.TargetPath = "explorer.exe"
$DocsShortcut.Arguments = "`"$TargetPath\docs`""
$DocsShortcut.WorkingDirectory = $TargetPath
$DocsShortcut.Description = "統治核AI v5 - ドキュメントフォルダを開く"
$DocsShortcut.Save()

Write-Host "=== 統治核AI v5 デスクトップアイコン作成完了 ==="
Write-Host "作成されたアイコン:"
Write-Host "  1. 統治核AI v5.lnk - メイン起動"
Write-Host "  2. 統治核AI v5 (開発者).lnk - 開発者モード"
Write-Host "  3. 統治核AI v5 設定.lnk - 設定フォルダ"
Write-Host "  4. 統治核AI v5 ドキュメント.lnk - ドキュメント"
Write-Host ""
Write-Host "場所: $DesktopPath"
Write-Host "対象プロジェクト: $TargetPath"
