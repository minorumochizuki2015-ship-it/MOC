# デスクトップに起動アイコンを作成するPowerShellスクリプト
param(
    [string]$TargetPath = (Get-Location).Path,
    [string]$DesktopPath = [Environment]::GetFolderPath("Desktop")
)

# 統治核AIの起動ショートカットを作成
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\統治核AI v5.lnk")

# ショートカットの設定
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$TargetPath\scripts\start_modern_ui.bat`""
$Shortcut.WorkingDirectory = $TargetPath
$Shortcut.Description = "統治核AI v5 - Cursor AI同等システム"
$Shortcut.IconLocation = "powershell.exe,0"

# ショートカットを保存
$Shortcut.Save()

Write-Host "デスクトップに起動アイコンを作成しました: 統治核AI v5.lnk"
Write-Host "場所: $DesktopPath"
Write-Host "対象: $TargetPath\scripts\start_modern_ui.bat"
