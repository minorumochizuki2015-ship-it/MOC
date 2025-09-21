# GoverningCore v5 インストーラースクリプト
# 管理者権限で実行してください

param(
    [string]$InstallPath = "$env:PROGRAMFILES\GoverningCore_v5",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "=== GoverningCore v5 インストーラー ===" -ForegroundColor Green
Write-Host "インストール先: $InstallPath" -ForegroundColor Yellow

# 管理者権限チェック
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "管理者権限が必要です。PowerShellを管理者として実行してください。"
    exit 1
}

try {
    # 1. インストールディレクトリ作成
    if (Test-Path $InstallPath) {
        if ($Force) {
            Remove-Item $InstallPath -Recurse -Force
        }
        else {
            Write-Error "インストール先が既に存在します: $InstallPath"
            exit 1
        }
    }
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

    # 2. ファイルコピー
    Write-Host "ファイルをコピー中..." -ForegroundColor Yellow
    Copy-Item ".\*" $InstallPath -Recurse -Force

    # 3. 仮想環境作成
    Write-Host "仮想環境を作成中..." -ForegroundColor Yellow
    $venvPath = Join-Path $InstallPath ".venv"
    & python -m venv $venvPath

    # 4. 依存関係インストール
    Write-Host "依存関係をインストール中..." -ForegroundColor Yellow
    $pythonExe = Join-Path $venvPath "Scripts\python.exe"
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install -r (Join-Path $InstallPath "requirements.txt")

    # 5. デスクトップショートカット作成
    Write-Host "デスクトップショートカットを作成中..." -ForegroundColor Yellow
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktop "GoverningCore v5.lnk"
    $targetPath = Join-Path $InstallPath "start_modern_ui.bat"
    
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $targetPath
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description = "GoverningCore v5 - 統治核AIシステム"
    $Shortcut.Save()

    # 6. 環境変数設定
    Write-Host "環境変数を設定中..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("GOVERNING_CORE_PATH", $InstallPath, "Machine")

    Write-Host "`n=== インストール完了 ===" -ForegroundColor Green
    Write-Host "インストール先: $InstallPath" -ForegroundColor Cyan
    Write-Host "デスクトップショートカット: $shortcutPath" -ForegroundColor Cyan
    Write-Host "`n起動方法:" -ForegroundColor Yellow
    Write-Host "1. デスクトップのショートカットをダブルクリック" -ForegroundColor White
    Write-Host "2. または: $targetPath" -ForegroundColor White

}
catch {
    Write-Error "インストール中にエラーが発生しました: $($_.Exception.Message)"
    exit 1
}

