# GoverningCore v5 アンインストーラースクリプト
# 管理者権限で実行してください

param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "=== GoverningCore v5 アンインストーラー ===" -ForegroundColor Red

# 管理者権限チェック
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "管理者権限が必要です。PowerShellを管理者として実行してください。"
    exit 1
}

try {
    # 1. インストールパス取得
    $InstallPath = [Environment]::GetEnvironmentVariable("GOVERNING_CORE_PATH", "Machine")
    if (-not $InstallPath) {
        $InstallPath = "$env:PROGRAMFILES\GoverningCore_v5"
    }

    Write-Host "アンインストール先: $InstallPath" -ForegroundColor Yellow

    if (-not (Test-Path $InstallPath)) {
        Write-Warning "インストール先が見つかりません: $InstallPath"
        exit 0
    }

    # 2. 確認
    if (-not $Force) {
        $response = Read-Host "本当にアンインストールしますか？ (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Host "アンインストールをキャンセルしました。" -ForegroundColor Yellow
            exit 0
        }
    }

    # 3. デスクトップショートカット削除
    Write-Host "デスクトップショートカットを削除中..." -ForegroundColor Yellow
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktop "GoverningCore v5.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Host "デスクトップショートカットを削除しました。" -ForegroundColor Green
    }

    # 4. 環境変数削除
    Write-Host "環境変数を削除中..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("GOVERNING_CORE_PATH", $null, "Machine")

    # 5. インストールディレクトリ削除
    Write-Host "インストールディレクトリを削除中..." -ForegroundColor Yellow
    Remove-Item $InstallPath -Recurse -Force

    Write-Host "`n=== アンインストール完了 ===" -ForegroundColor Green
    Write-Host "GoverningCore v5 が完全に削除されました。" -ForegroundColor Cyan

}
catch {
    Write-Error "アンインストール中にエラーが発生しました: $($_.Exception.Message)"
    exit 1
}

