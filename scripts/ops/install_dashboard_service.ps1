# ORCH-Next Dashboard Windows Service Installer
# 要件: 管理者PowerShell、Python/Waitressインストール済み
# 目的: WaitressベースでダッシュボードをWindowsサービスとして常駐させる
# 実行例: pwsh -File scripts/ops/install_dashboard_service.ps1

param(
  [string]$ServiceName = "ORCHNextDashboard",
  [string]$DisplayName = "ORCH-Next Dashboard",
  [int]$Port = 5001
)

$ErrorActionPreference = 'Stop'

# プロジェクトルート
$root = "C:\Users\User\Trae\ORCH-Next"
Set-Location $root

# Python 実行パス（優先: .venv、フォールバック: システム既定）
$venvPython = Join-Path $root ".venv/Scripts/python.exe"
if (Test-Path $venvPython) {
  $pythonExe = $venvPython
  Write-Host "[use] .venv を使用します: $pythonExe"
} else {
  $pythonExe = (Get-Command python).Source
  if (-not (Test-Path $pythonExe)) { throw "python 実行ファイルが見つかりません: $pythonExe" }
  Write-Host "[use] システム既定の python を使用します: $pythonExe"
}

# 依存確認（選択した python で実施）
Write-Host "[check] waitress インストール確認..."
try {
  & $pythonExe -c "import waitress" | Out-Null
} catch {
  Write-Host "[install] waitress をインストールします" -ForegroundColor Yellow
  & $pythonExe -m pip install waitress
}

# スクリプトパス
$entry = Join-Path $root "scripts/ops/waitress_entry.py"
if (-not (Test-Path $entry)) {
  throw "waitress_entry.py が存在しません: $entry"
}

# ここまでで $pythonExe が決定済み

# 既存サービスがある場合は停止・削除（安全のためプロンプト）
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host "[info] 既存サービスが見つかりました: $ServiceName" -ForegroundColor Yellow
  Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 1
}

# サービス作成
$bin = '"' + $pythonExe + '" "' + $entry + '"'
Write-Host "[create] New-Service -Name $ServiceName -DisplayName '$DisplayName' -BinaryPathName $bin"
New-Service -Name $ServiceName -DisplayName $DisplayName -BinaryPathName $bin -StartupType Automatic

# ポート環境変数をレジストリに設定（サービス専用環境変数）
# 注意: 一部環境では反映に再起動が必要になる可能性があります
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
Set-ItemProperty -Path $svcRegPath -Name "Environment" -Value @("ORCH_PORT=$Port")

# 起動
Start-Service -Name $ServiceName
Write-Host "[done] サービス起動完了。 http://127.0.0.1:$Port/ にアクセスして確認してください。"
