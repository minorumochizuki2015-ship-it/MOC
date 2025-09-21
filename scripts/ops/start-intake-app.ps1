# 学習インテーク・アプリ起動スクリプト
# ローカルWebアプリとして起動

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# パス設定
$here = Split-Path -Parent $PSCommandPath
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$py = Join-Path $repo '.venv\Scripts\python.exe'

# ログ設定
$logDir = Join-Path $repo 'data\logs\current'
$logFile = Join-Path $logDir 'intake-app.log'
New-Item -Path $logDir -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8
}

function Test-Python {
    if (-not (Test-Path $py)) {
        Write-Log "ERROR: Python not found at $py"
        return $false
    }
    return $true
}

function Test-Dependencies {
    Write-Log "依存関係を確認中..."
    try {
        & $py -c "import fastapi, uvicorn, pydantic, jinja2; print('依存関係OK')" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR: 依存関係が不足しています"
            Write-Log "以下のコマンドでインストールしてください:"
            Write-Log "& $py -m pip install fastapi uvicorn pydantic jinja2 python-multipart"
            return $false
        }
        Write-Log "依存関係確認完了"
        return $true
    }
    catch {
        Write-Log "ERROR: 依存関係確認エラー: $($_.Exception.Message)"
        return $false
    }
}

function Start-IntakeApp {
    Write-Log "学習インテーク・アプリを起動中..."
    
    # 作業ディレクトリをリポジトリルートに設定
    Set-Location $repo
    
    # 環境変数設定
    $env:PYTHONPATH = $repo
    $env:MINI_EVAL_MODE = 'tools'
    $env:MINI_EVAL_TIMEOUT = '30'
    $env:AUTO_PROCESS = '1'  # 自動パイプライン有効化
    
    # データディレクトリ作成
    $dataDirs = @(
        'data\intake\inbox',
        'data\intake\queue', 
        'data\intake\accepted',
        'data\intake\rejected',
        'data\intake\buckets\code',
        'data\intake\buckets\write',
        'data\intake\buckets\patent',
        'data\sft_ui'
    )
    
    foreach ($dir in $dataDirs) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "データディレクトリ作成完了"
    
    # API起動
    Write-Log "API起動中... (http://127.0.0.1:8787)"
    Write-Log "UI: http://127.0.0.1:8787/ui"
    Write-Log "API仕様: http://127.0.0.1:8787/docs"

    # 起動時に自動でUIを開く
    Start-Process "http://127.0.0.1:8787/ui/"

    try {
        # uvicornで起動（2ワーカーで自己HTTP待ち回避）
        & $py -X utf8 -u -m uvicorn app.intake_service.api:app --host 127.0.0.1 --port 8787 --workers 2 --timeout-keep-alive 5
    }
    catch {
        Write-Log "ERROR: API起動エラー: $($_.Exception.Message)"
        return $false
    }
}

function Show-Usage {
    Write-Host "学習インテーク・アプリ起動スクリプト" -ForegroundColor Green
    Write-Host ""
    Write-Host "使用方法:" -ForegroundColor Yellow
    Write-Host "  .\scripts\ops\start-intake-app.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "起動後:" -ForegroundColor Yellow
    Write-Host "  UI: http://127.0.0.1:8787/ui" -ForegroundColor White
    Write-Host "  API仕様: http://127.0.0.1:8787/docs" -ForegroundColor White
    Write-Host ""
    Write-Host "停止:" -ForegroundColor Yellow
    Write-Host "  Ctrl+C で停止" -ForegroundColor White
    Write-Host ""
    Write-Host "常駐起動:" -ForegroundColor Yellow
    Write-Host "  SCHTASKS /Create /TN `"gc-intake-app`" /SC ONLOGON /RL HIGHEST /F /TR `"powershell -ExecutionPolicy Bypass -File `"`$PWD\scripts\ops\start-intake-app.ps1`"`"" -ForegroundColor White
}

# メイン処理
try {
    Write-Log "=== 学習インテーク・アプリ起動開始 ==="
    
    # Python確認
    if (-not (Test-Python)) {
        Write-Log "ERROR: Pythonが見つかりません"
        exit 1
    }
    
    # 依存関係確認
    if (-not (Test-Dependencies)) {
        Write-Log "ERROR: 依存関係が不足しています"
        exit 1
    }
    
    # アプリ起動
    Start-IntakeApp
    
    Write-Log "=== 学習インテーク・アプリ起動完了 ==="
}
catch {
    Write-Log "ERROR: 起動エラー: $($_.Exception.Message)"
    exit 1
}
finally {
    Write-Log "アプリケーションを終了します"
}
