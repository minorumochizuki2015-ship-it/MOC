$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot; Set-Location $repo

# 1) 学習インテーク・アプリ稼働チェック
try { Invoke-RestMethod http://127.0.0.1:8787/healthz -TimeoutSec 3 | Out-Null }
catch { Write-Error "intake app down (:8787)"; exit 1 }

# 2) ミニ回帰（満点で通過、失敗でpush停止）
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py --mode tools --timeout 15
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3) 追加ゲート（LLM :8080）※準備できたらアンコメント
# & .\scripts\ops\quick-health.ps1 -Base "http://127.0.0.1:8080" -Quiet `
#   || (Write-Error "LLM :8080 not ready"; exit 1)

exit 0