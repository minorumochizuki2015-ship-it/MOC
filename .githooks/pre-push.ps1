#requires -version 5.1
$ErrorActionPreference = 'Stop'
$PSStyle.OutputRendering = 'PlainText'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$base = $env:OPENAI_COMPAT_BASE; if (-not $base) { $base = 'http://127.0.0.1:8080' }

# 1) LLMサーバのヘルス
$h = & scripts\ops\quick-health.ps1 -Base $base -Quiet
if (-not $h -or -not $h.server_ok -or -not $h.port_open) {
  Write-Error "LLM server not ready at $base"
  exit 1
}

# 2) ミニ回帰（ツールモード・短時間）
& .\.venv\Scripts\python.exe -X utf8 -u tools\mini_eval.py --mode tools --timeout 15
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

exit 0