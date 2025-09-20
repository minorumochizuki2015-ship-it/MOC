$ErrorActionPreference='Stop'
python -X utf8 -u tools/quick_diagnose.py
if($LASTEXITCODE -eq 0){ Write-Host "[OK]"; exit 0 }
elseif($LASTEXITCODE -eq 1){ Write-Warning "[WARN]"; exit 1 }
else{ Write-Error "[ERR]"; exit 2 }
