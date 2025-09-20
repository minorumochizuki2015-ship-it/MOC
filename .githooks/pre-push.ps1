$ErrorActionPreference='Stop'
.\.venv\Scripts\python.exe -X utf8 -u tools/quick_diagnose.py
$ec = $LASTEXITCODE
if($ec -eq 0){ exit 0 }
if($ec -eq 1){ 
    Write-Warning "[WARN] quick_diagnose: Environment/dependencies unresolved"
    exit 1 
}
Write-Error "[ERR] quick_diagnose: Dangerous configuration/implementation detected"
exit 2
