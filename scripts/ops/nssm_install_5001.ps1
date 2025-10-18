param(
  [switch]$Apply,
  [int]$Port = 5001,
  [string]$SvcName = "ORCHNextDashboard",
  [string]$McpToken = $env:ORCH_MCP_TOKEN
)

$Root   = Resolve-Path .
$Svc    = $SvcName
$NSSM   = Join-Path $Root "nssm\nssm-2.24\win64\nssm.exe"
$Py     = Join-Path $Root ".venv\Scripts\python.exe"
$Work   = $Root.Path
$Stdout = Join-Path $Root "data\logs\current\service_stdout.log"
$Stderr = Join-Path $Root "data\logs\current\service_stderr.log"
$LogDir = Join-Path $Root "data\logs\current"
# MCP token validation: require explicit token for service install
if (-not $McpToken -or $McpToken.Trim().Length -eq 0) {
  if ($Apply) {
    Write-Error "ORCH_MCP_TOKEN が未設定です。サービスを安全に構成するため、-McpToken を指定するか環境変数 ORCH_MCP_TOKEN を設定してください。"
    exit 1
  } else {
    Write-Warning "DRY: ORCH_MCP_TOKEN 未設定。実際のインストール時にはトークンが必須です。"
  }
}

if($Apply){
  if(-not (Test-Path $LogDir)){
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  }
  if(-not (Test-Path $Py)){
    try {
      $PyCmd = Get-Command python -ErrorAction Stop
      $Py = $PyCmd.Source
    } catch {
      Write-Error "Python 実行ファイルが見つかりません (.venv または PATH)。"
      exit 1
    }
  }
}
else{
  Write-Output ("DRY: New-Item -ItemType Directory -Force -Path `"$LogDir`"")
  if(-not (Test-Path $Py)){
    Write-Output ("DRY: .venv が未検出のため、システム python を使用予定")
    $PyCmd = Get-Command python -ErrorAction SilentlyContinue
    if($PyCmd){ Write-Output ("DRY: python => " + $PyCmd.Source) }
  }
  # セキュリティ: DRYランでもトークン値は表示しない
  Write-Output ("DRY: ORCH_MCP_TOKEN => (set) (override via -McpToken)")
}

$envExtra = "ORCH_HOST=127.0.0.1;ORCH_PORT=$Port;ORCH_MCP_TOKEN=$McpToken"

$waitressEntry = Join-Path $Root "scripts\ops\waitress_entry.py"
$cmds = @(
  @($NSSM,'install',$Svc,$Py,$waitressEntry),
  @($NSSM,'set',$Svc,'AppDirectory',$Work),
  @($NSSM,'set',$Svc,'AppEnvironmentExtra',$envExtra),
  @($NSSM,'set',$Svc,'AppStdout',$Stdout),
  @($NSSM,'set',$Svc,'AppStderr',$Stderr),
  @($NSSM,'set',$Svc,'AppStdoutCreationDisposition','4'),
  @($NSSM,'set',$Svc,'AppStderrCreationDisposition','4'),
  @($NSSM,'set',$Svc,'AppTimestampLog','1'),
  @($NSSM,'set',$Svc,'AppExit','Default','Restart'),
  @($NSSM,'set',$Svc,'AppThrottle','5000'),
  @($NSSM,'set',$Svc,'Start','SERVICE_AUTO_START'),
  @($NSSM,'set',$Svc,'AppRotateFiles','5'),
  @($NSSM,'set',$Svc,'AppRotateOnline','1'),
  @($NSSM,'set',$Svc,'AppRotateBytes','10485760'),
  @($NSSM,'set',$Svc,'AppRotateSeconds','86400'),
  @($NSSM,'start',$Svc)
)

$cmds | ForEach-Object {
  if($Apply){
    $exe = $_[0]
    $args = @()
    if($_.Count -gt 1){ $args = $_[1..($_.Count-1)] }
    Write-Output ("RUN: " + $exe + " " + ($args -join ' '))
    Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
  }
  else{
    $joined = ($_ | ForEach-Object { '"' + $_ + '"' }) -join ' '
    Write-Output ('DRY: ' + $joined)
  }
}
