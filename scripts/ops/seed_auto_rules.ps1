param(
  [string]$RulesPath = ".\auto_rules.json",
  [string]$CsvOut    = ".\auto_rules.csv"
)
if (Test-Path $RulesPath) {
  $cmr = Get-Content $RulesPath -Raw | ConvertFrom-Json
  if (-not $cmr.rules) { $cmr = @{ rules = @{} } }
} else { $cmr = @{ rules = @{} } }

function Get-StringId([string]$s) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($s)
  $sha1  = [System.Security.Cryptography.SHA1]::Create()
  (($sha1.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0,12)
}
function Add-Rule([string]$kind, [string]$signature, [hashtable]$fix, [hashtable]$ctx) {
  $id = Get-StringId $signature
  $now = (Get-Date).ToUniversalTime().ToString("s") + "Z"
  if (-not $cmr.rules.$id) {
    $cmr.rules.$id = @{
      kind       = $kind
      signature  = $signature.Substring(0, [Math]::Min($signature.Length, 500))
      count      = 0
      first_seen = $now
    }
  }
  $cmr.rules.$id.last_seen = $now
  $cmr.rules.$id.count     = [int]$cmr.rules.$id.count + 1
  $cmr.rules.$id.fix       = $fix
  $cmr.rules.$id.ctx       = $ctx
  return $id
}

$rules = @(
  @{ kind="INC-CHAT-FORMAT"; signature="Invalid chat handler: auto";
     fix=@{ server_flag="--chat_format qwen"; why="auto未対応系では明示が必要" };
     ctx=@{ component="server"; pkg="llama-cpp-python"; note="0.3.x" } },
  @{ kind="INC-API-ROUTE"; signature="404 Not Found - POST /v1/completions";
     fix=@{ route="/v1/chat/completions"; note="Chat Completions を使う" };
     ctx=@{ component="client"; api="openai-compat" } },
  @{ kind="INC-BASEURL"; signature="Incorrect API key provided: sk-local";
     fix=@{ base_url="http://127.0.0.1:8080/v1"; note="本家OpenAIに誤送信の疑い／OPENAI_COMPAT_BASE確認" };
     ctx=@{ component="client" } },
  @{ kind="INC-BODY-FORMAT"; signature="Input should be a valid dictionary or object (type= 'model_attributes_type')";
     fix=@{ content_type="application/json"; powershell="ConvertTo-Json -Depth 5"; note="JSONボディとContent-Typeを明示" };
     ctx=@{ component="client"; tool="PowerShell Invoke-RestMethod" } },
  @{ kind="INC-CONNECTION"; signature="リモート サーバーに接続できません";
     fix=@{ check="Test-NetConnection 127.0.0.1 -Port 8080"; start="llama_cpp.server 起動"; note="未起動/到達不能" };
     ctx=@{ component="network" } },
  @{ kind="INC-PROXY"; signature="Proxy/環境変数が原因で127.0.0.1へ到達不可";
     fix=@{ NO_PROXY="127.0.0.1,localhost"; HTTP_PROXY=""; HTTPS_PROXY="" };
     ctx=@{ component="network" } },
  @{ kind="INC-ENCODING"; signature="文字化け(Mojibake)";
     fix=@{ ps_console='[Console]::OutputEncoding=[Text.Encoding]::UTF8'; note="PowerShell出力をUTF-8へ" };
     ctx=@{ component="console" } },
  @{ kind="INC-COROUTINE"; signature="'coroutine' object is not callable (server app.py create_chat_completion)";
     fix=@{ action="llama-cpp-pythonを安定版に固定または最新へ上げる"; note="局所改変を戻し再インストール" };
     ctx=@{ component="server"; pkg="llama-cpp-python" } },
  @{ kind="INC-HEADERS"; signature="PowerShell Invoke-WebRequestでAuthorizationヘッダ化失敗";
     fix=@{ how="Invoke-RestMethod -Headers @{ Authorization='Bearer sk-local'; 'Content-Type'='application/json' }" };
     ctx=@{ component="client"; tool="PowerShell" } },
  @{ kind="INC-MODELS"; signature="model id を直接フルパスで渡して失敗";
     fix=@{ advice="まず /v1/models で id を取得その id を chat.completions に渡す";
           example="(irm $base/models -Headers $headers).data[0].id" };
     ctx=@{ component="client" } }
)

$added = @()
foreach ($r in $rules) {
  $id = Add-Rule -kind $r.kind -signature $r.signature -fix $r.fix -ctx $r.ctx
  $added += [pscustomobject]@{ id=$id; kind=$r.kind; signature=$r.signature }
}

$cmr | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $RulesPath

$rows = $cmr.rules.GetEnumerator() | ForEach-Object {
  [pscustomobject]@{
    id        = $_.Key
    kind      = $_.Value.kind
    count     = $_.Value.count
    firstSeen = $_.Value.first_seen
    lastSeen  = $_.Value.last_seen
    signature = $_.Value.signature
    fix       = ($_.Value.fix | ConvertTo-Json -Depth 5 -Compress)
    ctx       = ($_.Value.ctx | ConvertTo-Json -Depth 5 -Compress)
  }
}
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 $CsvOut

$added | Format-Table -AutoSize
Write-Host "Registered -> $RulesPath"
Write-Host "CSV Export -> $CsvOut"


