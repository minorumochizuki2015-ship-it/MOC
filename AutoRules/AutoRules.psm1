function Get-AutoRulesStore { param($Root)
  if(-not $Root){ $Root = Split-Path -Parent $PSCommandPath }
  $p = Join-Path $Root "auto_rules.json"
  if(-not (Test-Path $p)){ ConvertTo-Json @{ rules=@() } | Set-Content -Encoding UTF8 $p }
  return $p
}
function Read-AutoRules  { param($Root) $p=Get-AutoRulesStore $Root; (Get-Content $p -Raw | ConvertFrom-Json) }
function Write-AutoRules { param($Obj,$Root) $p=Get-AutoRulesStore $Root; $Obj | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $p }

function Ensure-RulesArray { param([ref]$db)
  if($null -eq $db.Value.rules){
    # 無ければ配列で作る
    if($db.Value.PSObject.Properties.Match('rules').Count -eq 0){
      $db.Value | Add-Member -NotePropertyName rules -NotePropertyValue @()
    } else {
      $db.Value.rules = @()
    }
  } elseif(-not ($db.Value.rules -is [System.Collections.IList] -or $db.Value.rules -is [object[]])) {
    # 単一オブジェクト -> 配列化
    $db.Value.rules = @($db.Value.rules)
  }
}

function Add-AutoRule {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$Kind,
    [Parameter(Mandatory)][string]$Signature,
    [string]$Note, [string]$Root
  )
  $db = Read-AutoRules $Root
  Ensure-RulesArray ([ref]$db)
  $now = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
  $hit = $db.rules | Where-Object { $_.kind -eq $Kind -and $_.signature -eq $Signature } | Select-Object -First 1
  if($hit){ $hit.lastSeen = $now; if($Note){$hit.note=$Note} }
  else    { $db.rules += [pscustomobject]@{ id=[guid]::NewGuid().ToString('n'); kind=$Kind; firstSeen=$now; lastSeen=$now; signature=$Signature; note=$Note } }
  Write-AutoRules $db $Root
}
function Show-AutoRules {
  [CmdletBinding()] param([int]$Top=20,[string]$Root)
  $db = Read-AutoRules $Root
  Ensure-RulesArray ([ref]$db)
  $db.rules | Sort-Object lastSeen -Descending | Select-Object -First $Top id,kind,firstSeen,lastSeen,signature
}
function Export-AutoRulesCsv {
  [CmdletBinding()] param([string]$Path="auto_rules.csv",[string]$Root)
  $db = Read-AutoRules $Root
  Ensure-RulesArray ([ref]$db)
  $db.rules | Sort-Object lastSeen -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 $Path
}
Export-ModuleMember Add-AutoRule,Show-AutoRules,Export-AutoRulesCsv
