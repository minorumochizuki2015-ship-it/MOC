function Get-AutoRulesStore {
  $path = Join-Path (Get-Location) 'auto_rules.json'
  if (Test-Path $path) {
    $raw = Get-Content $path -Raw | ConvertFrom-Json
  } else {
    $raw = [pscustomobject]@{ version = '1.0'; rules = @{} }
  }
  # PS5.1: PSCustomObject.rules -> Hashtable へ
  $rules = @{}
  if ($raw.rules -is [hashtable]) { $rules = $raw.rules }
  else {
    $raw.rules.PSObject.Properties | ForEach-Object { $rules[$_.Name] = $_.Value }
  }
  return @{ path = $path; raw = $raw; rules = $rules }
}

function Save-AutoRulesStore($store) {
  $store.raw.rules = $store.rules
  $store.raw | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $store.path
}

function Add-AutoRule {
  param(
    [Parameter(Mandatory)][string]$Kind,
    [Parameter(Mandatory)][string]$Signature,
    [hashtable]$Meta
  )
  $store = Get-AutoRulesStore
  $rules = $store.rules

  # 既存シグネチャを検索
  $hit = $null
  foreach ($kv in $rules.GetEnumerator()) {
    if ($kv.Value.signature -eq $Signature) { $hit = $kv; break }
  }

  $now = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
  if ($hit) {
    $hit.Value.count     = [int]($hit.Value.count) + 1
    $hit.Value.last_seen = $now
    if ($Meta) { $hit.Value.meta = ($hit.Value.meta + $Meta) }
  } else {
    # 決定的なキー（MD5 of signature 先頭16）
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $sigBytes = [System.Text.Encoding]::UTF8.GetBytes($Signature)
    $hash = ($md5.ComputeHash($sigBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    $id = $hash.Substring(0,16)
    $rules[$id] = [pscustomobject]@{
      kind       = $Kind
      signature  = $Signature
      first_seen = $now
      last_seen  = $now
      count      = 1
      meta       = $Meta
    }
  }
  Save-AutoRulesStore $store
}

function Show-AutoRules {
  param([int]$Top = 10)
  $store = Get-AutoRulesStore
  $list = @()
  foreach ($kv in $store.rules.GetEnumerator()) {
    $list += [pscustomobject]@{
      id        = $kv.Key
      kind      = $kv.Value.kind
      count     = [int]$kv.Value.count
      firstSeen = $kv.Value.first_seen
      lastSeen  = $kv.Value.last_seen
      signature = $kv.Value.signature
    }
  }
  $list | Sort-Object lastSeen -Descending |
    Select-Object -First $Top id,kind,count,
      @{N='signature';E={ $_.signature.Substring(0,[Math]::Min(60,$_.signature.Length)) }} |
    Format-Table -AutoSize
}

function Export-AutoRulesCsv {
  param([string]$Path = (Join-Path (Get-Location) 'auto_rules.csv'))
  $store = Get-AutoRulesStore
  $list = @()
  foreach ($kv in $store.rules.GetEnumerator()) {
    $v = $kv.Value
    $list += [pscustomobject]@{
      id        = $kv.Key
      kind      = $v.kind
      count     = [int]$v.count
      firstSeen = $v.first_seen
      lastSeen  = $v.last_seen
      signature = $v.signature
    }
  }
  $list | Sort-Object lastSeen -Descending |
    Export-Csv -NoTypeInformation -Encoding UTF8 $Path
  return $Path
}

Export-ModuleMember -Function Add-AutoRule, Show-AutoRules, Export-AutoRulesCsv, Get-AutoRulesStore
