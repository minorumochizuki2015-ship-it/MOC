# 学習インテーク・アプリ運用ガイド

## 概要

完全自動化された学習データ収集・管理システム。PC起動後は自動で常駐し、エディタからの即時取り込みで1分以内に自動処理される。

## 自動化フロー

1. **PC起動** → 自動でアプリ常駐
2. **エディタから** → HTTP Push or ファイルDROP
3. **1分以内に** → 自動フィルタ・承認・SFT生成
4. **UIから** → 学習実行・評価・モデル置換

## 運用コマンド

### 一時停止/再開

```powershell
# データ収集ループ停止
SCHTASKS /Change /TN gc-data-loop /DISABLE

# データ収集ループ再開
SCHTASKS /Change /TN gc-data-loop /ENABLE

# インテークアプリ停止
SCHTASKS /Change /TN gc-intake-app /DISABLE

# インテークアプリ再開
SCHTASKS /Change /TN gc-intake-app /ENABLE
```

### ログ確認

```powershell
# データ収集ループログ
Get-Content "data\logs\current\gc-data-loop.log" -Tail 50

# ミニ評価履歴
Get-Content "data\logs\current\mini_eval_history.jsonl" -Tail 10
```

### 状態確認

```powershell
# サービス生存確認
Invoke-RestMethod http://127.0.0.1:8787/healthz

# タスク稼働確認
Get-ScheduledTask gc-* | Get-ScheduledTaskInfo | ft TaskName,NextRunTime,LastTaskResult

# データ状況確認
Write-Host "inbox: $((Get-ChildItem data\intake\inbox -ErrorAction SilentlyContinue).Count) 件"
Write-Host "accepted: $((Get-ChildItem data\intake\accepted -ErrorAction SilentlyContinue).Count) 件"
Write-Host "buckets: $((Get-ChildItem data\intake\buckets -Recurse -File -ErrorAction SilentlyContinue).Count) 件"
```

## トラブルシューティング

### よくある問題

1. **API接続失敗**
   - 原因: `OPENAI_API_KEY`等が環境に残存
   - 解決: `setx OPENAI_API_KEY ""`

2. **タスクが動かない**
   - 原因: スケジュールタスクが無効化されている
   - 解決: `SCHTASKS /Change /TN gc-data-loop /ENABLE`

3. **UIが表示されない**
   - 原因: アプリが起動していない
   - 解決: `.\scripts\ops\start-intake-app.ps1`

### ログファイル

- `data\logs\current\gc-data-loop.log` - データ収集ループログ
- `data\logs\current\mini_eval_history.jsonl` - ミニ評価履歴
- `data\logs\current\intake-app.log` - インテークアプリログ

## エディタ連動

### Cursor

```powershell
# Tasks/Command → Run shell
.\scripts\ops\cursor-integration.ps1
```

### Trae

```powershell
# project_rules.md → 成功/失敗時に実行
.\scripts\ops\trae-integration.ps1
```

## 次の一歩

### 承認も自動化

しきい値超ならaccepted直行するスイッチ化

### 学習の夜間自動

既存の`gc-nightly`の後段に`train_local.py --auto-eval`を追加

## 完全自動化システム

**手動の「対上げ」は不要！完全自動で学習データ収集・管理！**

