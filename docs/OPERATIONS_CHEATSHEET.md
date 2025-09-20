# 運用チートシート（超短縮版）

## 🚀 即時実行コマンド

### 1) ヘルス & 回帰チェック（1-15秒）

```powershell
# 軽量チェック（推奨）
.\scripts\ops\quick-health.ps1

# 重いチェック（夜間用）
.\scripts\ops\quick-health.ps1 -Mode agent -Timeout 45

# ベースライン比較付き
.\scripts\ops\quick-health.ps1 -Baseline
```

### 2) 学習トリガー

```powershell
# 学習計画のみ生成
.\scripts\ops\train-trigger.ps1 -PlanOnly

# 実学習実行
.\scripts\ops\train-trigger.ps1

# ドライラン
.\scripts\ops\train-trigger.ps1 -DryRun
```

### 3) データ収集自走設定

```powershell
# 30分毎に設定（推奨）
.\scripts\ops\setup-data-collection.ps1 -Interval 30

# 1時間毎に設定
.\scripts\ops\setup-data-collection.ps1 -Interval 60

# 設定削除
.\scripts\ops\setup-data-collection.ps1 -Remove
```

### 4) 継続運用監視

```powershell
# 状態確認
.\scripts\ops\monitor-status.ps1

# 自動修正付き
.\scripts\ops\monitor-status.ps1 -Fix

# ログローテーション付き
.\scripts\ops\monitor-status.ps1 -LogRotate
```

### 5) ロールバック

```powershell
# 自動ベースライン復元
.\scripts\ops\quick-rollback.ps1

# 特定タグに復元
.\scripts\ops\quick-rollback.ps1 -Tag mini-eval-ok-20250920

# ドライラン
.\scripts\ops\quick-rollback.ps1 -DryRun

# 検証付き
.\scripts\ops\quick-rollback.ps1 -Verify
```

## 📊 継続運用の見るポイント

### 必須チェック項目

1. **Git hooksPath**: `.githooks` に設定されているか
   ```powershell
   git config core.hooksPath
   ```

2. **環境変数**: 日常=tools/15、夜間=agent/45
   ```powershell
   echo $env:MINI_EVAL_MODE
   echo $env:MINI_EVAL_TIMEOUT
   ```

3. **学習成果**: `dist/lora/*` に配置されているか
   ```powershell
   Get-ChildItem dist\lora -File | Format-Table Name, Length, LastWriteTime
   ```

4. **ログ肥大**: `data/logs/**` が100MB超えていないか
   ```powershell
   (Get-ChildItem data\logs -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB
   ```

### 自動化設定例

```powershell
# データ収集（30分毎）
SCHTASKS /Create /TN "gc-data-loop" /SC MINUTE /MO 30 `
  /TR "powershell -ExecutionPolicy Bypass -File `"%CD%\scripts\data-collection-loop.ps1`"" /F

# 夜間評価（毎日2:30）
SCHTASKS /Create /TN "gc-nightly-eval" /SC DAILY /ST 02:30 `
  /TR "powershell -ExecutionPolicy Bypass -File `"%CD%\.githooks\nightly-eval.ps1`"" /F

# ログローテーション（毎週日曜2:00）
SCHTASKS /Create /TN "gc-log-rotate" /SC WEEKLY /D SUN /ST 02:00 `
  /TR "powershell -ExecutionPolicy Bypass -File `"%CD%\scripts\ops\monitor-status.ps1` -LogRotate" /F
```

## 🔧 トラブルシューティング

### 詰まった時の順序

1. **状況固定**: `.\scripts\ops\quick-health.ps1`
2. **原因切り分け**: `.\tools\quick_diagnose.py`
3. **詳細診断**: `.\scripts\ops\monitor-status.ps1 -Fix`

### よくある問題と解決

| 問題 | 症状 | 解決 |
|------|------|------|
| hooksPath未設定 | pre-commit動作しない | `git config core.hooksPath .githooks` |
| 環境変数未設定 | mini_eval失敗 | `$env:MINI_EVAL_MODE="tools"` |
| ログ肥大 | ディスク容量不足 | `.\scripts\ops\monitor-status.ps1 -LogRotate` |
| 学習失敗 | スコア低下 | `.\scripts\ops\quick-rollback.ps1` |

## 📈 次ステップ（推奨順序）

1. **データ収集タスクを常時稼働**
   ```powershell
   .\scripts\ops\setup-data-collection.ps1 -Interval 30
   ```

2. **ローカルトレーナーの実体接続**
   ```powershell
   $env:LOCAL_LORA_TRAINER = "python scripts\trainer\real_trainer.py --train {train} --val {val} --out {outdir}"
   ```

3. **夜間失敗時の自動ロールバック**
   ```powershell
   # .githooks/nightly-eval.ps1 の最後に追加
   if ($score -lt 5) { & .\scripts\ops\quick-rollback.ps1 -Verify }
   ```

## 🎯 運用フロー

### 日常運用
1. `.\scripts\ops\quick-health.ps1` でヘルスチェック
2. 問題があれば `.\scripts\ops\monitor-status.ps1 -Fix` で修正
3. 学習が必要なら `.\scripts\ops\train-trigger.ps1` で実行

### 夜間運用
1. 自動データ収集（30分毎）
2. 自動夜間評価（毎日2:30）
3. 失敗時は自動ロールバック

### 週次運用
1. `.\scripts\ops\monitor-status.ps1 -LogRotate` でログローテーション
2. 学習成果の確認と置換
3. ベースラインタグの更新

---

**💡 ヒント**: 何か詰まったら、まず `.\scripts\ops\quick-health.ps1` で状況を把握してから対処しましょう！
