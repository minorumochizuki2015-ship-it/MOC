# システム運用ガイド詳細補完

## 概要
**作成日**: 2025-01-11  
**タスクID**: 004-P3  
**担当**: WORK1  
**目的**: Unity Game Projectの日常運用における詳細手順の補完

## 日常運用手順

### 1. 毎日の運用チェック

#### 1.1 システムヘルスチェック
```powershell
# 基本システム状態確認
Get-Process python | Where-Object {$_.ProcessName -eq "python"}
Get-ChildItem .venv/Scripts/python.exe -ErrorAction SilentlyContinue

# Unity プロセス確認
Get-Process Unity* -ErrorAction SilentlyContinue
```

#### 1.2 ログ確認
- **場所**: `data/logs/current/`
- **確認項目**:
  - エラーログの有無
  - パフォーマンス異常
  - セキュリティアラート

#### 1.3 CI/CD状態確認
```bash
# GitHub Actions ワークフロー状態確認
gh workflow list --repo Game_project
gh run list --limit 5
```

### 2. 週次運用手順

#### 2.1 monitor.yml実行確認
- **スケジュール**: 毎週月曜日 09:00 JST
- **確認項目**:
  - ワークフロー正常実行
  - アーティファクト生成確認
  - 監視レポート出力確認

#### 2.2 パフォーマンステスト
```powershell
# benchmark.yml手動実行
gh workflow run benchmark.yml --ref main

# 結果確認
pytest --benchmark-only --benchmark-json=benchmark_results.json
```

#### 2.3 セキュリティスキャン
```powershell
# 秘密情報スキャン
python scripts/ops/scan_secrets.py --scan-all

# 依存関係脆弱性チェック
python -m pip audit
```

### 3. 月次運用手順

#### 3.1 システム全体監査
- **TASKS.md** 状態確認
- **APPROVALS.md** 承認履歴確認
- **WORK_TRACKING.md** 進捗確認

#### 3.2 アーティファクト整理
```powershell
# 古いログファイルのアーカイブ
Compress-Archive -Path "data/logs/archive/*" -DestinationPath "archive/logs_$(Get-Date -Format 'yyyy-MM').zip"

# 古いベンチマーク結果の整理
Remove-Item ".benchmarks/*" -Recurse -Force -Confirm:$false
```

#### 3.3 依存関係更新
```powershell
# Python依存関係更新
python -m pip list --outdated
python -m pip install --upgrade pip setuptools wheel

# Unity パッケージ更新確認
# Package Manager で更新可能パッケージ確認
```

## 緊急時対応手順

### 1. システム停止時
1. **即座の対応**:
   - プロセス状態確認
   - ログ確認
   - 復旧可能性判断

2. **復旧手順**:
   ```powershell
   # 仮想環境再構築
   Remove-Item .venv -Recurse -Force
   python -m venv .venv
   .venv/Scripts/Activate.ps1
   python -m pip install -r requirements.txt
   ```

### 2. CI/CD障害時
1. **GitHub Actions障害**:
   - ワークフロー履歴確認
   - 手動実行による復旧
   - 設定ファイル検証

2. **ローカルテスト実行**:
   ```powershell
   # 緊急時ローカルテスト
   pytest -v --tb=short
   python scripts/normalize_paths.py --dry-run
   ```

### 3. セキュリティインシデント
1. **即座の対応**:
   - システム隔離
   - ログ保全
   - 影響範囲調査

2. **報告手順**:
   - インシデント記録作成
   - 関係者への通知
   - 復旧計画策定

## 運用メトリクス

### 1. パフォーマンス指標
- **CI実行時間**: < 10分
- **テストカバレッジ**: ≥ 80%
- **ビルド成功率**: ≥ 95%

### 2. 品質指標
- **静的解析スコア**: ≥ 8.0/10
- **セキュリティスキャン**: 0件
- **EOL準拠率**: 100%

### 3. 運用指標
- **監視アラート対応時間**: < 30分
- **インシデント解決時間**: < 4時間
- **定期メンテナンス実施率**: 100%

## 設定ファイル管理

### 1. 重要設定ファイル
- `.github/workflows/monitor.yml`
- `.github/workflows/benchmark.yml`
- `ORCH/STATE/TASKS.md`
- `ORCH/STATE/APPROVALS.md`

### 2. バックアップ手順
```powershell
# 設定ファイルバックアップ
$BackupDate = Get-Date -Format "yyyy-MM-dd"
Copy-Item "ORCH/STATE/*.md" "backups/config_$BackupDate/"
Copy-Item ".github/workflows/*.yml" "backups/workflows_$BackupDate/"
```

### 3. 復元手順
```powershell
# 設定ファイル復元
$RestoreDate = "2025-01-11"  # 復元したい日付
Copy-Item "backups/config_$RestoreDate/*" "ORCH/STATE/"
Copy-Item "backups/workflows_$RestoreDate/*" ".github/workflows/"
```

## 連絡先・エスカレーション

### 1. 通常運用
- **第一担当**: WORK1 エージェント
- **第二担当**: CMD エージェント

### 2. 緊急時
- **システム障害**: CMD エージェント（即座）
- **セキュリティ**: AUDIT エージェント（即座）

### 3. 外部連絡
- **GitHub障害**: GitHub Status確認
- **Unity障害**: Unity Status確認

---
**最終更新**: 2025-01-11T11:00:00Z  
**作成者**: WORK1 エージェント  
**承認者**: CMD エージェント  
**次回レビュー**: 2025-02-11