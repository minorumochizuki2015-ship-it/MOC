# トラブルシューティングガイド

## 概要
**作成日**: 2025-01-11  
**タスクID**: 005-P3  
**担当**: WORK2  
**目的**: Unity Game Project運用時の一般的な問題と解決方法

## 一般的なエラーパターン

### 1. Python環境関連

#### 1.1 仮想環境エラー
**症状**: `.venv/Scripts/python.exe` が見つからない
```
FileNotFoundError: [Errno 2] No such file or directory: '.venv/Scripts/python.exe'
```

**原因**:
- 仮想環境が破損
- パス設定の問題
- 権限不足

**解決方法**:
```powershell
# 仮想環境再構築
Remove-Item .venv -Recurse -Force -ErrorAction SilentlyContinue
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

#### 1.2 依存関係エラー
**症状**: モジュールインポートエラー
```
ModuleNotFoundError: No module named 'pytest'
```

**原因**:
- 依存関係未インストール
- バージョン競合
- 仮想環境未アクティベート

**解決方法**:
```powershell
# 依存関係確認・再インストール
.venv/Scripts/Activate.ps1
python -m pip list
python -m pip install -r requirements.txt --force-reinstall
```

### 2. Unity関連

#### 2.1 Unity起動エラー
**症状**: Unity Editorが起動しない
```
Unity Editor failed to start
```

**原因**:
- Unity Hubライセンス問題
- プロジェクト設定破損
- 権限不足

**解決方法**:
```powershell
# Unity プロセス確認・終了
Get-Process Unity* | Stop-Process -Force
Get-Process UnityHub* | Stop-Process -Force

# Unity Hub再起動
Start-Process "C:\Program Files\Unity Hub\Unity Hub.exe"

# プロジェクト設定確認
Get-ChildItem "Trae/ProjectSettings/" -Name
```

#### 2.2 ビルドエラー
**症状**: APKビルド失敗
```
Build failed with errors
```

**原因**:
- Android SDK設定問題
- IL2CPP設定問題
- 依存関係問題

**解決方法**:
```powershell
# ビルドログ確認
Get-Content "Trae/build_apk.log" | Select-Object -Last 50

# キャッシュクリア
Remove-Item "Trae/Library/Artifacts" -Recurse -Force
Remove-Item "Trae/Temp" -Recurse -Force

# 再ビルド
# Unity Editor > File > Build Settings > Build
```

### 3. CI/CD関連

#### 3.1 GitHub Actions失敗
**症状**: ワークフロー実行失敗
```
The job was not started because recent account payments have failed
```

**原因**:
- GitHub Actions制限
- 設定ファイル構文エラー
- 権限問題

**解決方法**:
```powershell
# ワークフロー構文チェック
Get-Content ".github/workflows/monitor.yml" | python -c "import yaml; import sys; yaml.safe_load(sys.stdin)"

# 手動実行テスト
gh workflow run monitor.yml --ref main

# ログ確認
gh run list --limit 5
gh run view [RUN_ID] --log
```

#### 3.2 テスト失敗
**症状**: pytest実行失敗
```
FAILED test_integration.py::test_basic - AssertionError
```

**原因**:
- テストデータ問題
- 環境設定問題
- コード変更による影響

**解決方法**:
```powershell
# 詳細テスト実行
pytest -v --tb=long test_integration.py

# 特定テストのみ実行
pytest -v test_integration.py::test_basic

# テストデータ確認
Get-ChildItem "test_output/" -Recurse
```

### 4. ファイルシステム関連

#### 4.1 パス問題
**症状**: ファイルパスエラー
```
FileNotFoundError: [Errno 2] No such file or directory: 'C:\Users\...'
```

**原因**:
- 絶対パス使用
- パス区切り文字問題
- ファイル存在確認不足

**解決方法**:
```powershell
# パス正規化実行
python scripts/normalize_paths.py --dry-run

# 手動パス修正
# バックスラッシュ → フォワードスラッシュ
# 絶対パス → 相対パス
```

#### 4.2 EOL問題
**症状**: 改行コード不一致
```
EOL mismatch detected: CRLF found in tracked files
```

**原因**:
- Windows環境でのCRLF
- Git設定問題
- エディタ設定問題

**解決方法**:
```powershell
# EOL確認・修正
python Scripts/check_eol.py

# Git設定確認
git config core.autocrlf
git config core.eol

# 一括修正
Tools/Scripts/Fix-EOL.ps1
```

### 5. セキュリティ関連

#### 5.1 秘密情報検出
**症状**: 秘密情報スキャンエラー
```
Secret detected in file: config.json
```

**原因**:
- 実際の秘密情報コミット
- プレースホルダー不適切
- 除外設定不足

**解決方法**:
```powershell
# 秘密情報スキャン実行
python scripts/ops/scan_secrets.py --scan-all

# 該当ファイル確認
Get-Content "config.json" | Select-String -Pattern "password|key|token"

# プレースホルダー置換
# 実際の値 → "REDACTED" または "CHANGEME"
```

#### 5.2 権限エラー
**症状**: ファイルアクセス権限エラー
```
PermissionError: [Errno 13] Permission denied
```

**原因**:
- ファイル権限不足
- プロセス実行中
- 管理者権限必要

**解決方法**:
```powershell
# 管理者権限でPowerShell起動
Start-Process PowerShell -Verb RunAs

# ファイル権限確認
Get-Acl "ファイルパス" | Format-List

# プロセス確認・終了
Get-Process | Where-Object {$_.Path -like "*Game_project*"}
```

## 復旧手順マニュアル

### 1. 緊急復旧手順

#### 1.1 システム全体復旧
```powershell
# 1. 現在の状態確認
Get-Process python, Unity*
Get-ChildItem .venv -ErrorAction SilentlyContinue

# 2. プロセス停止
Get-Process python, Unity* | Stop-Process -Force

# 3. 環境再構築
Remove-Item .venv -Recurse -Force
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt

# 4. 設定ファイル復元
Copy-Item "backups/config_latest/*" "ORCH/STATE/"

# 5. 動作確認
pytest --version
python scripts/normalize_paths.py --version
```

#### 1.2 データベース復旧
```powershell
# TASKS.md復旧
if (!(Test-Path "ORCH/STATE/TASKS.md")) {
    Copy-Item "ORCH/STATE/TASKS.md.bak" "ORCH/STATE/TASKS.md"
}

# APPROVALS.md復旧
if (!(Test-Path "ORCH/STATE/APPROVALS.md")) {
    Copy-Item "ORCH/STATE/APPROVALS.md.bak" "ORCH/STATE/APPROVALS.md"
}
```

### 2. 段階的復旧手順

#### 2.1 Phase 1: 基本環境
1. Python仮想環境確認
2. 依存関係インストール
3. 基本テスト実行

#### 2.2 Phase 2: Unity環境
1. Unity Editor起動確認
2. プロジェクト設定確認
3. ビルドテスト実行

#### 2.3 Phase 3: CI/CD環境
1. GitHub Actions確認
2. ワークフロー手動実行
3. 監視システム確認

## FAQ

### Q1: monitor.ymlが実行されない
**A**: GitHub Actionsの制限を確認し、手動実行でテストしてください。
```powershell
gh workflow run monitor.yml --ref main
```

### Q2: テストカバレッジが80%未満
**A**: pytest-covで詳細確認し、テストケースを追加してください。
```powershell
pytest --cov=. --cov-report=html
```

### Q3: Unity Editorが重い
**A**: キャッシュクリアとプロジェクト最適化を実行してください。
```powershell
Remove-Item "Trae/Library/Artifacts" -Recurse -Force
Remove-Item "Trae/Temp" -Recurse -Force
```

### Q4: Git操作でエラー
**A**: EOL設定とパス正規化を確認してください。
```powershell
git config core.autocrlf false
git config core.eol lf
python scripts/normalize_paths.py
```

### Q5: 依存関係の競合
**A**: 仮想環境を再構築してください。
```powershell
Remove-Item .venv -Recurse -Force
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
```

## エラーコード一覧

| コード | 説明 | 対処法 |
|--------|------|--------|
| E001 | Python環境エラー | 仮想環境再構築 |
| E002 | Unity起動エラー | Unity Hub再起動 |
| E003 | CI/CD失敗 | ワークフロー確認 |
| E004 | パス問題 | normalize_paths.py実行 |
| E005 | EOL問題 | Fix-EOL.ps1実行 |
| E006 | 権限エラー | 管理者権限で実行 |
| E007 | 秘密情報検出 | プレースホルダー置換 |
| E008 | テスト失敗 | テストデータ確認 |
| E009 | ビルドエラー | キャッシュクリア |
| E010 | 依存関係エラー | 依存関係再インストール |

---
**最終更新**: 2025-01-11T11:10:00Z  
**作成者**: WORK2 エージェント  
**承認者**: CMD エージェント  
**次回レビュー**: 2025-02-11