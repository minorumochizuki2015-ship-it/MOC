# エラーコード詳細リファレンス

## 概要
**作成日**: 2025-01-11  
**タスクID**: 005-P3  
**担当**: WORK2  
**目的**: システムエラーコードの詳細定義と対処法

## エラーコード体系

### 分類
- **E0xx**: システム基盤エラー
- **E1xx**: Unity関連エラー  
- **E2xx**: CI/CD関連エラー
- **E3xx**: ファイルシステムエラー
- **E4xx**: セキュリティエラー
- **E5xx**: ネットワーク関連エラー

## 詳細エラーコード

### E0xx: システム基盤エラー

#### E001: Python環境エラー
- **説明**: Python仮想環境の問題
- **原因**: 
  - 仮想環境破損
  - 依存関係不整合
  - パス設定問題
- **対処法**:
  ```powershell
  Remove-Item .venv -Recurse -Force
  python -m venv .venv
  .venv/Scripts/Activate.ps1
  python -m pip install -r requirements.txt
  ```
- **予防策**: 定期的な依存関係更新

#### E002: 依存関係競合エラー
- **説明**: Pythonパッケージ間の競合
- **原因**:
  - バージョン不整合
  - 循環依存
  - 破損したパッケージ
- **対処法**:
  ```powershell
  python -m pip list --outdated
  python -m pip install --force-reinstall -r requirements.txt
  ```
- **予防策**: requirements.txtのバージョン固定

#### E003: メモリ不足エラー
- **説明**: システムメモリ不足
- **原因**:
  - 大量データ処理
  - メモリリーク
  - 同時実行プロセス過多
- **対処法**:
  ```powershell
  Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10
  # 不要プロセス終了
  ```
- **予防策**: 定期的なプロセス監視

### E1xx: Unity関連エラー

#### E101: Unity Editor起動失敗
- **説明**: Unity Editorが起動しない
- **原因**:
  - ライセンス問題
  - プロジェクト設定破損
  - Unity Hub問題
- **対処法**:
  ```powershell
  Get-Process Unity* | Stop-Process -Force
  Start-Process "C:\Program Files\Unity Hub\Unity Hub.exe"
  ```
- **予防策**: Unity Hubの定期更新

#### E102: プロジェクト読み込みエラー
- **説明**: Unityプロジェクトが開けない
- **原因**:
  - ProjectSettings破損
  - Library破損
  - バージョン不整合
- **対処法**:
  ```powershell
  Remove-Item "Trae/Library" -Recurse -Force
  Remove-Item "Trae/Temp" -Recurse -Force
  # Unity Editorでプロジェクト再オープン
  ```
- **予防策**: 定期的なプロジェクトバックアップ

#### E103: ビルドエラー
- **説明**: APK/実行ファイルビルド失敗
- **原因**:
  - コンパイルエラー
  - 設定問題
  - 依存関係問題
- **対処法**:
  ```powershell
  # ビルドログ確認
  Get-Content "Trae/build_apk.log" | Select-Object -Last 100
  # キャッシュクリア後再ビルド
  ```
- **予防策**: 継続的インテグレーション

#### E104: IL2CPP変換エラー
- **説明**: IL2CPPバックエンドでの変換失敗
- **原因**:
  - 非対応コード
  - 設定問題
  - プラットフォーム固有問題
- **対処法**:
  ```csharp
  // link.xmlでの除外設定
  <linker>
    <assembly fullname="Assembly-CSharp" preserve="all"/>
  </linker>
  ```
- **予防策**: IL2CPP互換性テスト

### E2xx: CI/CD関連エラー

#### E201: GitHub Actions失敗
- **説明**: ワークフロー実行失敗
- **原因**:
  - 構文エラー
  - 権限問題
  - リソース制限
- **対処法**:
  ```powershell
  # 構文チェック
  gh workflow run monitor.yml --ref main
  gh run list --limit 5
  ```
- **予防策**: ローカルでの事前テスト

#### E202: テスト失敗
- **説明**: 自動テストの失敗
- **原因**:
  - コード変更による影響
  - テストデータ問題
  - 環境依存問題
- **対処法**:
  ```powershell
  pytest -v --tb=long
  pytest --lf  # 最後に失敗したテストのみ
  ```
- **予防策**: テスト駆動開発

#### E203: カバレッジ不足
- **説明**: テストカバレッジが基準未満
- **原因**:
  - テストケース不足
  - 未テストコード
  - 除外設定問題
- **対処法**:
  ```powershell
  pytest --cov=. --cov-report=html
  # htmlcov/index.htmlで詳細確認
  ```
- **予防策**: カバレッジ監視の自動化

#### E204: 静的解析エラー
- **説明**: mypy/flake8での検出
- **原因**:
  - 型注釈不足
  - コーディング規約違反
  - 未使用変数/インポート
- **対処法**:
  ```powershell
  mypy . --strict
  flake8 . --max-line-length=88
  black . --check
  ```
- **予防策**: エディタでのリアルタイム検査

### E3xx: ファイルシステムエラー

#### E301: パス問題
- **説明**: ファイルパスの問題
- **原因**:
  - 絶対パス使用
  - パス区切り文字問題
  - 存在しないパス
- **対処法**:
  ```powershell
  python scripts/normalize_paths.py --fix
  ```
- **予防策**: 相対パス使用の徹底

#### E302: EOL問題
- **説明**: 改行コード不一致
- **原因**:
  - Windows環境でのCRLF
  - Git設定問題
  - エディタ設定問題
- **対処法**:
  ```powershell
  Tools/Scripts/Fix-EOL.ps1
  git config core.autocrlf false
  ```
- **予防策**: .gitattributes設定

#### E303: ファイル権限エラー
- **説明**: ファイルアクセス権限不足
- **原因**:
  - 権限設定問題
  - ファイル使用中
  - 管理者権限必要
- **対処法**:
  ```powershell
  # 管理者権限で実行
  Start-Process PowerShell -Verb RunAs
  ```
- **予防策**: 適切な権限設定

#### E304: ディスク容量不足
- **説明**: ストレージ容量不足
- **原因**:
  - ログファイル蓄積
  - キャッシュファイル蓄積
  - 大容量ファイル
- **対処法**:
  ```powershell
  # ディスク使用量確認
  Get-ChildItem . -Recurse | Measure-Object -Property Length -Sum
  # 不要ファイル削除
  Remove-Item ".benchmarks" -Recurse -Force
  ```
- **予防策**: 定期的なクリーンアップ

### E4xx: セキュリティエラー

#### E401: 秘密情報検出
- **説明**: 秘密情報がコードに含まれている
- **原因**:
  - 実際の認証情報コミット
  - プレースホルダー不適切
  - 除外設定不足
- **対処法**:
  ```powershell
  # 秘密情報スキャン
  python scripts/ops/scan_secrets.py --fix
  # プレースホルダー置換
  ```
- **予防策**: pre-commitフックの設定

#### E402: 脆弱性検出
- **説明**: 依存関係に脆弱性
- **原因**:
  - 古いパッケージバージョン
  - 既知の脆弱性
  - 設定問題
- **対処法**:
  ```powershell
  python -m pip audit
  python -m pip install --upgrade [パッケージ名]
  ```
- **予防策**: 定期的な脆弱性スキャン

#### E403: 認証エラー
- **説明**: 認証・認可の失敗
- **原因**:
  - 認証情報不正
  - 権限不足
  - トークン期限切れ
- **対処法**:
  ```powershell
  # GitHub認証確認
  gh auth status
  gh auth login
  ```
- **予防策**: 認証情報の定期更新

### E5xx: ネットワーク関連エラー

#### E501: 接続タイムアウト
- **説明**: ネットワーク接続タイムアウト
- **原因**:
  - ネットワーク不安定
  - サーバー応答遅延
  - ファイアウォール
- **対処法**:
  ```powershell
  # 接続テスト
  Test-NetConnection github.com -Port 443
  # プロキシ設定確認
  ```
- **予防策**: ネットワーク監視

#### E502: DNS解決エラー
- **説明**: ドメイン名解決失敗
- **原因**:
  - DNS設定問題
  - ネットワーク問題
  - ドメイン無効
- **対処法**:
  ```powershell
  # DNS確認
  nslookup github.com
  # DNS設定変更
  ```
- **予防策**: 複数DNS設定

#### E503: プロキシエラー
- **説明**: プロキシ経由での接続失敗
- **原因**:
  - プロキシ設定問題
  - 認証問題
  - プロキシサーバー問題
- **対処法**:
  ```powershell
  # プロキシ設定確認
  netsh winhttp show proxy
  # Git プロキシ設定
  git config --global http.proxy [プロキシURL]
  ```
- **予防策**: プロキシ設定の文書化

## エラー対応フローチャート

```
エラー発生
    ↓
エラーコード確認
    ↓
分類別対処法実行
    ↓
解決確認
    ↓
[解決] → 予防策実施 → 完了
    ↓
[未解決] → エスカレーション → 上位対応
```

## ログ出力形式

### 標準ログ形式
```
[YYYY-MM-DD HH:MM:SS] [ERROR] [E001] Python環境エラー: 仮想環境が見つかりません
[YYYY-MM-DD HH:MM:SS] [WARN]  [E302] EOL問題: CRLFが検出されました
[YYYY-MM-DD HH:MM:SS] [INFO]  [E000] 正常終了
```

### エラー詳細ログ
```json
{
  "timestamp": "2025-01-11T11:15:00Z",
  "level": "ERROR",
  "code": "E001",
  "message": "Python環境エラー",
  "details": {
    "file": ".venv/Scripts/python.exe",
    "action": "仮想環境再構築",
    "status": "resolved"
  }
}
```

---
**最終更新**: 2025-01-11T11:15:00Z  
**作成者**: WORK2 エージェント  
**承認者**: CMD エージェント  
**次回レビュー**: 2025-02-11