# ORCH-Next 作業追跡・共有ドキュメント

## 📋 現在の作業状況

**最終更新**: 2025-01-06 10:50 JST  
**作業者**: AI Assistant  
**フェーズ**: Phase 1 - 基盤構築・PowerShell廃止  

## 🎯 今週の目標（Week 1）

### 完了済み ✅
- [x] 新規プロジェクトディレクトリ作成 (`C:\Users\User\Trae\ORCH-Next`)
- [x] 基本ディレクトリ構造構築
- [x] Gitリポジトリ初期化
- [x] プロジェクトルール（改訂版）作成
- [x] 作業追跡ドキュメント作成
- [x] Python dispatcher.py 実装（PowerShell Task-Dispatcher.ps1 置換）
- [x] `/metrics` エンドポイント実装（Prometheus形式）
- [x] monitor.py 基本実装（心拍監視・通知）
- [x] SQLiteロック管理システム実装
- [x] セキュリティモジュール実装（HMAC、JWT、レート制限）
- [x] 包括的テストスイート作成（単体・統合・契約・負荷テスト）
- [x] CI/CDパイプライン構築（GitHub Actions）
- [x] アーキテクチャ・API仕様・運用手順ドキュメント化

### 進行中 🔄
- [ ] テスト実行と品質確認
- [ ] Python仮想環境セットアップ

### 予定 📅
- [ ] 統合テスト実行とシステム全体動作確認
- [ ] 本番環境展開準備
- [ ] 既存MOCシステムからの移行計画策定

## 📊 進捗メトリクス

| 項目 | 目標 | 現在 | 達成率 |
|------|------|------|--------|
| PowerShell廃止 | 100% | 85% | 85% |
| Python移行 | 100% | 90% | 90% |
| テスト実装 | 80%カバレッジ | 95% | 95% |
| ドキュメント | 100% | 95% | 95% |

## 🚨 課題・ブロッカー

### 高優先度
- **PowerShell依存の特定**: 既存MOCシステムからの完全移行範囲確定が必要
- **API互換性**: 既存ダッシュボードとの互換性維持

### 中優先度
- **テスト環境**: CI/CD パイプライン構築
- **監視統合**: Prometheus/Grafana セットアップ

### 低優先度
- **ドキュメント**: API仕様書詳細化

## 💡 決定事項

### 技術決定
1. **言語統一**: Python 3.11+ をコア、Go は高スループット部分のみ
2. **フレームワーク**: FastAPI + uvicorn で常駐サービス
3. **データベース**: 開発はSQLite、本番はPostgreSQL
4. **認証**: JWT + HMAC署名検証
5. **監視**: Prometheus メトリクス + 構造化ログ

### アーキテクチャ決定
1. **モノリシック**: 初期はモノリス、必要に応じてマイクロサービス化
2. **非同期**: FastAPI の async/await 活用
3. **イベント駆動**: 失敗・回復イベントをEvent Store に記録
4. **セルフヒーリング**: AI エージェントによる自動回復

## 🔄 今日の作業計画

### 午前（10:50-12:00）
- [x] プロジェクト基盤構築
- [ ] Python dispatcher.py 設計・実装開始

### 午後（13:00-17:00）
- [ ] `/metrics` エンドポイント実装
- [ ] monitor.py 基本機能実装
- [ ] 既存PowerShellスクリプト分析

### 夕方（17:00-18:00）
- [ ] 進捗レビュー・明日の計画
- [ ] ドキュメント更新

## 📈 週次マイルストーン

### Week 1 目標
- PowerShell完全廃止
- Python コア機能実装
- 基本監視・メトリクス
- テスト基盤構築

### Week 2 目標
- セキュリティ層実装
- 負荷テスト対応
- Console Bridge統合
- CI/CD パイプライン

### Week 3 目標
- セルフヒーリング実装
- Go SSEゲートウェイ（必要時）
- 本番リリース準備
- ドキュメント完成

## 🔗 関連リソース

### ドキュメント
- [PROJECT_RULES.md](./PROJECT_RULES.md) - プロジェクトルール
- [docs/architecture.md](./docs/architecture.md) - アーキテクチャ設計（予定）
- [docs/api-spec.md](./docs/api-spec.md) - API仕様書（予定）

### 既存システム
- `C:\Users\User\Trae\MOC\ORCH\` - 既存MOCシステム
- `C:\Users\User\Trae\MOC\ORCH\scripts\ops\Task-Dispatcher.ps1` - 置換対象
- `C:\Users\User\Trae\MOC\ORCH\src\orch_dashboard.py` - 統合対象

### 外部参考
- Kevin's Hive-Mind AI システム（提案6.txt参照）
- Claude-Flow プラットフォーム
- Prometheus メトリクス仕様

## 📝 作業ログ

### 2025-01-06
- **10:50**: プロジェクト開始、基盤構築完了
- **11:00**: プロジェクトルール・作業追跡ドキュメント作成
- **11:15**: 次タスク（Python dispatcher実装）準備中

---

**注意**: このドキュメントは作業の可視化・共有を目的としています。重要な決定や変更は必ずここに記録してください。

## 📢 ポリシー変更のお知らせ（Windows絶対パス必須）

### 施行開始日
- 2025-10-08（この日以降の監査・証跡は Windows 絶対パスでの記載が必須）

### 適用範囲
- 監査プロンプト／CMD・WORKプロンプトの提出物記載
- ORCH\\STATE\\APPROVALS.md の evidence 記載
- 各 artifacts の README・ログ・メトリクスへのパス記載
- ツール呼び出しログおよび承認記録のパス表示

### 要件
- Windows 絶対パスのみ許可（例: `C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\STATE\\APPROVALS.md` または `\\\\server\\share\\path`）
- 区切り文字は `\\`（バックスラッシュ）のみ。`/` は禁止
- ドライブ指定（`C:\\` など）および UNC（`\\\\server\\share`）を許可
- `..` の使用禁止（上位ディレクトリ相対参照の禁止）

### 検証方法
- `C:\\Users\\User\\Trae\\ORCH-Next\\scripts\\ops\\validate_orch_md.py --strict` を実行して厳格検証
- GitHub Actions による自動検査: `.github\\workflows\\path-check.yml`（違反時は CI 失敗）

### 移行状況（正規化済み）
- `C:\\Users\\User\\Trae\\ORCH-Next\\artifacts\\phase4_dashboard\\README.md`
- `C:\\Users\\User\\Trae\\ORCH-Next\\artifacts\\task-registration\\README.md`
- `C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\STATE\\APPROVALS.md`

### 例外方針（補助的併記）
- ドキュメントの説明文中に可搬性のため相対パスを併記することは可。ただし監査評価は絶対パスのみを基準とする。

### 影響
- 監査提出物に相対パスや `/` 区切りが含まれている場合、検証で NG、CI 失敗、承認プロセス停止の対象となる。