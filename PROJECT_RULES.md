# ORCH-Next プロジェクトルール（改訂版）

## 概要
ORCH-NextはPowerShell依存を完全廃止し、Python ASGI（FastAPI）を中核とするAI駆動オーケストレーションシステムです。
Kevin's Hive-Mind AIエージェント統合により、セルフヒーリング・動的メトリクス最適化・自動回復を実現します。

## 基本方針
- **AI First**: すべての判断・監視・回復にAIエージェントを活用
- **Python統一**: PowerShell全廃、Python ASGIベース、必要箇所のみGo
- **品質重視**: 単体/統合/負荷/セキュリティテストを必須とする
- **可観測性**: 構造化ログ・Prometheusメトリクス・リアルタイム監視

## ブランチ戦略・コミット規約

### ブランチ命名規則
- `feat/*` - 新機能開発
- `fix/*` - バグ修正
- `docs/*` - ドキュメント更新
- `refactor/*` - リファクタリング
- `test/*` - テスト追加・修正

### コミット規約（Conventional Commits）
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

例:
- `feat(api): add /metrics endpoint with Prometheus format`
- `fix(lock): resolve SQLite deadlock in high concurrency`
- `docs(readme): update installation instructions`

### PR要件
- **小粒化**: 変更行数 < 500行
- **契約テスト**: API変更時は必須
- **レビュー**: 最低1名の承認
- **CI通過**: 全テストスイート成功

## 品質ゲート

### 必須テストスイート
1. **単体テスト**: pytest、カバレッジ > 80%
2. **統合テスト**: API契約テスト、DB整合性
3. **負荷テスト**: SSE 100同時接続、レスポンス < 1秒
4. **セキュリティテスト**: HMAC検証、JWT認証、レート制限

### CI/CD要件
- **GitHub Actions**: PRごとに全テスト実行
- **メトリクススモーク**: `/metrics` エンドポイント200応答
- **SSE耐性**: 100同時接続で95%成功率
- **契約検証**: Webhook HMAC検証 > 99%

## セキュリティ要件

### 認証・認可
- **JWT**: サービスアカウントベース、ロール制御
- **HMAC**: Webhook署名検証、時刻ずれ±120秒
- **レート制限**: API呼び出し制限、DDoS対策

### 秘匿情報管理
- **環境変数**: `.env.local` のみ、コミット禁止
- **Vault統合**: 本番環境はHashiCorp Vault
- **ログ除外**: 機密情報のログ出力禁止

### セキュリティ監査
- **自動スキャン**: 依存関係脆弱性チェック
- **コード監査**: 静的解析ツール統合
- **ペネトレーションテスト**: 定期実施

## 可観測性・監視

### メトリクス（Prometheus互換）
- `orch_http_requests_total{method,status}` - HTTP リクエスト数
- `orch_sse_connections_active` - アクティブSSE接続数
- `orch_webhook_signatures_verified_total` - Webhook署名検証数
- `orch_task_duration_seconds` - タスク実行時間
- `orch_lock_acquisitions_total{resource}` - ロック取得数

### 構造化ログ
- **JSON形式**: 全ログをJSON構造化
- **相関ID**: リクエスト追跡用ID付与
- **レベル分け**: DEBUG/INFO/WARN/ERROR/CRITICAL
- **ローテーション**: 日次ローテーション、30日保持

### アラート・通知
- **Slack統合**: 重要イベント通知
- **Webhook**: 外部システム連携
- **メール**: 緊急時通知

## アーキテクチャ・技術スタック

### コア技術
- **Python**: 3.11+、FastAPI、uvicorn
- **Go**: 高スループット部分（SSEゲートウェイ）
- **SQLite**: 開発・テスト環境
- **PostgreSQL**: 本番環境

### AI統合
- **Hive-Mind**: リーダーエージェントによる調整
- **Swarm Mode**: タスク自動分散
- **Self-Healing**: 異常検知・自動回復
- **Dynamic Metrics**: AI による閾値自動調整

### 外部統合
- **Prometheus**: メトリクス収集
- **Grafana**: ダッシュボード
- **GitHub Actions**: CI/CD
- **Slack**: 通知

## 開発・運用ルール

### ローカル開発
- **UTF-8統一**: 全ファイルUTF-8、改行LF
- **pathlib使用**: パス操作はpathlibで統一
- **仮想環境**: `.venv` 必須使用
- **動作確認**: `pytest -q` + 軽負荷テスト

### データ管理
- **バックアップ**: `data/backups/` へ日次
- **設定**: `data/config/*.env.local`
- **ログ**: `data/logs/` 構造化保存
- **メトリクス**: `data/metrics.db` SQLite

### 復旧手順
- **ドキュメント**: `docs/recovery.md` に手順記載
- **自動復旧**: セルフヒーリング機能
- **手動復旧**: 段階的復旧プロセス

## マイグレーション計画

### Phase 1 (Week 1)
- PowerShell完全廃止
- Python dispatcher.py 実装
- `/metrics` エンドポイント追加
- 基本監視機能

### Phase 2 (Week 2)
- SQLiteロック管理
- HMAC/JWT セキュリティ
- Console Bridge API統合
- 負荷テスト100接続

### Phase 3 (Week 3)
- セルフヒーリング拡張
- Go SSEゲートウェイ（必要時）
- CI完全実装
- カナリアリリース

## 受入基準

### 機能要件
- `/metrics` が200応答、主要メトリクス更新
- SSE 100同時接続、心拍遅延 < 1秒平均
- Webhook HMAC検証成功率 > 99%
- ロック競合時のStarvation回避
- 失敗イベントのJSON永続化

### 非機能要件
- セルフヒーリング段階的復旧実行
- CI全テストスイート通過
- セキュリティ要件100%準拠
- ドキュメント完全性

## 禁止事項

### 技術的禁止
- PowerShellスクリプト新規作成
- ファイルベースロック（フォールバック除く）
- 平文での秘匿情報保存
- 非構造化ログ出力

### 運用的禁止
- 手動デプロイ（緊急時除く）
- テストスキップ
- セキュリティ要件の妥協
- ドキュメント未更新でのリリース

---

**更新履歴**
- 2025-01-06: 初版作成（PowerShell廃止、AI統合、品質ゲート強化）