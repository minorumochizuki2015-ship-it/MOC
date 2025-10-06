# ORCH-Next: AI-Driven Orchestration System

## 概要

ORCH-NextはPowerShell依存を完全廃止し、Python ASGI（FastAPI）を中核とするAI駆動オーケストレーションシステムです。Kevin's Hive-Mind AIエージェント統合により、セルフヒーリング・動的メトリクス最適化・自動回復を実現します。

## 主要機能

- 🤖 **AI駆動**: Hive-Mind エージェントによる自動調整・セルフヒーリング
- 🚀 **高性能**: Python ASGI + 必要箇所のみGo実装
- 📊 **可観測性**: Prometheus メトリクス + 構造化ログ
- 🔒 **セキュリティ**: JWT認証 + HMAC署名検証
- 🔄 **自動回復**: 異常検知・段階的復旧
- 📈 **スケーラブル**: SQLite → PostgreSQL 対応

## アーキテクチャ

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Monitor       │    │   Lock Manager  │
│   (Core API)    │◄──►│   (AI Healing)  │◄──►│   (SQLite)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Metrics       │    │   Event Store   │    │   Console       │
│   (Prometheus)  │    │   (JSON Logs)   │    │   Bridge        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## クイックスタート

### 前提条件
- Python 3.11+
- Git
- (オプション) Go 1.21+ (SSEゲートウェイ用)

### インストール

```bash
# リポジトリクローン
git clone <repository-url>
cd ORCH-Next

# 仮想環境作成・有効化
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate

# 依存関係インストール
pip install -r requirements.txt

# 設定ファイル作成
cp data/config/example.env data/config/.env.local
```

### 起動

```bash
# 開発サーバー起動
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# バックグラウンド監視開始
python src/monitor.py --daemon

# メトリクス確認
curl http://localhost:8000/metrics
```

## API エンドポイント

### コア機能
- `GET /` - ヘルスチェック
- `GET /metrics` - Prometheus メトリクス
- `POST /dispatch` - タスクディスパッチ
- `GET /jobs/{id}/events` - ジョブイベント取得

### 管理機能
- `POST /webhook` - 外部Webhook受信
- `GET /health` - システムヘルス
- `GET /locks` - ロック状態確認

## 設定

### 環境変数 (.env.local)
```env
# API設定
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true

# データベース
DATABASE_URL=sqlite:///data/orch.db

# セキュリティ
JWT_SECRET_KEY=your-secret-key
HMAC_SECRET_KEY=your-hmac-key

# 監視
PROMETHEUS_PORT=9090
LOG_LEVEL=INFO

# 通知
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

## 開発

### テスト実行
```bash
# 全テスト実行
pytest

# カバレッジ付き
pytest --cov=src --cov-report=html

# 負荷テスト
locust -f tests/load/test_sse.py --host=http://localhost:8000
```

### コード品質
```bash
# フォーマット
black src/ tests/
isort src/ tests/

# リント
flake8 src/ tests/
mypy src/

# プリコミットフック
pre-commit install
pre-commit run --all-files
```

## 監視・運用

### メトリクス
- `orch_http_requests_total` - HTTP リクエスト数
- `orch_sse_connections_active` - アクティブSSE接続数
- `orch_task_duration_seconds` - タスク実行時間
- `orch_lock_acquisitions_total` - ロック取得数

### ログ
```bash
# 構造化ログ確認
tail -f data/logs/orch.log | jq .

# エラーログ抽出
grep "ERROR" data/logs/orch.log | jq .
```

### セルフヒーリング
システムは自動的に以下を監視・回復します：
- API応答時間異常
- SSE接続切断
- ロック競合・デッドロック
- メモリ・CPU使用率

## デプロイ

### Docker (推奨)
```bash
# イメージビルド
docker build -t orch-next .

# コンテナ起動
docker run -d -p 8000:8000 --name orch-next \
  -v $(pwd)/data:/app/data \
  orch-next
```

### systemd (Linux)
```bash
# サービス登録
sudo cp scripts/orch-next.service /etc/systemd/system/
sudo systemctl enable orch-next
sudo systemctl start orch-next
```

## 移行ガイド

### 既存MOCシステムから
1. PowerShellスクリプト停止
2. データベース移行実行
3. 設定ファイル変換
4. 段階的切り替え

詳細は [docs/migration.md](docs/migration.md) を参照

## トラブルシューティング

### よくある問題
- **ポート競合**: `lsof -i :8000` でプロセス確認
- **DB接続エラー**: `data/orch.db` の権限確認
- **メトリクス取得失敗**: Prometheus設定確認

### ログ確認
```bash
# アプリケーションログ
tail -f data/logs/orch.log

# システムログ (Linux)
journalctl -u orch-next -f
```

## 貢献

1. フォーク作成
2. フィーチャーブランチ作成 (`git checkout -b feat/amazing-feature`)
3. コミット (`git commit -m 'feat: add amazing feature'`)
4. プッシュ (`git push origin feat/amazing-feature`)
5. プルリクエスト作成

## ライセンス

MIT License - 詳細は [LICENSE](LICENSE) を参照

## サポート

- 📖 [ドキュメント](docs/)
- 🐛 [Issue報告](https://github.com/your-org/orch-next/issues)
- 💬 [ディスカッション](https://github.com/your-org/orch-next/discussions)

---

**作成日**: 2025-01-06  
**バージョン**: 0.1.0-alpha  
**メンテナー**: ORCH-Next Team