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

# テスト実行
.venv\Scripts\python.exe -m pytest -v --cov=src --cov=app --cov-report=xml:coverage.xml

# 設定ファイル作成
cp data/config/example.env data/config/.env.local
```

### 起動

```bash
# 開発サーバー起動
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# バックグラウンド監視開始
python src/monitor.py --daemon

# メトリクス確認（開発サーバ）
curl http://localhost:8000/metrics

# 運用URLの既定（Windows/NSSM + Waitress）
# ダッシュボード／プレビュー等の既定 Base URL は http://127.0.0.1:5001
# 監視・E2E・Playwright の既定も同一です
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

# セキュリティ（例示値。実運用では環境変数やCIシークレッツで注入してください）
JWT_SECRET_KEY=REDACTED
HMAC_SECRET_KEY=REDACTED

# 監視
PROMETHEUS_PORT=9090
LOG_LEVEL=INFO

# 通知（例示値。実運用では環境変数やCIシークレッツで注入してください）
SLACK_WEBHOOK_URL=<REDACTED>
```

## 開発

### テスト実行
```bash
# 全テスト実行
pytest

# カバレッジ付き
pytest --cov=src --cov-report=html

# 負荷テスト（既定 Base URL を 5001 に統一）
locust -f tests/load/test_sse.py --host=http://127.0.0.1:5001
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

#### ロギング方針と使用例
- 共通ロガー取得: `from app.shared.logging_config import get_logger, _in_pytest`
- pytest 実行時は FileHandler を自動抑止（stderr のみ）。通常は INFO、pytest は WARNING。`LOG_LEVEL`/`ORCH_LOG_LEVEL` で上書き可。
- 使用例:
```python
from app.shared.logging_config import get_logger, _in_pytest
logger = get_logger(__name__, in_pytest=_in_pytest())
logger.info("started", extra={"operation": "boot"})
```
- 環境変数によるレベル指定:
```env
LOG_LEVEL=DEBUG  # または ORCH_LOG_LEVEL=DEBUG
```
- テストでのノイズ抑止:
```python
def test_example(caplog):
    caplog.set_level("WARNING")
    # ...
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

## Kernel 最小API と CI プリフライト

本プロジェクトには、テキスト生成機能のための最小 Kernel API が含まれます。公開関数は以下のとおりです（`kernel` モジュール経由で提供）。

- `generate(prompt, *, temperature=0.7, max_tokens=256, top_p=1.0, stop=None, model=None, stream=False)`
- `generate_chat(messages, *, temperature=0.7, max_tokens=256, top_p=1.0, stop=None, model=None, stream=False)`
- `read_paths(path_key=None)`
- `healthcheck()`
- `_model_id()`

整合性と CI の早期検知のため、Windows ジョブではプリフライトとして `healthcheck()` を実行し、`status=="ok"` 以外の場合はジョブを失敗させます。

```bash
python -c "import importlib, sys; mod=importlib.import_module('kernel'); s=mod.healthcheck().get('status'); print(f'kernel health: {s}'); sys.exit(0 if s=='ok' else 1)"
```

また、差分カバレッジを `diff-cover --fail-under=80` でゲートしています。テストとカバレッジは以下で確認できます。

```bash
pytest -v --cov=src --cov=app --cov-report=xml:coverage.xml
diff-cover coverage.xml --compare-branch origin/main --fail-under=80 --html-report diff-cover.html
```

CI（Windows）では次のディレクトリが事前に作成されます：

- `data/`
- `data/baseline/`
- `data/baseline/milestones/`
- `data/baseline/tasks/`
- `data/baseline/metrics/`

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