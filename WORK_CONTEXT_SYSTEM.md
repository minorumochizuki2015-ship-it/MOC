# ORCH-Next 作業コンテキスト管理システム

## 🎯 目的

新規セッションや新規AIが即座に作業に参加できるよう、プロジェクトの状態・進捗・技術的コンテキストを構造化して管理する。

## 📁 ファイル構造

```
ORCH-Next/
├── WORK_TRACKING.md          # メイン進捗管理（全体俯瞰）
├── WORK_SESSION_TEMPLATE.md  # セッション記録テンプレート
├── WORK_CONTEXT_SYSTEM.md    # 本ドキュメント（システム設計）
├── sessions/                 # セッション記録保存
│   ├── 2025-01-06_1500_session.md
│   ├── 2025-01-06_1800_session.md
│   └── ...
├── context/                  # コンテキスト情報
│   ├── current_state.json    # 現在の状態（機械可読）
│   ├── decisions.md          # 重要な決定事項
│   ├── architecture.md       # アーキテクチャ概要
│   └── troubleshooting.md    # よくある問題と解決法
└── handoff/                  # 引き継ぎ専用
    ├── quick_start.md        # 新規参加者向けクイックスタート
    ├── current_priorities.md # 現在の優先事項
    └── blocked_items.md      # ブロックされている項目
```

## 🔄 作業フロー

### 1. セッション開始時
1. `WORK_TRACKING.md` で全体状況を把握
2. `handoff/quick_start.md` で即座に開始可能なタスクを確認
3. `sessions/` の最新セッションで前回の詳細を確認
4. 新しいセッションファイルを `WORK_SESSION_TEMPLATE.md` から作成

### 2. 作業中
1. セッションファイルにリアルタイムで作業ログを記録
2. 重要な決定は `context/decisions.md` に追記
3. 新しい課題は `handoff/blocked_items.md` に記録

### 3. セッション終了時
1. セッションファイルを完成させる
2. `WORK_TRACKING.md` の進捗を更新
3. `context/current_state.json` を更新
4. 次回作業者向けに `handoff/current_priorities.md` を更新

## 📊 状態管理（current_state.json）

```json
{
  "last_updated": "2025-01-06T15:30:00Z",
  "project_phase": "Phase 1 - 基盤構築",
  "overall_progress": 85,
  "current_sprint": {
    "name": "Week 1 - PowerShell廃止",
    "start_date": "2025-01-06",
    "end_date": "2025-01-12",
    "progress": 90
  },
  "active_tasks": [
    {
      "id": "task-001",
      "title": "統合テスト実行",
      "status": "in_progress",
      "assignee": "AI Assistant",
      "priority": "high",
      "estimated_hours": 2,
      "spent_hours": 1.5
    }
  ],
  "blocked_tasks": [
    {
      "id": "task-002",
      "title": "本番環境展開",
      "blocker": "テスト完了待ち",
      "blocked_since": "2025-01-06T14:00:00Z"
    }
  ],
  "technical_context": {
    "main_language": "Python 3.11",
    "framework": "FastAPI",
    "database": "SQLite",
    "test_coverage": 95,
    "last_test_run": "2025-01-06T15:25:00Z",
    "last_test_status": "PASS"
  },
  "environment": {
    "development": {
      "status": "ready",
      "python_version": "3.11.0",
      "venv_path": ".venv",
      "dependencies_updated": "2025-01-06T10:00:00Z"
    },
    "testing": {
      "status": "ready",
      "last_run": "2025-01-06T15:25:00Z",
      "coverage": 95
    }
  }
}
```

## 🚀 新規参加者向けクイックスタート

### 即座に開始可能なタスク
1. **テスト実行**: `python -m pytest tests/ -v`
2. **コード品質チェック**: `python -m black src/ && python -m isort src/`
3. **ドキュメント更新**: 既存MDファイルの情報更新

### 5分で理解できる概要
- **プロジェクト**: PowerShell → Python移行
- **現在フェーズ**: 基盤構築（85%完了）
- **主要技術**: Python 3.11, FastAPI, SQLite
- **テスト**: 95%カバレッジ達成済み

### 重要なコマンド
```bash
# 環境セットアップ
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# テスト実行
python -m pytest tests/ -v --cov=src

# 開発サーバー起動
python src/main.py

# 品質チェック
python -m black src/ tests/
python -m isort src/ tests/
python -m mypy src/
```

## 🔧 高度な作業共有手段の提案

### 1. SQLite + JSON ハイブリッド
**現在の実装**: 軽量で即座に利用可能
- ✅ ファイルベースで簡単
- ✅ バージョン管理可能
- ❌ 同時編集に制限

### 2. MCP (Model Context Protocol) 統合
**提案**: AI間の効率的な情報共有
```python
# mcp_context.py
class MCPContextManager:
    def __init__(self):
        self.context_store = {}
    
    def save_session_context(self, session_id, context):
        """セッションコンテキストをMCP形式で保存"""
        pass
    
    def load_context_for_ai(self, ai_id):
        """AI向けに最適化されたコンテキストを提供"""
        pass
```

### 3. Redis + WebSocket リアルタイム同期
**提案**: 複数AI・セッション間のリアルタイム状態共有
```python
# redis_sync.py
import redis
import json

class RealTimeContextSync:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379)
    
    def publish_state_change(self, change_type, data):
        """状態変更をリアルタイム配信"""
        message = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': change_type,
            'data': data
        }
        self.redis_client.publish('orch_context', json.dumps(message))
```

### 4. GraphQL API + 状態管理
**提案**: 複雑な関係性を持つプロジェクト情報の効率的クエリ
```graphql
type Project {
  id: ID!
  name: String!
  currentPhase: Phase!
  tasks: [Task!]!
  sessions: [Session!]!
}

type Task {
  id: ID!
  title: String!
  status: TaskStatus!
  dependencies: [Task!]!
  assignee: String
}

query GetCurrentContext {
  project(id: "orch-next") {
    currentPhase {
      name
      progress
    }
    tasks(status: IN_PROGRESS) {
      title
      priority
      estimatedHours
    }
  }
}
```

## 📈 推奨実装順序

### Phase 1: 基本構造（現在）
- [x] Markdownベースの作業追跡
- [x] セッションテンプレート
- [x] JSONベース状態管理

### Phase 2: 自動化強化
- [ ] 状態更新の自動化スクリプト
- [ ] セッション間の差分検出
- [ ] 進捗メトリクスの自動計算

### Phase 3: 高度な統合
- [ ] MCP統合（AI間効率化）
- [ ] Redis同期（リアルタイム）
- [ ] GraphQL API（複雑クエリ）

## 🎯 成功指標

- **新規参加時間**: 5分以内でコンテキスト把握
- **作業継続性**: セッション間の情報ロス0%
- **意思決定追跡**: 全ての重要決定が記録・検索可能
- **自動化率**: 状態更新作業の80%以上を自動化

---

**このシステムにより、どのAIや新規セッションでも即座に効果的な作業継続が可能になります。**