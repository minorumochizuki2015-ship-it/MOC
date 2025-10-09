# MOCシステム移行計画書

## 概要
- **作成日**: 2025-01-XX
- **対象**: 既存MOCシステム → ORCH-Nextへの移行
- **移行方式**: 段階的移行（Phase 1-3）
- **完了予定**: 2025-02-XX

## 現状分析

### 既存MOCシステム構成
```
C:\Users\User\Trae\MOC\
├── ORCH\                    # 主要システム
│   ├── orch_dashboard.py    # メインダッシュボード（2412行）
│   ├── scripts\ops\         # PowerShellスクリプト群
│   │   └── Task-Dispatcher.ps1  # タスクディスパッチャ（89行）
│   ├── STATE\               # 状態管理
│   │   ├── TASKS.md         # タスク台帳
│   │   └── APPROVALS.md     # 承認台帳
│   └── integrated_config.json  # 統合設定
├── src\                     # Pythonソースコード
├── requirements.txt         # 依存関係
└── main.py                  # エントリーポイント
```

### 主要依存関係
```
# Core clients
openai>=1.40.0
requests>=2.31.0
google-generativeai>=0.7.2

# Web framework
fastapi>=0.110.0
uvicorn>=0.27.0
flask
flask-cors
flask-socketio

# Optional
numpy>=1.26.4
qutip>=5.0.3
```

### 重要コンポーネント
1. **orch_dashboard.py**: メインダッシュボード（Flask + SocketIO）
2. **Task-Dispatcher.ps1**: PowerShellベースのタスクディスパッチャ
3. **STATE管理**: TASKS.md, APPROVALS.md（SSOT）
4. **WebSocket統合**: リアルタイム通信
5. **知識DB**: KnowledgeStore, MLEngine統合

## 移行戦略

### Phase 1: 基盤移行（優先度: HIGH）
**期間**: 1週間
**目標**: 基本機能の移行と動作確認

#### 1.1 設定ファイル移行
- [ ] `requirements.txt` → `ORCH-Next/requirements.txt` 統合
- [ ] `integrated_config.json` → `config/production.json` 統合
- [ ] 環境変数設定の統一

#### 1.2 STATE管理移行
- [ ] `MOC/ORCH/STATE/TASKS.md` → `ORCH-Next/ORCH/STATE/TASKS.md`
- [ ] `MOC/ORCH/STATE/APPROVALS.md` → `ORCH-Next/ORCH/STATE/APPROVALS.md`
- [ ] スキーマ互換性確認

#### 1.3 ログ・データ移行
- [ ] `MOC/ORCH/LOGS/` → `ORCH-Next/data/logs/`
- [ ] `MOC/data/` → `ORCH-Next/data/`
- [ ] バックアップ作成

### Phase 2: コア機能移行（優先度: HIGH）
**期間**: 1週間
**目標**: PowerShell → Python移行

#### 2.1 Task-Dispatcher移行
```diff
- MOC/ORCH/scripts/ops/Task-Dispatcher.ps1 (PowerShell)
+ ORCH-Next/src/dispatcher.py (Python)
```

**移行内容**:
- [ ] `Dispatch-Task` → `dispatch_task()`
- [ ] `Get-SystemStats` → `get_system_stats()`
- [ ] `Run-MonitorLoop` → `monitor_loop()`
- [ ] ロック管理統合

#### 2.2 Dashboard統合
```diff
- MOC/orch_dashboard.py (2412行)
+ ORCH-Next/src/dashboard.py (統合版)
```

**統合内容**:
- [ ] Flask設定統合
- [ ] WebSocket機能統合
- [ ] テンプレート統合
- [ ] API エンドポイント統合

### Phase 3: 高度機能移行（優先度: MEDIUM）
**期間**: 1週間
**目標**: 知識DB・ML機能統合

#### 3.1 知識データベース統合
- [ ] `KnowledgeStore` → ORCH-Next統合
- [ ] `MLEngine` → AI予測システム統合
- [ ] データマイグレーション

#### 3.2 WebSocket・リアルタイム機能
- [ ] `dashboard_websocket.py` 統合
- [ ] `realtime_sync.py` 統合
- [ ] SSE/Webhook統合

## 技術的課題と対策

### 1. PowerShell依存の解消
**課題**: Task-Dispatcher.ps1の89行PowerShellコード
**対策**: 
- Python `dispatcher.py` で完全置換
- 既存機能の1:1移植
- テスト駆動開発で品質確保

### 2. Flask設定の統合
**課題**: 2つのFlaskアプリケーションの統合
**対策**:
- 設定ファイルの統一
- テンプレート・静的ファイルの統合
- CORS設定の統一

### 3. 状態管理の互換性
**課題**: TASKS.md, APPROVALS.mdのスキーマ差異
**対策**:
- スキーマ検証ツール作成
- 移行時データ検証
- ロールバック機能

### 4. 依存関係の競合
**課題**: requirements.txtの重複・競合
**対策**:
- 依存関係解析
- バージョン統一
- 仮想環境分離

## 移行手順

### 事前準備
```bash
# 1. バックアップ作成
cp -r C:\Users\User\Trae\MOC C:\Users\User\Trae\MOC_backup_$(date +%Y%m%d)

# 2. 依存関係確認
cd C:\Users\User\Trae\ORCH-Next
.\.venv\Scripts\python.exe -m pip list > current_deps.txt

# 3. MOC依存関係確認
cd C:\Users\User\Trae\MOC
.\.venv\Scripts\python.exe -m pip list > moc_deps.txt
```

### Phase 1実行
```bash
# 1. 設定ファイル統合
python scripts/migrate_config.py --source MOC --target ORCH-Next

# 2. STATE管理移行
python scripts/migrate_state.py --validate --backup

# 3. データ移行
python scripts/migrate_data.py --logs --metrics
```

### Phase 2実行
```bash
# 1. Dispatcher移行
python scripts/migrate_dispatcher.py --test --validate

# 2. Dashboard統合
python scripts/migrate_dashboard.py --templates --static --api

# 3. 統合テスト
python -m pytest tests/integration/test_migration.py -v
```

### Phase 3実行
```bash
# 1. 知識DB統合
python scripts/migrate_knowledge.py --data --schema

# 2. WebSocket統合
python scripts/migrate_websocket.py --realtime --sse

# 3. 最終テスト
python scripts/test_full_migration.py --comprehensive
```

## 品質保証

### テスト戦略
1. **単体テスト**: 各移行コンポーネント
2. **統合テスト**: システム間連携
3. **E2Eテスト**: ユーザーシナリオ
4. **性能テスト**: レスポンス時間・メモリ使用量

### 受入基準
- [ ] 全機能が移行後も正常動作
- [ ] 性能劣化なし（±5%以内）
- [ ] データ整合性100%
- [ ] セキュリティ要件満足

### ロールバック計画
1. **即座ロールバック**: 設定ファイル復元
2. **データロールバック**: バックアップからの復元
3. **完全ロールバック**: MOCシステムへの切り戻し

## リスク管理

### 高リスク項目
1. **データ損失**: バックアップ戦略で対応
2. **機能欠損**: 段階的移行で早期発見
3. **性能劣化**: 継続的監視で対応
4. **互換性問題**: 事前検証で対応

### 緊急時対応
- **緊急連絡先**: CMD, AUDIT
- **エスカレーション**: 24時間以内
- **復旧目標**: 4時間以内

## 完了条件

### Phase 1完了条件
- [ ] 設定ファイル統合完了
- [ ] STATE管理移行完了
- [ ] データ移行完了
- [ ] 基本動作確認完了

### Phase 2完了条件
- [ ] PowerShell → Python移行完了
- [ ] Dashboard統合完了
- [ ] API互換性確認完了
- [ ] 統合テスト合格

### Phase 3完了条件
- [ ] 知識DB統合完了
- [ ] WebSocket統合完了
- [ ] 全機能テスト合格
- [ ] 性能要件満足

### 最終完了条件
- [ ] MOCシステム停止可能
- [ ] ORCH-Next完全稼働
- [ ] ドキュメント更新完了
- [ ] 運用手順書完成

## 次ステップ
1. Phase 1実行承認取得
2. 移行スクリプト作成
3. テスト環境構築
4. 段階的移行実行

---
**更新履歴**
- 2025-01-XX: 初版作成
- 2025-01-XX: 依存関係調査完了
- 2025-01-XX: 移行手順詳細化