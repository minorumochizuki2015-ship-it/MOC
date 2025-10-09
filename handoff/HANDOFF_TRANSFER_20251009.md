移管用ハンドオフドキュメント（2025-10-09）

目的
- 現在の作業コンテキストを別アカウントへスムーズに引き継ぎ、即時に作業再開できるようにする。

作業環境
- Workspace: C:\Users\User\Trae\ORCH-Next
- Python: 3.x 推奨（仮想環境 .venv 使用）
- 依存: requirements.txt

初期セットアップ（新アカウント）
1) リポジトリ/プロジェクトフォルダを取得（ORCH-Next ディレクトリを丸ごとコピー、またはGit取得）。
2) 仮想環境作成と依存導入（Windows例）
   - python -m venv .venv
   - .\.venv\Scripts\pip install -r requirements.txt
3) 重要な環境変数（pytest の安定化）
   - PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

直近の実行結果（2025-10-09）
- 単一端末（Auditorロール）直列実行
  - コマンド: python scripts/ops/terminal_role_runner.py --role Auditor
  - 結果: 1 passed, 4 warnings（FastAPI on_event DeprecationWarning 継続）
- 並列テスト（Terminal8〜10）
  - Executor-Contract: 9 failed, 6 passed, 1 error（JWT契約テストの仕様整合不足）
  - Executor-Unit: 2 failed, 23 passed, 18 errors（Windowsファイルロックで PermissionError 多数）
  - Executor-Orchestrator: 10 failed, 10 passed, 2 errors（CORS/DBエラー処理/HTTPコード期待ミスマッチ等）
- 集約
  - コマンド: python scripts/ops/aggregate_multi_terminal_results.py
  - 出力: data/test_results/multi_terminal_summary.json

現在の端末状況（例）
- Terminal6: python orch_dashboard.py 実行中
- Terminal7〜10: テスト用（Auditor/Executor-Contract/Executor-Unit/Executor-Orchestrator）

ロール/ハンドシェイク管理
- ORCH/STATE/LOCKS/
  - role_status.json（ロール状態: idle/in_progress/blocked/completed）
  - heartbeat.json（ロールごとのハートビート）
  - handoff_queue.json（監査官⇄実行者のハンドオフキュー）
- 運用概要: ORCH/STATE/LOCKS/README.md を参照

監査官プレイブック
- ORCH/STATE/APPROVALS.md に追記済み（テスト→収集→差分検証→巻き戻し→承認記録）

エージェント・プロンプト
- docs/AGENT_PROMPTS.md に司令官/監査官/実行者テンプレートを定義
- 参考資料（採用済）
  - Claude Code サブエージェント集: https://github.com/VoltAgent/awesome-claude-code-subagents
  - Vibe Kanban オーケストレーション解説: https://qiita.com/Earthfreedom/items/1209a650ca16f81dd553

追加/更新済みスクリプト
- scripts/ops/terminal_role_runner.py（新規）: ロール別に pytest をクロスプラットフォーム実行
- scripts/ops/aggregate_multi_terminal_results.py（更新）: sys.executable 経由で pytest 実行に変更
- scripts/ops/terminal_role_setup.ps1（既存）: PowerShell 用（現方針は Python ランナー推奨）

テスト実行手順（推奨）
1) 単一端末（直列）
   - python scripts/ops/terminal_role_runner.py --role Auditor
   - python scripts/ops/aggregate_multi_terminal_results.py
2) 並列（複数端末）
   - Terminal7: Auditor → python scripts/ops/terminal_role_runner.py --role Auditor
   - Terminal8: Executor-Contract → python scripts/ops/terminal_role_runner.py --role Executor-Contract
   - Terminal9: Executor-Unit → python scripts/ops/terminal_role_runner.py --role Executor-Unit
   - Terminal10: Executor-Orchestrator → python scripts/ops/terminal_role_runner.py --role Executor-Orchestrator
   - 集約: python scripts/ops/aggregate_multi_terminal_results.py

既知の課題（優先度順）
1) FastAPI Lifespan へ移行（on_event DeprecationWarning 解消）
2) JWT 契約テストの失敗修正（UTC時刻整合、失効・スキュー許容、エッジ期限処理）
3) Windows ファイルロック対策（TemporaryDirectory/close/flush、共有モード・リトライ導入）
4) orchestrator ユニットの期待仕様整備（CORSヘッダ、DBエラー、HTTPステータス）
5) 残存 utcnow の置換（dispatcher.py / lock_manager.py / monitor.py 等）

関連ファイル
- src/security.py（UTC対応進行中、例: details の JSON ログ行付近）
- src/orchestrator.py（一部 UTC対応済。startup/shutdown は Lifespan へ移行予定）
- tests/contract/test_jwt_contract.py（多数の失敗が発生）
- tests/test_security.py（Windows の PermissionError 多数）
- tests/test_orchestrator.py（CORS/DB/HTTPコードの失敗あり）

成果物・ログ
- data/test_results/multi_terminal_summary.json（直近の並列テスト集約結果）
- ORCH/LOGS/2025-10/（運用ログ保管）
- ORCH/REPORTS/（フェーズレポート類）

再開推奨フロー（新アカウント）
1) 仮想環境の準備と依存インストール
2) Auditor 直列テストでベースライン確認
3) Lifespan への移行を先行実装 → pytest 再実行
4) JWT 契約テストの仕様調整 → 再実行
5) Windows ファイルロック対策適用 → security/orchestrator の再実行
6) 並列テスト + 集約 → ORCH/STATE/APPROVALS.md に承認記録

補足
- pytest のプラグイン自動読み込みは環境差の原因になるため、PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 を推奨。
- 本ドキュメントの更新日: 2025-10-09。