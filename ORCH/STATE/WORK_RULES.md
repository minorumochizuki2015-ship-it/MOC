# WORK_RULES — ConsoleStay/TerminalOnly 運用

目的
- 会話コンソールでの報告は最小限に留め、端末（Terminal）でのログ・MD更新・作業のみを継続する。

基本方針
1. ConsoleStay: セッション終了やタスク完了を誘発する要約・締めの報告は禁止。
2. TerminalOnly: 監視・監査・検証・ビルド・テストは端末で実施し、レポートは MD/LOG へ追記する。
3. 状態維持: 状態機械は DOING/REVIEW を維持。finish/完了宣言は行わない。
4. 重大時通知: MAJOR のみ会話コンソールへ一行通知。通常は端末出力/MD追記のみ。

設定・ファイル
- ORCH-Next/ORCH/STATE/LOCKS/console_mode.json: {"mode":"stay"}
- ORCH-Next/ORCH/STATE/LOCKS/role_status.json: 各ロールの in_progress を維持
- ORCH-Next/ORCH/STATE/LOCKS/heartbeat.json: 3分以内の心拍を維持

監査・監視
- 3分監視: Terminal 5 で継続。MDは ORCH-Next/ORCH/REPORTS/autopilot_audit_agents_metrics.md に追記
- 30秒監視: 必要時のみ起動。ログは ORCH-Next/ORCH/LOGS/2025-10/autopilot_monitor_session.log

更新履歴
- 2025-10-09: ConsoleStay/TerminalOnly ルール初版
 - 2025-10-11: ルール再確認（Windows絶対パス義務・finish禁止・DOING/REVIEW維持を再周知）。WORK_TRACKING.md にポリシー準拠のログ追記。

---
## 2025-10-12 追記 — SSE運用標準 / バージョン可視化 / EOLゲート

SSE運用標準（必須ヘッダ）
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache`
- `Connection: keep-alive`
- `X-Accel-Buffering: no`（Nginx/Traefik/IIS 等のバッファリング抑制）

バージョン可視化（起動時ログ）
- ダッシュボード起動時に `__file__` の絶対パスを INFO ログ出力して稼働実体を明示（誤起動/バックアップ起動を検知）。

EOL/Encodingゲート（CI必須）
- 全資産を UTF-8 / LF に統一。CRLF混在・非UTF-8は CI FAIL。
- 監視ガード: `scripts/ops/locks_eol_guard.py` を常時稼働（`ORCH/STATE/LOCKS/**` をLFへ自動正規化）。
- テスト: `tests/unit/test_eol_locks.py` を必須化。

---
## 2025-10-11 追記 — ユニットテスト品質ルール / CI Gate 強化

ユニットテスト品質ルール
- 依存注入（DI）を原則義務化。ユニットテストでは外部I/O（ネットワーク・ファイル・DB）をモック化し、決定論的に実行する。
- 非同期例外の扱い: バックグラウンドタスク/スレッドでの未捕捉例外（PytestUnraisableExceptionWarning）は FAIL として扱う。
- モジュール境界のテストは、状態・副作用（ログ/ファイル/スレッド）を明示的に検証する。

CI Gate（品質ゲート）
- lint = 0（ruff/flake8）
- unit/integration tests 合格（変更対象モジュール）
- coverage ≥ 80%
- secrets / EOL チェック OK
- e2e OK、主要エンドポイント（SSE/SocketIO）HTTP 200

pytest.ini 強化（推奨設定）
- filterwarnings を追加して Unraisable を ERROR 化:
  ```ini
  [pytest]
  filterwarnings =
      error::pytest.PytestUnraisableExceptionWarning
  ```

運用メモ
- ユニットテストで外部サービス連携が必要な場合、contract/integration 階層へ移動。
- 例外監視は sys.unraisablehook / threading.excepthook の活用を検討（Python 3.8+）。

---
## 2025-10-14 追記 — DB接続管理ルール（sqlite3）

目的
- ResourceWarning（未クローズ接続）をゼロにし、トランザクションの整合性を保つ。

ルール
- 物理クローズ保証: 常に `with closing(sqlite3.connect(path, timeout=5.0)) as conn:` を使用。
- トランザクション管理: 書き込み時は `with conn:` を併用して自動 commit/rollback を適用。`conn.commit()`/`conn.close()` の手動呼び出しは禁止。
- 初期化時PRAGMA: 初期化メソッドで `PRAGMA journal_mode=WAL;` / `PRAGMA busy_timeout=3000;` / `PRAGMA foreign_keys=ON;` を設定。
- 読み取りクエリ: 読み取りでも `closing(...)` を使用（カーソルやコネクションの確実なクローズ）。
- テストゲート: `pytest -W error::ResourceWarning` を必須化し、回帰を防止。

対象
- src/automated_approval.py（適用済み）
- src/lock_manager.py / src/monitor.py / その他 `sqlite3.connect` を含む箇所（適用予定）
