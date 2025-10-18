# APPROVALS.md

## 承認台帳

| appr_id | task_id | op | status | requested_by | approver | approver_role | ts_req | ts_dec | evidence |
|---------|---------|-------|--------|--------------|----------|---------------|---------|---------|----------|
| A001 | 001 | タスク実装 | approved | WORK | AUDIT | AUDIT | 2025-01-15T10:00:00Z | 2025-01-15T10:30:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\patches\\2024-01\\001-A001.diff.md |
| A002 | 002 | 設定変更 | approved | WORK | CMD | CMD | 2025-01-16T14:00:00Z | 2025-01-16T14:15:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\STATE\\TASKS.md |
| A003 | 003 | データベース更新 | approved | WORK | AUDIT | AUDIT | 2025-01-17T09:00:00Z | 2025-01-17T09:45:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\patches\\2024-10\\003-A003.diff.md |
| A004 | 004 | デプロイメント設定 | approved | WORK | CMD | CMD | 2025-10-07T15:30:00Z | 2025-10-07T15:30:00Z | C:\Users\User\Trae\ORCH-Next\ORCH\patches\2025-10\deploy-004.diff.md |
| A006 | 005 | オーケストレーション自動化実装検証 | approved | WORK | AUDIT | AUDIT | 2025-10-07T16:00:00Z | 2025-10-07T16:30:00Z | C:\Users\User\Trae\ORCH-Next\ORCH\patches\2025-01\005-A006.diff.md |
| A007 | 006 | Phase 3統合テスト実行と機能統合完了 | approved | WORK | AUDIT | AUDIT | 2025-10-07T15:52:00Z | 2025-10-07T15:53:00Z | C:\Users\User\Trae\ORCH-Next\ORCH\patches\2025-10\006-A007.diff.md |
| A008 | WORK-RULES | 作業核ルール更新（ConsoleStay/TerminalOnly導入） | approved | WORK | CMD | CMD | 2025-10-07T17:00:00Z | 2025-10-09T06:25:00Z | C:\Users\User\Trae\ORCH-Next\ORCH\patches\2025-10\WORK-RULES-A008.diff.md |
| A009 | task-registration | TASK_REGISTRATION | approved | WORK | AUDIT | AUDIT | 2025-10-08T07:42:52Z | 2025-10-09T07:45:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\patches\\2025-10\\task-registration-fix4.md |
| A010 | coverage-omit-20251009 | カバレッジ設定一時調整（.coveragerc） | approved | WORK | CMD@manual | CMD | 2025-10-09T06:30:00Z | 2025-10-09T06:35:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\docs\\auto_decide_exceptions.md |
| A011 | eol-locks-20251009 | プロジェクトルール更新（LOCKS書き込みLF統一） | approved | WORK | CMD | CMD | 2025-10-09T07:00:00Z | 2025-10-09T07:02:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\PROJECT_RULES.md |
| A012 | mcp-consistency-win | Windows MCP設定整合性検証とCI追加 | approved | WORK | CMD | CMD | 2025-10-10T08:00:00Z | 2025-10-10T08:10:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\.trae\\mcp_servers.json |
| A013 | 009 | ワークフロー自動化実装検証 | approved | WORK | AUDIT | AUDIT | 2025-10-10T09:20:00Z | 2025-10-10T09:25:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\observability\\junit\\junit.xml |
| A014 | 013 | テスト環境統一・CI Quality Gate強化 | approved | WORK | AUDIT@auto | AUDIT | 2025-10-11T12:00:00Z | 2025-10-11T12:05:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\coverage.xml |
| A015 | 009 | ワークフロー自動化実装 | approved | WORK | CMD | CMD | 2025-10-11T13:00:00Z | 2025-10-11T13:05:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\STATE\\CHECKLISTS\\phase4_execution_checklist.md |
| A016 | 012 | 監視システム監査・改善実装 | approved | WORK | AUDIT | AUDIT | 2025-10-11T13:10:00Z | 2025-10-11T13:15:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\REPORTS\\Monitoring_Audit_Report.md |

| A017 | ui-audit-p0 | UI-Audit P0 実装（semantic anchors・CI artifacts・accountability card） | pending | WORK |  | CMD | 2025-10-13T00:00:00Z |  | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\patches\\2025-10\\diff_card.md |
| A018 | style-preview-fix | スタイルマネージャ／プレビュー統合修正 | approved | WORK | AUDIT | AUDIT | 2025-10-15T12:00:00Z | 2025-10-15T12:10:00Z | C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\LOGS\\2025-10\\A018_style_manager_preview_fix_20251015.md |

## 承認ステータス定義

### ステータス値
- **pending**: 承認待ち
- **approved**: 承認済み
- **rejected**: 却下
- **expired**: 期限切れ

### 承認者ロール
- **CMD**: コマンド実行権限者
- **AUDIT**: 監査実行権限者

## 制約条件

### 承認ルール
1. 
equested_by != approver （自己承認禁止）
2. pprover_role ∈ {CMD, AUDIT}
3. 	s_dec >= ts_req （決定日時は要求日時以降）
4. evidence は実在する Windows 絶対パス必須（`\\` 区切り）

### 更新可能項目
- status: pending → approved/rejected/expired
- pprover: 承認者名
- pprover_role: 承認者ロール
- 	s_dec: 決定日時

### 更新不可項目
- ppr_id: 承認ID
- 	ask_id: タスクID
- op: 操作内容
- 
equested_by: 要求者
- 	s_req: 要求日時
- vidence: 証跡パス

## パス安全性規約
- .. 指定禁止
- ドライブ指定（例: C:）禁止
- 区切り文字は / に正規化

## 更新履歴
- 2024-01-XX: 初版作成、承認A001起票

## 監査官プレイブック（Auditor Playbook）

目的
- 並行テストの実行、ログ収集、結果の差分検証、巻き戻し（ロールバック）判断を体系化する。

前提
- ロール状態・心拍・ハンドオフ: ORCH/STATE/LOCKS/{role_status.json, heartbeat.json, handoff_queue.json}
- 実行手段はクロスプラットフォームの Python を基準とし、環境依存を低減する。

標準手順
1) テスト実行
   - 単一ターミナルでの直列実行: `python scripts/ops/terminal_role_runner.py --role Auditor`
   - 端末分割での並列実行: 各端末で `--role` を変えて起動（Auditor は統合、Executor-* は担当テスト）
2) ログ・結果収集
   - `python scripts/ops/aggregate_multi_terminal_results.py` を実行し、`data/test_results/multi_terminal_summary.json` を生成
3) 齟齬検知・差分検証
   - 期待仕様（tests/ 配下の期待値・契約テスト）と比較し、失敗の原因（UTC時刻、依存関係、Windowsロック等）を特定
4) 巻き戻し基準
   - 重大失敗（契約テスト破綻、セキュリティ回帰、クリティカル警告）は承認保留し、`ORCH/patches/` の直近安定パッチへロールバック
5) 承認記録
   - 本ファイル（APPROVALS.md）の台帳へ、evidence の絶対パスと共に記録（Windows パスは `\\` 区切り）

参考（エージェント連携の活用例）
- Claude Code サブエージェントのベストプラクティス集: VoltAgent コレクション（awesome-claude-code-subagents）。コードレビューや品質・セキュリティ、DevOps など専門エージェントの定義が整理されている。
- Vibe Kanban の活用による複数 AI エージェントのオーケストレーション事例（ダッシュボードで ToDo/InProgress/Done 管理、タスク並列実行の一元化）。

推奨サブエージェントの例
- Code Reviewer（品質の守護者）: コーディング規約チェック、潜在バグ指摘、パフォーマンス改善案、セキュリティ観点レビュー。
- Debugger（バグ退治の専門医）: 根本原因分析、デバッグ手順、メモリリーク検知、ボトルネック特定。
- Refactoring Specialist（リファクタリング職人）: 長大関数分割、命名統一、設計パターン適用、循環的複雑度の低減。
- Database Optimizer（DB最適化）: クエリ最適化、インデックス戦略、スキーマ設計、キャッシュ活用。
- Security Engineer（セキュリティ）: OWASP Top10、依存脆弱性、認証・暗号の実装確認、ベストプラクティス適用。

備考
- 並行実行の有無にかかわらず、監査官は「結果の一元化」と「承認基準の適用」を最優先とする。

### A013 詳細（タスク009：ワークフロー自動化）

- 概要: e2e/coverage/performance/integration の全検証完了。ダッシュボード（5000/5001）起動・接続性健全。
- プレビューURL: 
  - http://localhost:5000/
  - http://localhost:5001/
- HTTP/SSE/SocketIO 精査結果（要約）:
  - 5000: `/`, `/health`, `/status`, `/api/prediction`, `/api/trends`, `/api/metrics`, `/api/trends-schema/dashboard_trends.schema.json` → 全て HTTP 200
  - 5001: `/`, `/health`, `/api/realtime/metrics`, `/api/realtime/alerts`, `/api/realtime/system-status` → HTTP 200
  - 5001: `/socket.io/?EIO=4&transport=polling` → HTTP 200、ハンドシェイク成功
  - 5001: `/events` → サーバ側 200（SSEストリーム）。クライアント側はタイムアウト動作を確認（想定どおり）。
- ポート疎通: 127.0.0.1:5000/5001 ともに TcpTestSucceeded=True
- 統合テスト再実行: `python quick_integration_test.py` → 成功 4/4（ダッシュボード接続 200）
- パフォーマンス推奨: `quick_performance_test.py` → 最適タイムアウト推奨 3s（効率・速度・安定のバランス）
- Evidence（Windows 絶対パス）:
  - C:\\Users\\User\\Trae\\ORCH-Next\\observability\\junit\\junit.xml
  - C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\LOGS\\2025-10\\A013_dashboard_checks_20251011.md

---

## 付録: 承認ルール（正準版）とパス安全性規約・自動検証

### 承認ルール（正準版）
- requested_by != approver（自己承認禁止）
- approver_role ∈ {CMD, AUDIT}
- ts_dec >= ts_req（決定日時は要求日時以降）
- evidence は実在する Windows 絶対パス必須（区切りは `\\`）

### パス安全性規約（Windows 絶対パス準拠）
- 相対パス・`..` 指定は禁止（必ず絶対パス）。
- ドライブレター（例: `C:`）を含むドライブパス、または UNC（例: `\\server\\share\\...`）のみ許可。
- 区切り文字は `\\`（バックスラッシュ）を使用。`/`（スラッシュ）は禁止。
- 証跡ファイルは実在し、読み取り可能であること（CI で検証）。

### 自動検証ルール（CI/ローカル）
- 以下のコマンドで承認台帳・作業記録・チェックリスト内のパス整合性を厳格検証する。
  - `python scripts/ops/validate_orch_md.py --strict`
- CI（.github/workflows/ci.yml）およびローカル手動実行の双方で「All checks passed」を満たすこと。
- 例示（A013 の証跡）:
  - `C:\\Users\\User\\Trae\\ORCH-Next\\observability\\junit\\junit.xml`
  - `C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\LOGS\\2025-10\\A013_dashboard_checks_20251011.md`

- [2025-10-11T04:59:26.024546] Alert WARNING canary_test — 監査・テスト用カナリーアラート（fallback通知と証跡登録の検証）

- [2025-10-11T10:40:21.732140] Alert WARNING coverage_low — テストカバレッジが低下: 79.4%

- [2025-10-11T10:54:32.345772] Alert INFO test — AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:54:33.570756] Alert INFO test — Message 0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:54:34.053040] Alert INFO test — AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:55:30.512763] Alert INFO test — Initial message

- [2025-10-11T10:55:44.754063] Alert INFO test — Large message 0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:57:25.839291] Alert INFO test — Initial message

- [2025-10-11T10:57:26.087588] Alert INFO test — Large message 0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:57:26.562495] Alert INFO test — AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:58:14.442808] Alert INFO test — Initial message

- [2025-10-11T10:58:14.719171] Alert INFO test — Large message 0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:58:15.292626] Alert INFO test — AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

- [2025-10-11T10:58:59.475851] Alert WARNING coverage_low — テストカバレッジが低下: 74.8%

- [2025-10-11T10:58:59.482814] Alert WARNING complexity_high — コード複雑度が高い: 3.34

- [2025-10-11T12:14:39.553350] Alert CRITICAL error_rate_high — エラー率が高い: 10.5%

- [2025-10-11T12:26:19.925955] Alert WARNING coverage_low — テストカバレッジが低下: 78.3%

- [2025-10-11T12:32:59.757518] Alert CRITICAL error_rate_high — エラー率が高い: 9.3%

- [2025-10-11T12:51:59.681851] Alert CRITICAL error_rate_high — エラー率が高い: 10.9%

- [2025-10-11T13:18:05.493310] Alert WARNING coverage_low — テストカバレッジが低下: 71.4%

- [2025-10-11T13:20:26.259964] Alert WARNING complexity_high — コード複雑度が高い: 3.45

- [2025-10-11T13:21:40.424834] Alert CRITICAL error_rate_high — エラー率が高い: 5.5%

- [2025-10-11T13:27:54.846897] Alert WARNING complexity_high — コード複雑度が高い: 3.20

- [2025-10-11T13:29:26.679239] Alert WARNING complexity_high — コード複雑度が高い: 3.57

- [2025-10-11T13:29:26.688095] Alert CRITICAL error_rate_high — エラー率が高い: 7.2%

- [2025-10-11T13:38:23.099456] Alert WARNING coverage_low — テストカバレッジが低下: 77.9%

- [2025-10-11T13:38:23.108764] Alert CRITICAL error_rate_high — エラー率が高い: 7.5%

- [2025-10-11T14:58:36.625236] Alert WARNING coverage_low — テストカバレッジが低下: 71.2%

- [2025-10-11T14:58:36.631428] Alert CRITICAL error_rate_high — エラー率が高い: 9.6%

- [2025-10-11T14:58:36.638387] Alert INFO prediction_uncertain — 予測信頼度が低い: 55.6%

- [2025-10-11T18:13:19.597079] Alert CRITICAL error_rate_high — エラー率が高い: 6.8%

- [2025-10-11T19:12:03.117230] Alert CRITICAL error_rate_high — エラー率が高い: 8.1%

- [2025-10-11T19:12:03.124836] Alert WARNING performance_low — パフォーマンスが低下: 77.7%

- [2025-10-11T19:12:03.131838] Alert INFO prediction_uncertain — 予測信頼度が低い: 57.2%

- [2025-10-11T21:07:25.714208] Alert WARNING coverage_low — テストカバレッジが低下: 71.8%

- [2025-10-11T21:07:25.720731] Alert INFO prediction_uncertain — 予測信頼度が低い: 50.1%

- [2025-10-12T06:04:04.039393] Alert WARNING complexity_high — コード複雑度が高い: 3.74

- [2025-10-12T06:04:04.045944] Alert CRITICAL error_rate_high — エラー率が高い: 11.3%

- [2025-10-12T06:04:04.052593] Alert WARNING performance_low — パフォーマンスが低下: 76.1%

- [2025-10-12T06:20:05.167624] Alert WARNING complexity_high — コード複雑度が高い: 3.21

- [2025-10-12T06:25:25.091415] Alert WARNING coverage_low — テストカバレッジが低下: 77.4%

- [2025-10-12T06:25:25.098662] Alert WARNING complexity_high — コード複雑度が高い: 3.22

- [2025-10-12T06:39:55.483059] Alert WARNING complexity_high — コード複雑度が高い: 3.45

- [2025-10-12T06:39:55.489664] Alert CRITICAL error_rate_high — エラー率が高い: 10.9%

- [2025-10-12T06:39:55.495741] Alert INFO prediction_uncertain — 予測信頼度が低い: 51.1%

- [2025-10-12T06:56:18.497955] Alert WARNING complexity_high — コード複雑度が高い: 3.53

- [2025-10-12T07:40:39.329948] Alert WARNING complexity_high — コード複雑度が高い: 3.43

- [2025-10-12T07:40:39.336069] Alert CRITICAL error_rate_high — エラー率が高い: 11.4%

- [2025-10-12T07:40:39.343421] Alert INFO prediction_uncertain — 予測信頼度が低い: 53.7%

- [2025-10-12T08:26:44.612677] Alert WARNING coverage_low — テストカバレッジが低下: 70.8%

- [2025-10-12T08:26:44.619160] Alert WARNING complexity_high — コード複雑度が高い: 3.61

- [2025-10-12T08:26:44.625030] Alert CRITICAL error_rate_high — エラー率が高い: 8.1%

- [2025-10-12T08:26:44.631991] Alert INFO prediction_uncertain — 予測信頼度が低い: 58.4%

- [2025-10-12T10:25:12.472850] Alert WARNING complexity_high — コード複雑度が高い: 3.52

- [2025-10-12T10:25:12.481714] Alert WARNING performance_low — パフォーマンスが低下: 79.2%

- [2025-10-12T10:25:12.488419] Alert INFO prediction_uncertain — 予測信頼度が低い: 50.7%

- [2025-10-13T17:20:08.726478] Alert WARNING coverage_low — テストカバレッジが低下: 79.1%

- [2025-10-13T18:03:09.546836] Alert WARNING coverage_low — テストカバレッジが低下: 79.3%

- [2025-10-13T18:03:09.553379] Alert WARNING complexity_high — コード複雑度が高い: 3.87

- [2025-10-13T18:03:09.559374] Alert INFO prediction_uncertain — 予測信頼度が低い: 50.0%

- [2025-10-15T06:23:20.762192] Alert CRITICAL error_rate_high — エラー率が高い: 8.7%

- [2025-10-15T06:23:20.780199] Alert INFO prediction_uncertain — 予測信頼度が低い: 67.2%

- [2025-10-15T06:38:10.818370] Alert WARNING complexity_high — コード複雑度が高い: 3.06

- [2025-10-15T06:38:20.829440] Alert CRITICAL error_rate_high — エラー率が高い: 5.7%

- [2025-10-15T06:38:20.837206] Alert WARNING performance_low — パフォーマンスが低下: 75.2%

- [2025-10-15T06:38:20.862029] Alert INFO prediction_uncertain — 予測信頼度が低い: 51.9%

- [2025-10-15T07:24:14.483277] Alert WARNING coverage_low — テストカバレッジが低下: 70.4%

- [2025-10-15T07:24:23.446275] Alert CRITICAL error_rate_high — エラー率が高い: 10.1%

- [2025-10-15T07:24:23.456887] Alert INFO prediction_uncertain — 予測信頼度が低い: 59.4%

- [2025-10-15T10:20:14.999910] Alert CRITICAL error_rate_high — エラー率が高い: 10.8%

- [2025-10-15T10:20:15.012865] Alert INFO prediction_uncertain — 予測信頼度が低い: 53.6%

- [2025-10-18T08:06:06.368826] Alert CRITICAL error_rate_high — エラー率が高い: 10.2%

- [2025-10-18T08:06:06.376826] Alert INFO prediction_uncertain — 予測信頼度が低い: 62.3%
