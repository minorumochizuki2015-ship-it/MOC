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
