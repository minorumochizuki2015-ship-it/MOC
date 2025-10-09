# Traeクレジット1QAベンチマーク計画

目的
- 「1度のクレ消化（1QA）」で許容される推論時間、推論回数、処理タスク数、出力文字数の上限と、回答品質への影響を定量評価し、費用最適化（QA集約）と運用パラメータ（待機時間・出力上限）を確定する。

評価指標（ログ項目）
- session_id, qa_id: セッション／QA集約ID。
- k: 集約係数（1QA内で処理するやり取り数）。候補: 1, 2, 3, 4。
- tasks_count: 1QA内のタスク数（1, 2, 3, 4）。
- output_chars: 出力文字数（実測）。候補上限: 8k / 10k / 15k。
- think_cycles: 内部推論ステップ（進捗ログから近似カウント）。
- tool_calls: ツール呼び出し回数（ファイル参照・解析など）。
- t_first_token: 最初の応答断片（SSE）までの時間。
- t_total: 1QA完了までの総時間（QAウィンドウ滞留時間含む）。
- quality_scores: 可読性・正確性・再現性・テスト合格率・静的解析（quality_criteria.mdに準拠）。

前提・制約
- Traeの課金: 1質問=1クレ、1回答=1クレ → 1QA=2クレ消費。
- 入力制限: 6,000文字。出力制限: 不明（~20,000文字想定）。
- 文字制約対策: パス参照優先、ローリング要約（~800–1,000字）で文脈維持、出力は章分割。

テストマトリクス（代表ケース）
- k ∈ {1, 2, 3, 4} × tasks_count ∈ {1, 2, 3, 4} × output_cap ∈ {8k, 10k, 15k} 文字。
- QA許容待機時間（ウィンドウ）候補: 3分 / 5分 / 8分。
- 計測カテゴリ（3種類×各5ケース）:
  1) Kanban同期（要約・整合チェック・差分適用）
  2) 小規模コード修正（単ファイル、テスト1–2件）
  3) 中規模設計更新（MD編集・差分生成・影響箇所列挙）

計測プロトコル
1. QAウィンドウ内で複数タスクをストリーミング（SSE）進捗で可視化。回答は1QAで閉じない（最小限のクレ消費）。
2. 進捗ログにチェックポイント（checkpoint_id）を付与。中断時はresume_tokenで再開。
3. 入力は6,000文字以下に維持（パス参照＋差分要約）。
4. 出力はoutput_capを厳格に設定（8k/10k/15k）。
5. 品質評価はquality_criteria.mdの観点＋tests/integration・tests/loadの再利用で測定。

計測実装（インストルメンテーション）
- src/orchestrator, src/monitor に以下を追加予定:
  - SSE進捗ログに計測ID（session_id, qa_id, checkpoint_id）を付与。
  - t_first_token/t_totalの自動計測。
  - think_cycles/tool_callsの収集（簡易カウント）。
- ログ保存場所: ORCH/LOGS/2025-10/trae_credit_bench/*.json。

ログJSONスキーマ（案）
```json
{
  "session_id": "string",
  "qa_id": "string",
  "k": 1,
  "tasks_count": 3,
  "output_cap": 10000,
  "output_chars": 9876,
  "think_cycles": 12,
  "tool_calls": 3,
  "t_first_token_ms": 850,
  "t_total_ms": 278000,
  "quality_scores": {
    "readability": 0.90,
    "accuracy": 0.92,
    "reproducibility": 0.88,
    "tests_pass_rate": 0.95,
    "static_analysis_score": 0.93
  },
  "category": "kanban_sync|code_fix|arch_update",
  "window_minutes": 5,
  "checkpoint_ids": ["cp1", "cp2"],
  "timestamp": "2025-10-09T00:00:00Z"
}
```

意思決定基準（例）
- 待機時間: 95パーセンタイルが8分以内ならk≥3を許容、3–5分以内ならk=4も検討。
- 品質: accuracy/再現性/テスト合格率が0.9以上を維持できるk・output_capを採用。
- コスト: 300–400やり取り/日の月額目標（例: k=3で$120–$160/月）に収まる構成を優先。

スケジュール（今週金曜固定）
- D0: 計測フック設計・ログ仕様反映・テスト準備。
- D1: 計測実施（3カテゴリ×各5ケース×マトリクス）。
- D2: 分析・意思決定（最適k、出力上限、待機時間）→ マイルストーン改定に反映。
- 金曜: レビュー・承認・固定（CURRENT_MILESTONE.mdに参照追記）。

成果物
- ORCH/REPORTS/trae_credit_benchmark_report_20251009.md（計測結果と提案）。
- MILESTONE_OVERRIDE_20251010.md 改定（計測ゲート・予算ゲート・集約ポリシー）。

ユーザー確認事項（開始前）
- QA許容待機時間の候補（3/5/8分）と望ましい中央値。
- 1QAの最大出力文字上限（8k/10k/15kのいずれか）。
- 代表タスク例（各カテゴリで5ケースを準備するため）。