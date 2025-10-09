# Traeクレジット1QAベンチマーク レポート（テンプレート）

概要（Executive Summary）
- 今回の目的、対象期間、主要結論（推奨k、出力上限、待機時間、月次キャップ）。

計測条件
- QAウィンドウ: 3/5/8分（採用値を明記）
- 出力上限: 8k/10k/15k（採用値を明記）
- マトリクス: k×tasks_count×output_cap
- カテゴリ: kanban_sync / code_fix / arch_update（各5ケース）

結果サマリ（表）
- k別 t_first_token/t_total（中央値・95パーセンタイル）
- 出力文字数（平均・最大）
- think_cycles / tool_calls（平均）
- quality_scores（平均）：readability/accuracy/reproducibility/tests_pass_rate/static_analysis

詳細結果（セクション）
- カテゴリ別のケース一覧とログ参照（ORCH/LOGS/2025-10/trae_credit_bench/*.json）
- ボトルネック分析（待機時間・出力超過・品質劣化要因）

意思決定（提案）
- 推奨集約係数 k = __
- 推奨出力上限 = __ 文字
- 推奨QA許容待機時間 = __ 分
- 推奨月次キャップ = __ （日次300/400やり取りシナリオ別に算定）

運用ガード（config/monitoring.jsonへの反映案）
- 閾値通知: 月次80%到達、日次ペース超過（>400）で通知
- 縮退: kを1段階下げる、出力上限を10–20%引き下げ
- 承認: 臨時増枠は承認必須（期間と上限明記）

マイルストーン改定
- MILESTONE_OVERRIDE_20251010.mdへ反映する変更点（決定事項・ゲート条件）
- CURRENT_MILESTONE.mdに参照追記

付録
- ログスキーマ／測定定義（docs/Trae_Credit_Benchmark_Plan.md）
- 評価基準（quality_criteria.md）

作成者・日時
- 作成者: __
- 日付: 2025-10-09