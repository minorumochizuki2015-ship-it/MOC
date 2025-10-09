検証データ保存ポリシー

目的
- ベンチマークや検証用の生データ・正規化データ・派生レポートを、運用ディレクトリと分離して保存し、履歴・再現性・監査性を確保する。

保存場所
- data/validation/benchmarks/<campaign_id>/
  - raw/            : 計測で得た生ログ（SSE/HTTPレスポンスなど）
  - normalized/     : ログスキーマに合わせたJSON（docs/Trae_Credit_Benchmark_Plan.md参照）
  - summaries/      : 集計・要約（CSV/JSON/MD）
  - reports/        : 人間向けレポート（MD/HTML）。ORCH/REPORTSとのリンクを持つ。

命名規約
- campaign_id は日付やテーマを含める（例: trae_credit_bench_20251009）。
- ファイルは prefix_yyyymmdd_hhmmss.ext を推奨。

注意事項
- PIIや秘匿情報は保存しない。必要に応じてマスキングする。
- 大容量バイナリは原則禁止。必要な場合は artifacts/ に移し、ここにはメタ情報のみ保存。
- コード・設定変更の成果物は src/ や config/ に置き、ここには検証結果のみ。