benchmarks ディレクトリ構造

- data/validation/benchmarks/
  └── <campaign_id>/
      ├── raw/
      ├── normalized/
      ├── summaries/
      └── reports/

使い分け
- raw: 収集したままのログ（再現のため削除しない）
- normalized: スキーマ準拠のJSON（分析の主データ）
- summaries: 集計結果（metrics, percentile 等）
- reports: ヒト向けの短報／詳細報（ORCH/REPORTS へのリンクを付与）