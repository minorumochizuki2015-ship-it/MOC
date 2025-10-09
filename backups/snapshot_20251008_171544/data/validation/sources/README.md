search/math 参照ソース取り込みガイド

目的
- 外部ソース（Git/ウェブ）から検索・数学の参照データを取得し、検証用に安全・再現可能・監査可能な形で保存する。

保存場所
- data/validation/sources/
  - search_corpus/  : 検索評価用のテキスト・HTML・JSON
  - math_corpus/    : 数学問題・解説・式（テキスト/JSON）

取得方法
- scripts/ops/fetch_reference_sources.py と scripts/ops/fetch_sources_config.json を使用。
- 取得先と保存先、ライセンス情報を config に定義。

注意事項
- ライセンスと出典の明記（再配布可否、引用条件、PII除去）。
- 大容量ファイルの取得は避け、必要に応じて要約・抽出を行う。
- 取得ログは summaries/ に記録（キャンペーン単位）。