# 外部参照ソース選定とフィルタ条件（search/math/code_fix）

目的
- 検証用の参照ソース（Git/Web）を安全・再現可能・監査可能な形で取得し、汚染を避けつつテスト資産を充実化する。

優先選定方針
- ライセンスが明確で再利用可（MIT/Apache-2.0/BSD/CC BY系など）。
- テキスト主体（画像・大容量バイナリは避ける）。
- 出典URL・取得日時を記録し、再現可能。

候補リスト（例）
- search（CC BY-SA/CC BY/GPL系は注意）
  - Wikipediaの特定テーマ記事（CC BY-SA 4.0、要クレジット／SA）
  - gov/open-dataの説明ページ（CC BY 4.0 等）
  - 技術ブログでCC BY/MIT表記のもの（出典明記）
- math（MIT/Apache/BSD優先）
  - GSM8K（多段推論の算数、MITライセンス）
  - MathQA（QA形式の数学問題、MIT系・要確認）
  - ASDiv（式変形の算数問題、ライセンス要確認）
- code_fix（小規模MIT/Apache/BSDリポジトリ）
  - TheAlgorithms/Python（MIT、アルゴリズムの小修正に適）
  - 小規模ユーティリティのMIT/Apacheリポジトリ（例：文字列処理）

フィルタ条件（推奨デフォルト）
- 共通
  - language: ["ja", "en"] 以外は除外
  - mime: text/plain, text/html, application/json のみ
  - doc_text_char_max: 20000、doc_text_char_min: 200
  - pii_scrub: email/phone/address を簡易マスキング
  - dedup: sha256で重複除去
- search 特化
  - topic_whitelist: ["情報検索", "ソート", "ベクトル検索", "評価指標"]
  - table_strip: HTMLテーブルは本文に整形
- math 特化
  - require_steps: 解法手順（step-by-step）が含まれるものを優先
  - allow_latex: LaTeX式をテキストで保持（$...$ のまま保存）
  - image_exclude: 画像のみの問題は除外
- code_fix 特化
  - repo_size_max_mb: 50MB 以下
  - file_types: [".py", ".md", ".json"]
  - test_presence_preferred: 既存テストがあるものを優先

運用
- 取得設定は scripts/ops/fetch_sources_config.json に定義。
- 取得は scripts/ops/fetch_reference_sources.py で実行。
- 正規化は scripts/ops/normalize_sources.py と scripts/ops/source_filters.json に準拠。
- 保存先は data/validation/sources/（search_corpus, math_corpus）に限定する。

承認事項（ユーザー入力）
- 具体URL/リポジトリ（5–10件）と各カテゴリの優先度。
- ライセンス確認（再配布可否、出典の表記方法）。
- フィルタ条件の微調整（文字長、言語、トピック、除外規則）。