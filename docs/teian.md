# TEIAN（提案カバレッジ）統合ドキュメント

本ドキュメントは、ORCH-Next の「提案（teian）」に関する機能要件・最小コアAPI契約・実装/テスト根拠・現在の状態を単一のソースとして統合します。

## 運用方針（境界）
- L0: 自己復旧（プロセス再起動・ポート監視）と観測（ログローテーション）は全自動
- L1: 毎夜の UI/SSE ヘッダ監査（Playwright）は全自動
- L2: 準自動（Waitress再起動・設定反映まで）
- L3: 本番反映は必ず PR＋人手承認（/preview 書換規則・CORS方針変更・サイト差分適用・DB移行）

## 最小コアAPI契約（ドラフト）

site.load { url } → { graph_id }
- 入力: { url: string }
- 出力: { graph_id: string }
- 役割: URL をクロールし Site Graph を生成（ページ/コンポーネント/アセット依存）

site.select { graph_id, by:{ point|css|text|xpath }, scope } → { anchor_id[] }
- 入力: グラフIDと選択方式（座標/セレクタ/テキスト/ XPath）＋スコープ
- 出力: セマンティック・アンカーのID配列（安定参照）

patch.propose { anchors, instruction, constraints } → { diff_id, diffs[], preview_url }
- 入力: 対象アンカー、自然言語指示、制約（min/max/比率/折返し等）
- 出力: 最小 unified diff の配列、プレビューURL、diffの ID

patch.test { diff_id, gates:["html","a11y","perf","visual"] } → { report, pass }
- 入力: diff の ID とテストゲート
- 出力: レポートと合否（4ゲートすべて通過で pass=true）

patch.apply { diff_id, mode:"pr|proxy|browser" } → { apply_id, rollback_token }
- 入力: 適用モード（PR 作成／リバースプロキシ注入／一時ブラウザパッチ）
- 出力: 適用 ID とロールバックトークン

patch.rollback { apply_id, token } → { ok }
- 入力: 適用 ID とトークン
- 出力: 成功可否

## CORS/Expose/SSE の設計原則
- 資格情報付き CORS は "*" を禁止。明示 Origin＋Vary: Origin＋Access-Control-Allow-Credentials: true（[MDN][1]）
- Expose に ETag と X-Preview-* を常時含める（200/4xx/5xx）（[MDN][7]）
- SSE は Content-Type: text/event-stream、Cache-Control: no-cache、X-Accel-Buffering: no を付与（[MDN][2]）
- 本番運用は Waitress（WSGI）を使用（[Waitress docs][3]）
- ログは RotatingFileHandler でローテーション。出力先は data/logs/current/（[Python docs][4]）

## 実装・テスト根拠（抜粋）
- SSE ブループリント登録: src/dashboard.py（SSE blueprint 初期化）; src/blueprints/sse_routes.py
- /preview ヘッダ／書換: src/dashboard.py, src/utils/headers.py（共通化）
- Nightly UI/SSE ヘッダ監査: .github/workflows/playwright-nightly.yml, playwright/tests/

## 現在の状態（要点）
- Expose-Regression-Playwright: 済（CI ワークフロー・E2E を追加済み）
- SSE 推奨ヘッダ: 済（text/event-stream, no-cache, X-Accel-Buffering: no）
- ログ設計: 済（data/logs/current へ統一、ローテーション適用）
- Waitress 常駐: 入口スクリプト・サービス化スクリプトあり（要運用手順）

## 参考（元ドキュメントのポイント集約）
- データ結合/レイアウト/可視化/AI補助/協働/配布運用/品質ダッシュボード特化要素（詳細は旧 teian.txt に記載）
- MCP コマンド設計（site.*, patch.* 系）は上記最小コア API 契約へ統合

---

[1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials
[2]: https://developer.mozilla.org/ja/docs/Web/API/Server-sent_events/Using_server-sent_events
[3]: https://docs.pylonsproject.org/projects/waitress/
[4]: https://docs.python.org/3/library/logging.handlers.html
[7]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS