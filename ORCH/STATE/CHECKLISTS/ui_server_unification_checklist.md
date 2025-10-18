# UI サーバ統一チェックリスト（2025-10-13）

## 目的
複数起動によるポート競合を防ぎ、Flask サーバを単一運用へ統一する。

## チェック項目
- [x] 重複プロセスの検出（`python src/dashboard.py` と `flask run`）
- [x] 競合プロセスの停止（`python src/dashboard.py` 終了）
- [x] 単一サーバの稼働確認（`flask run` のみ）
- [x] UI ページの実地確認（/dashboard, /style-manager）
- [ ] ヘルスチェック `/healthz` の実装
- [ ] CI での起動判定（curl /healthz）
- [ ] UI e2e テスト（Playwright）を CI に追加

## 備考
将来的に `blueprints/ui_routes.py` への集約を検討（保守性向上）。