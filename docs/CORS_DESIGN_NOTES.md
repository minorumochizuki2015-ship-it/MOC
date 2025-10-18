# CORS 設計ノート

最終更新: 2025-10-15

## 資格情報（credentials）使用時の原則
- `Access-Control-Allow-Origin: *`（ワイルドカード）は、資格情報（`withCredentials`、Cookie、Authorization ヘッダ）を伴う要求では許容されない。
- 原則として、明示オリジン（例: `Access-Control-Allow-Origin: http://127.0.0.1:5001`）を返す。
- その際、`Vary: Origin` を付与し、キャッシュ対象がオリジンごとに分離されるようにする。

参考: MDN Web Docs（CORS、Credentials）

## ダッシュボード運用への適用
- ORCH ダッシュボード（Flask/SocketIO）の CORS は統一設定で管理し、開発環境では `localhost` 系の明示オリジンを返す。
- ゲートウェイ（FastAPI）は CORSMiddleware を用い、同様に明示オリジン + `Vary: Origin` をベースとする。

## /preview に関する補足
- `/preview` は編集プレビューに該当し、`Cache-Control: no-store` を必須とする（ブラウザキャッシュを残さない）。
- 監査・トレース容易化のため、`X-Preview-Origin`（プレビュー元サーバのオリジン）と `X-Preview-Target`（要求されたターゲットURL）を応答に付与する。