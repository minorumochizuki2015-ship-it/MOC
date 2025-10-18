# Obsidian Vault × Docker Desktop × MCP 接続ガイド

日付: 2025-10-13

## 概要
- 目的: Obsidian Vault を「記録保管庫」として継続同期し、MCP（Model Context Protocol）経由で参照/追記できる標準的な接続方法を用意する。
- 方針: Docker Desktop 上に MCP ファイルシステム系サーバ（例：Vaultフォルダをルートにした読み書きサーバ）を立て、ホスト側の Vault をコンテナへバインドマウントして提供する。

## 推奨アーキテクチャ
- ホスト: Windows（Docker Desktop）
- コンテナ: MCP FS Server（イメージは利用環境に応じて選択）
- バインドマウント: `C:\Path\To\Obsidian\Vault` → `/vault`
- 公開ポート: `8001/tcp`（例）
- セキュリティ: 必要に応じて読み取り専用、あるいは書き込み可能に設定。アクセス制御や認証はサーバ仕様に従う。

## 手順（例）
1. Vaultパスの決定
   - 例: `C:\Users\User\Documents\ObsidianVault`
2. docker-compose の用意（サンプル）
   - 例（ファイル内容はサーバ実装に合わせて修正）:
     ```yaml
     version: "3.8"
     services:
       mcp-fs:
         image: <MCP_FS_SERVER_IMAGE>
         container_name: mcp-fs-obsidian
         ports:
           - "8001:8001"
         environment:
           - FS_ROOT=/vault
           - FS_MODE=rw  # ro/rw はサーバ仕様に合わせて
         volumes:
           - C:\\Users\\User\\Documents\\ObsidianVault:/vault
     ```
   - 注意: `<MCP_FS_SERVER_IMAGE>` は利用する MCP サーバに合わせて差し替え（実装やドキュメントを参照）。
3. 起動
   - `docker compose up -d`（適切な compose ファイルに対して）
4. MCP クライアント設定（.trae/mcp_servers.yaml 例）
   - 実サーバ仕様に合わせて HTTP/WS 等のエンドポイントを設定:
     ```yaml
     servers:
       - name: obsidian-vault
         type: http
         base_url: "http://localhost:8001"
         permissions:
           - read
           - write
     ```
   - 認証が必要な場合はトークンやヘッダの設定を追加。
5. 動作確認
   - サーバのヘルスエンドポイントがある場合は `http://localhost:8001/healthz` 等で確認。
   - 読み書きAPIの簡易テストを実施（ドキュメント参照）。

## 利点 / 注意点
- 利点:
  - セッション/AIを跨いでも同一のコンテナに集約され、経路が一貫する。
  - バインドマウントにより Vault の即時反映が可能。
- 注意点:
  - Windowsパスのエスケープ（`C:\\`）や権限に留意。
  - コンテナが Vault に書き込む場合は衝突・ロックに注意（Obsidian側の更新タイミングと同期ルールを明記）。
  - 認証/認可、ログの保護、バックアップも合わせて設計。

## 代替・補完案（要件に応じて）
- ネイティブ（非Docker）FSサーバ: 直接ホスト上に MCP サーバを配置すると、パスの取り回しや起動コストが軽い。
- 既存の同期スクリプトとの併用: `scripts/ops/sync_obsidian.ps1` で Vault とプロジェクトの記録を双方向/片方向に同期（軽量運用）。
- MkDocs + GitHub Pages: Git履歴に沿った公開ドキュメント運用（CIで自動化）。
- SaaS（Notion/Confluence）: コラボレーションとAPI連携が容易。

## 運用ルール（標準）
- ポート競合回避: 8001 を利用する場合は起動前に `scripts/ops/check_port.py 8001` で空き確認。
- ヘルス監視: コンテナ側の `/healthz` またはサーバ仕様に沿ったエンドポイントで死活監視。
- 記録標準化: `ORCH/STATE/` や `ORCH/REPORTS/` のMD更新を Obsidian と同期。
- 監査: 変更は PR/承認ログ（`ORCH/STATE/APPROVALS*.md`）へ記録。

## 次アクション（設定支援）
- ご利用予定の MCP ファイルシステムサーバのイメージ（名称・レジストリURL）をご指定ください。docker-composeの具体値を生成し、`.trae/mcp_servers.yaml` に接続設定を追記します。
- Vault の実パスをご共有ください（Windowsのフルパス）。