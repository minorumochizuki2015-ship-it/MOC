# Obsidian × MCP 連携ガイド（記録保管庫の標準化）

日付: 2025-10-13

## 目的
- すべてのセッション/AIが同一ルールで記録・確認・保存を行える「記録保管庫」を用意し、運用の一貫性を担保する。
- ポート利用状況、ヘルスチェック、作業報告、承認履歴などを継続的に保管。

## 推奨構成（フォルダ同期型）
- Obsidian Vaultに、以下のディレクトリを同期（読み書き可能）:
  - `docs/`（運用ルール・ランブック・ポートREADME）
  - `ORCH/STATE/`（APPROVALS, PORTS スナップショット）
  - `ORCH/REPORTS/`（監査・レポート）
  - `ORCH/LOGS/`（日次ログ）
- 方式: Vault配下にプロジェクトの該当ディレクトリをコピー/同期、もしくはシンボリックリンク。

## MCP 統合（ファイルシステムサーバ例）
- `.trae/mcp_servers.yaml` に、Vault をファイルシステムサーバとして登録（例）:
  ```yaml
  servers:
    - name: obsidian-vault
      type: filesystem
      root: "C:\\Path\\To\\Obsidian\\Vault"
      permissions:
        - read
        - write
  ```
- 注意: 実環境のMCPサーバ仕様に合わせて `type` と `root` を調整。Obsidian用のMCPプラグインがある場合は、その仕様に従い設定すること。

## 運用オートメーション
- ポートスナップショットの自動生成: `scripts/ops/write_port_snapshot.ps1` をタスクスケジューラで日次実行。
- Vault同期: `scripts/ops/sync_obsidian.ps1 -VaultPath <VaultPath>` を起動/終了時に実行。

## 標準ルール（セッション/AI 共通）
1. サーバ起動前にポートチェック（`scripts/ops/check_port.py` または `scripts/ops/start_ui_server.ps1`）。
2. ヘルス確認（`GET /healthz`）。
3. 変更・発見事項は `ORCH/STATE/` と `ORCH/REPORTS/` にMDで追記。
4. Obsidian Vaultへ同期（上記スクリプト）。

## 代替案（用途に応じた最善策）
- MkDocs + GitHub Pages: Git履歴と公開ドキュメントの両立。CIで自動公開。
- Notion/Confluence等のSaaS: コラボレーション重視。APIで自動記録も可能。
- Elastic/Meilisearch等で全文検索ログ保管: 検索性・集約性を重視。
- S3/SharePoint等のバイナリ含む保管庫: 監査/法的要件に強い。

## セキュリティ・衝突回避
- 重複ポート起動防止ルール遵守（README_PORTS.md 参照）。
- Vault同期は「最終更新日時」を優先し、衝突時は手動マージ。
- 機密情報は `docs/` ではなく、アクセス制御付きの `ORCH/STATE/` のみに保存。