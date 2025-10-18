# 変更ガード宣言（雛形）

最終更新: 2025-10-13  
責任者: me

この雛形は「保護ファイルを含む変更」を安全に適用するための宣言テンプレートです。Plan → Test → Patch の3段階で運用し、Windows絶対パス準拠・最小差分・証跡の明文化を徹底します。

---
## Plan（計画）
- 変更ID: <ID>
- 目的: <目的を記載>
- 影響範囲: <影響対象・スコープ>
- 代替案: <代替の可否と選定理由>
- 対象ファイル（保護対象を含む／Windows絶対パス）:
  - 例: `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\MILESTONES.md`
  - 例: `C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml`
- 差分計画（最小 unified diff の方針）:
  - 変更箇所を限定し、不要な再整形・ホワイトスペース変更を禁止
  - 機密値（APIキー等）は差分・ログに含めない

## Test（検証）
- フォーマット: black / isort（必要範囲のみ）
- 型検査: `mypy --strict`（該当ディレクトリに限定）
- テスト: pytest（該当範囲）
- ポート確認: 8001 の競合検査（MCP FS 想定）
  - `C:\Users\User\Trae\ORCH-Next\.venv\Scripts\python.exe C:\Users\User\Trae\ORCH-Next\scripts\ops\check_port.py 8001`
- 健全性: 起動/停止の挙動・healthz(200) 事前確認
- Dry-Run: 書込前に全検証 PASS を確認（Dry-Run を既定）
- 証跡: `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_YYYYMMDD.md`（`write_port_snapshot.ps1` 出力）

## Patch（適用）
- 承認後に原子的書込（失敗時は即ロールバック）
- 機密値は出力・ログへ残さない
- EOL/encoding は UTF-8 LF（*.bat のみ CRLF）
- 適用手順と結果を WORK_TRACKING.md に追記

## 承認フロー・証跡
- 承認記録: `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\APPROVALS.md`
- 変更差分: `C:\Users\User\ORCH\patches\<ID>_<DATE>.patch`（参考保管）
- 実行ログ: `C:\Users\User\Trae\ORCH-Next\ORCH\LOGS\<YYYY-MM>\<ID>_<DATE>.md`

## 使用スクリプトと設定（関係絶対パス）
- 競合検査: `C:\Users\User\Trae\ORCH-Next\scripts\ops\check_port.py`
- スナップショット: `C:\Users\User\Trae\ORCH-Next\scripts\ops\write_port_snapshot.ps1`
- UIサーバ（参考）: `C:\Users\User\Trae\ORCH-Next\scripts\ops\start_ui_server.ps1`
- 同期（参考）: `C:\Users\User\Trae\ORCH-Next\scripts\ops\sync_obsidian.ps1`
- MCP設定（予定）: `C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml`
- MCP compose（予定）: `C:\Users\User\Trae\ORCH-Next\docker\mcp_fs\docker-compose.yaml`

---
## 記入例（抜粋）
- 変更ID: CG-20251013-01
- 目的: Obsidian Vault MCP連携に伴う `.trae\mcp_servers.yaml` への接続設定追加
- 影響範囲: MCP接続、scripts/ops/* による検証フロー
- 対象ファイル:
  - `C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml`（保護対象）
- 差分計画: 既存キー維持、エントリ1件のみ追加（最小差分）
- Test: mypy(strict) PASS / pytest 該当 PASS / port 8001 Free / healthz 200
- Patch: 承認 A014 取得後に原子的書込、失敗時ロールバック
- 証跡: `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_20251013.md`