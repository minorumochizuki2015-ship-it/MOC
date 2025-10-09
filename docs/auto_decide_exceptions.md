# AUTO_DECIDE 例外運用（別紙）

本文の承認閾値は不変です。例外は軽微パッチ（影響範囲が小さく、保護領域・設定変更を含まない）に限定し、以下の手順を必須とします。

## 手順
1. 例外理由の記録：`ORCH/STATE/APPROVALS.md` に `approver=CMD@manual`、根拠（evidence）を明記。
2. 影響範囲の提示：差分が 50 行以下・3 ファイル以下であることを示す。
3. 検証の簡易化：pytest はスモークに限定可。ただし secrets/EOL 検査は省略不可。
4. ログ保全：`ORCH/LOGS/YYYY-MM/APPROVALS-YYYY-MM-DD.md` に例外適用を明記。
5. 期限：例外は当該リリースのみ有効。継続は不可。

## 禁則（例外でも不可）
- 保護領域の変更
- 設定（prod）変更
- DBスキーマ変更
- secrets 検出