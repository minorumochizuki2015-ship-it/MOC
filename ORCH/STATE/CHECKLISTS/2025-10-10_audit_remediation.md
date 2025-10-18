# 2025-10-10 監査リメディエーション チェックリスト

目的: 監査で発見された事項の是正と、プロジェクトルール厳密化の適用。
対象: src/, tests/, .github/workflows/ci.yml, PROJECT_RULES.md, ORCH/STATE/CHECKLISTS/

ステータス定義: [ ] pending / [~] in_progress / [x] completed

## 手順（PLAN → TEST → PATCH）
1. ルール追記（厳密化）
   - [~] 追記案の提示（ユーザー承認済み: 承認）
   - [x] PROJECT_RULES.md に追記（A〜F）
   - [x] 共有・適用宣言

2. 承認エンドポイント修正（tests/test_workflows_api.py 満足）
   - [ ] RBAC (VIEWER:GET / OPERATOR:POST)
   - [ ] approver の照合（current_user.username 一致）
   - [ ] decision バリデーション（approve/approved/reject/rejected）
   - [ ] 既存IDの重複 409 応答
   - [ ] GET は pending を返すスタブの維持
   - [ ] pytest 再実行で 失敗0 を確認

3. CI の秘密鍵非存在チェック追加
   - [ ] 署名後に private.pem 非存在を検証（存在すれば Fail）

4. 型・静的解析改善
   - [ ] types-PyYAML 導入確認（pre-commit/mypy 連携）
   - [ ] 未注釈箇所の計画的削減

5. pre-commit の秘密/EOL フック運用確認
   - [x] 設定に含まれていることを確認

6. flake8 警告是正（テスト）
   - [ ] 未使用 import/変数の除去、F811 解消

7. CI/カバレッジ/ダッシュボード確認
   - [ ] pytest 全通過
   - [ ] coverage 70% 以上維持
   - [ ] ダッシュボード類の変更があればプレビュー提示

## ロールバック手順
- 失敗時は該当ファイルの差分を revert、再度 PLAN からやり直す。

## 実施ログ
- 2025-10-10 追加: ルール追記適用、チェックリスト作成。
- 2025-10-14 実施: kansakekk_1015.txt 監査レポート精査、SQLite ResourceWarning 是正方針確定。

## SQLite 接続 ResourceWarning 是正（2025-10-14）
- [x] kansakekk_1015.txt の監査指摘をレビューし、with sqlite3.connect(...) だけでは物理クローズされない点を確認
- [x] src/automated_approval.py に closing(sqlite3.connect(...)) + with conn: を最小diffで適用（_init_database/_log_rule_application/process_approval/get_approval_stats）
- [x] _init_database に PRAGMA 設定（WAL/busy_timeout/foreign_keys）を追加
- [x] pytest -W error::ResourceWarning を実行し、警告ゼロで完了（Exit code 0）
- [ ] lock_manager.py 等の残り接続箇所に同様の修正を適用
- [ ] 監査再実行（pytest -W error::ResourceWarning）で回帰なしを確認