# next-004 監査修正パッチ

## 修正概要
- タスクID: next-004
- 修正日時: 2025-10-07T04:35:00Z
- 修正者: AUDIT
- 修正理由: SSOT欠落・スキーマ逸脱・承認フロー欠落の修正

## 検出された違反
1. TASKS.md に next-004 行が存在しない（SSOT欠落）
2. artifact 列が複数パス（pathA | pathB）でスキーマ逸脱
3. REVIEW 状態なのに APPROVALS.md に対応レコードなし（承認フロー欠落）

## 修正内容

### 1. TASKS.md 修正
```diff
--- TASKS.md (before)
+++ TASKS.md (after)
@@ -13,4 +13,5 @@
  | 002 | 運用テスト実施 | DONE | CMD | - | - | - | 2025-10-06T12:00:00Z | ORCH/STATE/TASKS.md | priority=HIGH・運用テスト完了・全機能検証済み |
  | 003 | 緊急スケジュール調整とAI予測機能実装 | DONE | WORK | - | - | - | 2025-10-08T00:00:00Z | ORCH/REPORTS/Phase3_Completion_Report.md | priority=HIGH・AI予測システム・監視・ダッシュボード実装・Phase3完了報告 |
+ | next-004 | 既存MOCシステム移行計画 | REVIEW | WORK | - | - | - | 2025-10-08 | handoff/MOC_MIGRATION_PLAN.md | MOC移行計画・依存関係分析完了・3段階移行戦略 |
```

### 2. APPROVALS.md 修正
```diff
--- APPROVALS.md (before)
+++ APPROVALS.md (after)
@@ -14,4 +14,5 @@
  | A002 | 002 | operational_test | approved | WORK | CMD | CMD | 2025-10-06T09:13:22Z | 2025-10-06T09:13:22Z | ORCH/STATE/TASKS.md |
  | A003 | 003 | AI予測機能・監視・ダッシュボード実装 | approved | WORK | AUDIT | AUDIT | 2025-10-06T18:43:20Z | 2025-10-06T19:15:00Z | ORCH/REPORTS/Phase3_Completion_Report.md |
+ | A004 | next-004 | MOC移行計画 | pending | WORK | - | - | 2025-10-07T04:35:00Z | - | ORCH/patches/2025-10/next-004.diff.md |
```

## 修正後の状態
- TASKS.md: next-004行追加、単一artifact相対パス設定
- APPROVALS.md: A004 pendingレコード起票
- 承認フロー: pending状態で承認待ち

## 検証結果
- SSOT整合性: ✅ 修正完了
- スキーマ準拠: ✅ 単一artifact相対パス
- 承認フロー: ✅ pending起票完了
- EOL/UTF-8: ✅ 準拠
- 最小diff: ✅ 必要最小限の変更

## 次のアクション
1. AUDIT による承認審査
2. approved 取得後に DONE 遷移
3. 最終検証とクロージング