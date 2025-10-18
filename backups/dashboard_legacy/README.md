# Dashboard Legacy Backup Files

## 概要
このディレクトリには、ダッシュボードリファクタリング作業中に作成されたバックアップファイルが格納されています。

## ファイル一覧

### 移動済みバックアップファイル
- `orch_dashboard_v1_20251012_123239.py` (159.8 KB)
  - 元ファイル: `orch_dashboard.py.backup_20251012_123239`
  - 作成日時: 2025-10-12 12:32:39
  - 説明: 初期バックアップ版

- `orch_dashboard_v2_20251012_125034.py` (160.4 KB)
  - 元ファイル: `orch_dashboard.py.backup_20251012_125034`
  - 作成日時: 2025-10-12 12:50:34
  - 説明: 中間バックアップ版

- `orch_dashboard_advanced_20251012_123718.py` (159.7 KB)
  - 元ファイル: `orch_dashboard.py.backup_advanced_20251012_123718`
  - 作成日時: 2025-10-12 12:37:18
  - 説明: 高度機能実装版バックアップ

## 命名規約
- パターン: `orch_dashboard_{version}_{YYYYMMDD_HHMMSS}.py`
- version: v1, v2, advanced等のバージョン識別子
- 日時: 作成日時（JST）

## 整理作業記録
- 実行日: 2024-12-12
- 作業者: CMD Agent (AUDIT-06)
- 目的: プロジェクトルートの整理とバックアップファイルの体系的管理
- 参照: ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md

## 保持期間
- 推奨保持期間: 6ヶ月
- 次回見直し: 2025-06-12
- 削除条件: リファクタリング版の安定稼働確認後

## 関連ファイル
- 現行版: `orch_dashboard.py` (ポート5000)
- リファクタリング版: `orch_dashboard_refactored.py` (ポート5001)
- 監査レポート: `ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md`