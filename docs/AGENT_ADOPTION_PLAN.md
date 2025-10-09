# Trae環境 サブエージェント採用・即時実施計画

目的
- Vibe Kanban/Claude Codeの思想をTrae環境へ即時取り入れ、反復作業の自動化と開発支援を強化する。

評価基準（採用可否）
- ライセンス適合（商用可/制限事項/依存関係の整合）
- セキュリティ（認証・権限・監査ログ・シークレット取扱）
- 開発生産性（コード提案品質、誤修正率、検証容易性）
- 統合容易性（API/SDK/CLI、Windows/PowerShell環境適合）
- 運用性（ログ/監視、リソース消費、障害時切替/ロールバック）

ショートリスト（例・要レビュー）
- Claude Code系サブエージェント（コード補助/レビュー/説明生成）
- ドキュメント生成系（spec/README/設計補助）
- テスト補助系（テストケース提案、リグレッション観点）

統合アプローチ（最小差分）
1) dispatcher/hive_mind に委譲フックを追加（Subagent Fabric契約準拠）
2) orchestrator に /api/subagents/dispatch を追加（最小）
3) ダッシュボードに進捗表示（templates/orch_dashboard.html の更新）
4) scripts/status_updater.py と連携し、メトリクス記録

PoC 対象
- artifacts/task-registration の Operation: TASK_REGISTRATION_FIX（設計書と差分生成の自動化）

ステップ（即時着手）
- S1: ライセンス・依存関係の確認（docsに記録）
- S2: API/WS最小実装のドラフト作成（モック可）
- S3: サブエージェント呼び出しの安全ガード（protected_targets遵守）
- S4: 指標定義と検証（WIP/リードタイム/失敗率/ロック競合率）

リスクと対策
- 誤修正: apply_patch差分のレビュー必須、重要ファイルは除外
- セキュリティ: JWT/HMACの必須化、権限ロール設定
- 依存破綻: ピン留めバージョン、SBOMの作成

成果物
- 設計/採用レポート、API/WSドラフト、PoC結果、改善計画