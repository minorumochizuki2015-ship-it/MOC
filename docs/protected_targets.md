# Protected Targets (SSOT)

本ドキュメントは保護対象の単一の情報源（SSOT）です。ここに記載された領域への変更は承認ゲートを通過しない限り禁止されます。

## 1. コード／設定（保護領域）
- src/dispatcher.py
- src/hive_mind.py
- src/orchestrator.py
- src/security.py
- config/production.json
- migrations/**
- scripts/ops/**

## 2. 運用ルール文書
- .trae/rules/project_rules.md
- ORCH/STATE/TASKS.md
- ORCH/STATE/APPROVALS.md
- ORCH/STATE/flags.md
- ORCH/STATE/LOCKS/**

## 3. 変更手順（例外）
例外は `docs/auto_decide_exceptions.md` に従い、軽微パッチに限定。本文の閾値は不変です。