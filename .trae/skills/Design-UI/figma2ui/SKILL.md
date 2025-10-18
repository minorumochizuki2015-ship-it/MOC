# figma2ui ‑ Skill Specification & Implementation Plan

## 1. Purpose / 背景と目的
The `figma2ui` skill enables Design-UI agent to convert Figma design references into a structured UI component plan (based on shadcn UI) and generate preview artefacts automatically. This unlocks fine-grained “skill–level” task routing in Trae, reducing end-to-end lead-time from design hand-off to UI implementation while preserving traceability, observability, and governance.

## 2. Completion Goals (Definition of Done)
1. Single `/webhook` endpoint consolidated with signed request & JWT owner extraction (SecurityManager).
2. `CMD.yaml` patched with `mode: skill` routing and `skill: figma2ui` attribute (K1 minimal-patch path).
3. Agent Spec (Design-UI) extended with `skills:` array listing `figma2ui` and its QoS limits.
4. Skill directory `.trae/skills/Design-UI/figma2ui/` populated with:
   - `SKILL.md` (this file)
   - `__init__.py` (loader stub)
   - `runner.py` (executes conversion)
5. Observability pipeline:
   - Append JSONL logs to `observability/ui/skills/figma2ui-<task_id>.jsonl` with schema: `{ts, task_id, agent, skill, inputs_hash, status, latency_ms, artifacts}`.
   - Expose Prometheus metrics: `trae_skill_invocations_total`, `trae_skill_latency_ms_bucket`, `trae_skill_errors_total`.
6. CI pipeline executes `pytest -q -k figma2ui` and fails on non-zero exit.
7. Hourly Web-Verify job extended to include “AI agent releases” topic.
8. All changes comply with SSOT/project/personal rules (minimal unified diff, LF, atomic write, no protected-area violations).

## 3. Current Implementation Snapshot (2025-10-17)
| Area | Status |
|------|--------|
| `CMD.yaml` routing | lacks `mode: skill` & `skill` attributes |
| Agent Spec (Design-UI) | no `skills[]` section |
| Skill dir `.trae/skills/Design-UI/figma2ui/` | **absent** |
| `/webhook` | duplicated endpoints; default secret in `config/security.json` |
| Observability for skills | **none** |
| Prometheus metrics | agent-level only |
| Web-Verify hourly job | monitors security advisories only |

## 4. Unimplemented Items

## 5. Milestones & Timeline
| ID | Milestone | Owners | Exit Criteria | Target Date |
|----|-----------|--------|--------------|------------|
| M1 | Webhook consolidation & secret ENV | WORK2 | Single `/webhook` with signature + JWT validation, tests | T + 4d |
| M2 | Routing patch (K1) applied | WORK1 | `CMD.yaml` diff merged; Design-UI Agent Spec updated | T + 4d |
| M3 | Skill scaffold delivered | Design-UI | `figma2ui` code + SKILL.md committed | T + 6d |
| M4 | Observability pipeline | WORK1 + UI-Audit | JSONL logs & Prometheus metrics on dashboard | T + 8d |
| M5 | Web-Verify job update | WORK2 | Hourly job detects agent release posts | T + 9d |
| M6 | Beta MPC release | CMD | All gates PASS; UI-Audit PASS; docs updated | T + 12d |

## 6. Detailed Features
1. Skill Routing (K1)
   - Extend `CMD.yaml.routing_rules` to include skill mode.
   - Maintain backward compatibility (`plan`/`auto`).
2. Agent Spec Enhancement
   - `skills:` array under each agent defining name, path, QoS, test flag, outputs.
3. Webhook Security Hardening
   - Remove duplicate handlers.
   - Verify HMAC SHA-256 signature from header `X-Trae-Sig` using `ORCH_WEBHOOK_SECRET`.
   - Extract `owner` via JWT; fail 401 if invalid.
4. Skill Runner
   - Inputs: `figma_ref` (URL/id), optional `scope`.
   - Uses Figma API to fetch JSON, maps nodes to shadcn component list, generates `design.md` + `components.plan.json`.
5. Observability
   - Real-time streaming to `observability/ui/skills/`.
   - Prometheus counters via existing `monitor.py` plugin hook.
6. Testing
   - Smoke test ensuring runner produces expected artefacts.

## 7. Considerations / リスク & 留意点
- Backward compatibility: legacy plan/auto routes must continue working.
- ENV secret propagation in CI/CD & local dev shells.
- Rate limiting on `/webhook` after consolidation.
- JSONL growth: rotate logs daily; compress after 7 days.
- Skills spec versioning for future DSL/dispatcher extension (K2 path).

## 8. Comparative Analysis
| Criterion | Trae skills (proposed) | LangGraph tools | Claude 2 skills | ReAct pattern |
|-----------|------------------------|-----------------|-----------------|---------------|
| Routing granularity | Agent → Skill (fine) | Node (graph) | Skill/function | Implicit via LLM chain |
| Governance hooks | Native (CMD rules, approvals, locks) | External (custom) | Closed | None |
| Observability | Built-in JSONL + dashboards + UI-Audit | Limited | N/A | Manual |
| Security model | Signed webhook + RBAC + PII guard | Varies | Proprietary | Minimal |
| Extensibility | YAML + Python skills, hot-reload | Python graph nodes | Vendor-locked | Code changes |

## 9. Next Steps Summary
1. Implement M1 (Security hardening) — in progress.
2. Apply minimal routing & Agent Spec patch; merge via WORK1.
3. Generate skill scaffold & smoke tests.
4. Wire observability & metrics.
5. Extend Web-Verify job.
6. Plan for K2 expansion post-beta.
## 10. 実装の完全性確認

- 不足している要素（洗い出し）
  - Skill 実行コード: `.trae/skills/Design-UI/figma2ui/runner.py`（未作成）
  - Skill ローダ: `.trae/skills/Design-UI/figma2ui/__init__.py`（未作成）
  - Skill 用プロンプト: `.trae/skills/Design-UI/figma2ui/prompts/system.txt`, `prompts/user.txt`（未作成）
  - CMD ルーティング差分: `.trae/rules/CMD.yaml` に `mode: skill`, `skill: figma2ui`（未適用）
  - Webhook 統合: `src/orchestrator.py` の `/webhook` 単一化＋署名/JWT 検証（未実施）
  - セキュリティ ENV 化: `config/security.json` を `"secret_env": "ORCH_WEBHOOK_SECRET"` へ（未適用）
  - 観測性: `observability/ui/skills/` への JSONL 出力と Prometheus メトリクス（未実装）
  - テスト: `tests/unit/test_figma2ui.py` スモーク（未作成）
  - Web-Verify 拡張: `hourly-web-verify` に「AI agent releases」追加（未適用）

- 現在の進捗状況と位置付け
  - 設計/計画（SKILL.md）: 完了
  - セキュリティ（Webhook 統合・ENV 化）: 未着手（最優先）
  - ルーティング（K1 最小差分）: 未着手（次優先）
  - スキル実装/観測性/テスト: 未着手（ルーティング適用後に着手）
  - 運用（Web-Verify 拡張）: 後続

- 使用ディレクトリ構造（予定）
  - C:\Users\User\Trae\ORCH-Next\.trae\skills\Design-UI\figma2ui\
    - SKILL.md
    - runner.py
    - __init__.py
    - prompts\system.txt
    - prompts\user.txt
    - assets\sample_figma.json
    - README.md（使用方法）

- システム要素の網羅性チェック（主要コンポーネント）
  - ルーティング（CMD.yaml）: 追加必要
  - セキュリティ（署名/JWT）: 強化必要
  - ディスパッチャ（src/dispatcher.py）: skill モード対応拡張必要
  - 実行エンジン（runner.py）: 実装必要
  - 観測性（observability/ui/skills, src/monitor.py）: 実装必要
  - UI プレビュー（artifacts/preview, src/dashboard.py）: 連携必要
  - テスト（tests/unit, data/test_results）: 追加必要
  - ドキュメント（docs, README.md, WORK_TRACKING.md）: 更新必要

## 11. テスト環境の整備状況

- テスト結果の保存先と管理方法
  - 保存先（既存）: C:\Users\User\Trae\ORCH-Next\data\test_results\, ルートの `test_results.json`
  - 新規追加: C:\Users\User\Trae\ORCH-Next\observability\ui\skills\figma2ui-<task_id>.jsonl（スキル実行ログ）
  - 管理: タスク ID ベースのファイル命名、JSON Lines（UTF-8 LF）、日次ローテーション＋7日後圧縮、ハッシュ検証（SHA256）

- 比較データの収集方法と分析手法
  - 収集元: C:\Users\User\Trae\ORCH-Next\data\baseline\（metrics, tasks）, C:\Users\User\Trae\ORCH-Next\data\results\
  - 手法: ベースライン vs 現行の差分算出（component count, mapping 正答率, 生成時間）、統計（平均/分位/標準偏差）、回帰検知（±x% 逸脱）
  - ゴールデン比較: C:\Users\User\Trae\ORCH-Next\tests\golden\ に期待成果物を配置し、差分を CI で検証

- テスト方針の明確化と検証方法
  - 方針: Unit（runner 変換ロジック）、Integration（dispatcher 経由 skill 実行）、E2E（webhook→preview→UI-Audit）
  - 検証: pytest（スモーク/機能/エラー系）、Playwright（UI-Audit）、bandit/detect-secrets（セキュリティ）、mypy（型）、flake8（lint）
  - 閾値: Coverage≥80%、UI-Audit: LCP≤2.5s/TTI≤3s/CLS≤0.10、axe serious+ 0、visual diff≤10%

- テストケースの完全性評価（初期マトリクス）
  - 正常: 有効な `figma_ref`（URL/ID）、`scope` 有/無、複数ページ/コンポーネント
  - 境界: 大規模ドキュメント、欠落ノード、未知コンポーネント、タイムアウト
  - 異常: 無効 URL、権限なし、API レート制限、JSON パース失敗
  - セキュリティ: シグネチャ不一致、JWT 無効、PII/Secrets の出力禁止確認
  - 観測性: JSONL スキーマ準拠、メトリクス出力、ファイルローテーション

## 12. 既存システムとの統合

- リリース済み MCP の活用最適化
  - 位置付け: CMD エージェントレジストリの MCP-Orchestrator を使用し、外部 MCP ツール呼び出しを安全化
  - 実装: `src/dispatcher.py` に MCP チャネルを設け、タイムアウト/リトライ/サーキットブレーカーを適用、メトリクス送出
  - テスト: `tests/test_mcp.py` を拡張し、skill 経由の MCP 呼び出しをシミュレーション

- Docker Desktop の効果的運用
  - 目的: 開発/テスト環境の再現性確保（Windows + WSL2）
  - 推奨: 4CPU/8GB メモリ割当、ファイル共有最適化（gRPC FUSE）、`pip cache` 永続化、CI と同一イメージでテスト
  - 手順例: `docker build -t trae-orch-next .` → `docker run -v C:\Users\User\Trae\ORCH-Next:/work -w /work trae-orch-next pytest -q -k figma2ui`

- 8n8 システムの統合と比較分析
  - 現状参照: C:\Users\User\Trae\ORCH-Next\templates\orch_dashboard.html（コメント: 「タスクフロー可視化（8N8風）」）
  - 統合案: 8n8 の可視化様式に合わせ、skill 実行ログをダッシュボードに反映（ガント/ネットワーク表示）
  - 指標比較: タスク遷移速度、ボトルネック（skill/agent）、成功率、UI-Audit 合格率、MCP 呼出安定性

- オーケストレーションシステムとしての完成度評価
  - 強み: ガバナンス（CMD ルール）、観測性（JSONL+Prometheus）、セキュリティ（署名+JWT）、拡張性（skill 粒度）
  - 課題: `/webhook` 統合前、skill 実行コード未整備、ルーティング未パッチ
  - 目標: K1 完了で「agent→skill」移行の安全な導入、K2 で DSL/Dispatcher/Engine 拡張

## 13. 設計書の品質向上

- 実装仕様書としての完全性チェック
  - 目的/背景/DoD/前提/依存/入出力/失敗時動作/観測性/セキュリティ/テスト/マイルストーン/比較表/運用ルールが記述済み（本書）
  - 追加予定: シーケンス図（`docs/architecture.md` 参照）、API 契約（`schema/contracts/`）への追記

- 画期的なシステム設計の要素
  - skill 粒度のルーティングとガバナンス連携、JSONL による非同期証跡、UI-Audit PASS をゲートにしたリリース制御、Prometheus で運用 KPI 可視化

- ブラッシュアップ提案（具体）
  - CMD.yaml に `ab_routing` を残し、skill モードで A/B を設定可能に（成功指標: 実行時間、UI-Audit PASS）
  - `observability/ui/skills/` のスキーマに `error_code` と `retry_count` を追加
  - `README.md` にクイックスタート（skill 追加〜テストまで）を追記
  - `DEPLOYMENT_CHECKLIST.md` に skill 導入チェック項目を追加（ENV, ルーティング, テスト, 観測性）

- ドキュメントの堅牢性と詳細度の評価
  - 参照関係を明示（下記 16. 参照資料）し、絶対パスを付与
  - 変更差分は統一 diff で提示、EOL/LF、署名/CI ゲートの要件を併記

## 14. 参照資料（相対パス）

- ./trae報告書.txt
- ./kansakekk_1015.txt
- ./WORK_TRACKING.md
- ./README.md
- ./DEPLOYMENT_CHECKLIST.md
- ./.trae/rules/CMD.yaml
- ./docs/deploy.md（運用手順補助）

---

本書は K1（最小差分）を即時実装可能な完成度に引き上げました。指定があれば、上記不足項目の PATCH を段階的に適用します。