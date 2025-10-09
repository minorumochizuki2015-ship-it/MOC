
# PROJECT_RULES.md（ORCH-Next 統合版 v2.8）

Version: 2.8  
Date:2025-10-07  
適用方式:既存 `.trae/rules/project_rules.md` の末尾追記（最小diff・unified diff 限定）  
段階導入:`AUTO_DECIDE=shadow → on`（現行値：on）

---

## 0. 適用原則・更新方法

- 最小差分：既存本文は保持。全置換禁止。
- 形式：unified diff のみ。
- 段階導入：`AUTO_DECIDE=shadow` 開始→CI/Canary安定後 `on`。
- PTP：Plan → Test → Patch。
- 学習記録：失敗は `handoff/blocked_items.md` に即記録。

---

## 1. 権威／ROOT／適用範囲
PROJECT_RULES.md

.trae/rules/
ORCH/STATE/TASKS.md（SSOT）
user_rules.md
ROLE.md

- ##SSOT##：`ORCH/STATE/TASKS.md` 最優先（矛盾時はSSOTを裁定）。
- ##WORKSPACE_ROOT##：`C:\Users\User\Trae\ORCH-Next`。
- ##適用範囲（継続明示）##：リポジトリ内の##テキスト資産##全体（`src/`, `scripts/`, `tests/`, `docs/`, `config/`, `ORCH/`）。

## 2. 実行規約

- 実行系：`.venv\Scripts\python.exe` 固定（`pip` は `python -m pip`）。
- 改行：UTF-8 LF。`.gitattributes`
##text=auto eol=lf

併せて `git config core.autocrlf false`。

EOL チェック対象の除外：`backups/`, `data/`, `ORCH/LOGS/`, `.mypy_cache/`, `.pytest_cache/`, `__pycache__/`。
正規化：`python scripts/ops/normalize_eol.py` を使用（CRLF→LF に一括変換）。

- 書込：原子的（`*.tmp → 検証 → *.bak → rename`）。
- 検証：適用直後に EOL と SHA256(in/out) を検証。
- seed：`seed=42`（未対応は n/a）。

---

## 3. ディレクトリ標準／README 義務


.
├─ src/
├─ scripts/
│  └─ ops/rollback_release.ps1 / scan_secrets.py / validate_orch_md.py / deploy.ps1
├─ tests/ (unit / integration / e2e)
├─ config/ (staging.json ほか)
├─ docs/ (protected_targets.md / auto_decide_exceptions.md / deploy.md)
├─ ORCH/
│  ├─ STATE/ (TASKS.md / APPROVALS.md / FLAGS.md / LOCKS/ / CONTINUOUS_IMPROVEMENT.md)
│  ├─ LOGS/YYYY-MM/
│  └─ releases/
└─ artifacts/<task_id>/ (metrics.json / run.log / README.md / scratch/)

- 実行スクリプトは ##scripts/ops## 限定。実験は ##artifacts/<task_id>/scratch## 限定。
- ##成果物 README 必須##（テンプレ準拠、欠落は禁則）。

##成果物 README テンプレ##

# <task_id>: <title>
- Owner: WORK
- Date: <UTC-ISO8601>
- Inputs: ...
- Outputs: ...
- Reproduce:
  1) .\.venv\Scripts\python.exe -m pytest -q
  2) .\.venv\Scripts\python.exe scripts/repro_<task_id>.py
- Metrics: <k>=<v>
- Dependencies: <pip packages/models>
- Notes: <limits>

---

## 4. 再現性保証（WORK1 / WORK2）

| 名称  | 定義                            | 判定 |
| ----- | ------------------------------- | ---  |
| WORK1 | 初回実行の `sha_out`             | 生成時|
| WORK2 |同一コミット・依存・環境再実行の `sha_out` | 検証時 |

→ 完全一致で再現性確定。

---

## 5. 禁則一覧（自動承認の「禁則=none」基準）

- 非原子的上書き／強制 push。
- 成果物 README（テンプレ）欠落。
- Secrets 混入（APIキー・認証情報）。
  - README/CI/test に実値のシークレット記載を禁止（例示は `REDACTED`/`CHANGEME`、CIは `jwt-ci`/`webhook-ci` など短いプレースホルダーを用いる）。
  - Bearer 文字列はテストで短いプレースホルダーのみ使用（実トークンのハードコード禁止）。
- CRLF 混入（LF 不一致）。
- 保護領域改変（例：`src/dispatcher.py`, `src/hive_mind.py`, `config/*.json`(prod), `migrations/`, `scripts/ops/`）。
- venv 外 pip、再現不能な手動操作、SSOT 破壊。

保護領域のSSOT：`docs/protected_targets.md`。AUDIT 月次レビューを実施し、結論を `ORCH/STATE/CONTINUOUS_IMPROVEMENT.md` にリンク。

---

## 6. 承認・監査ゲート
##ORCH/STATE/APPROVALS.md##

| appr_id | task_id | op | status | requested_by | approver | approver_role | ts_req | ts_dec | evidence |

- `status ∈ {pending, approved, rejected, expired}`、自己承認禁止、`ts_dec ≥ ts_req`。
- `evidence = ORCH/patches/YYYY-MM/<task_id>-<appr_id>.diff.md`。
- 対象：外部書込／ルール更新／設定変更／保護領域。
- `pending` は本番適用不可。

---

## 7. 自動決裁（AUTO-DECIDE）

### ORCH/STATE/FLAGS.md

AUTO_DECIDE=on
FREEZE=off

### 承認条件（全充足）

1. pytest=100%、coverage ≥ 80%
2. mypy strict／flake8=0／black & isort 整合
3. Diff Scope=minimal、禁則=none、EOL=LF
4. metrics.json／run.log／README.md 実在
5. WORK1/WORK2 の `sha_out` 一致
6. Secrets 検査 pass（`scan_secrets.py` または pre-commit）
7. Lock 正常（TTL≤600s、競合なし、FLAGS 連動）
8. Canary 成功（`pytest -q -k e2e`）

### 却下条件

- 保護領域／設定／DBスキーマ変更、差分>50行 or >3ファイル、coverage 未達、禁則検出、README 欠落。
 - 秘密情報スキャナでの検出（`scan_secrets.py`）が解消されていない。

### 記録・制御

- `APPROVALS.md`：`approver=AUDIT@auto, ts_dec=UTC` を自動追記。
- 日次ログ：`ORCH/LOGS/YYYY-MM/APPROVALS-YYYY-MM-DD.md`。
- CircuitBreaker：30日内 1 失敗で `AUTO_DECIDE=off`。
- Freeze：`FREEZE=on` 中は自動決裁停止。
- Shadow：判定のみ記録。
- 例外運用：本文閾値は不変。必要例外は `docs/auto_decide_exceptions.md` に限定。

---

## 8. Canary／Lock／Rollback

### Canary（設定可搬・環境変数上書き可）

- 設定：`config/staging.json`

  ```json
  { "healthcheck_url": "https://staging.local/api/health",
    "retry_sec": 5, "max_wait_sec": 30, "success_required": 5 }
  ```

- 実行：`pytest -q -k e2e`
- 成否：HTTP 200 を success_required 回（既定 5）。間隔 5 秒、最大 30 秒。
- 3 連失敗で CircuitBreaker。
- 環境変数上書き：`HEALTHCHECK_URL` / `RETRY_SEC` / `MAX_WAIT_SEC` / `SUCCESS_REQUIRED`。
- 運用参照先（実装は別タスク）：`scripts/ops/deploy.ps1`／`docs/deploy.md`。

### Lock（JSON 仕様）

`ORCH/STATE/LOCKS/<task_id>.lock`

```json
{
  "owner": "AUDIT@auto",
  "task_id": "<id>",
  "ts_acquired": "<ISO8601Z>",
  "ttl_sec": 600,
  "status": "active"   // {active, pending, expired, released}
}
```

- 状態：`active/pending/expired/released`。TTL超過は expired （自動失効、記録）。正常終了は released。
- `FREEZE=on`：自動決裁を保留。競合検出時は自動決裁停止。

### Rollback（idempotent）

- 手順：sha256 照合 → 復旧 → 後検証（hash 一致）。
- スクリプト：`scripts/ops/rollback_release.ps1 -CheckOnly`（Dry-run）。多重実行安全。
- 参照：`ORCH/releases/<ver>/sha256sum.txt`。

---

## 9. 自動検証（CI ゲート）／設定集約

- CI（`.github/workflows/ci.yml`）順：lint → format → type → test → coverage → secret → EOL(LF) check。
  → EOL/LF 失敗は必ず Fail（強制）。`eol-check.yml` にて `scripts/ops/check_eol.py` を実行。
  → 秘密情報検査は `scripts/ops/scan_secrets.py` を使用。除外：`__pycache__/`, `backups/`, `data/logs/`。許容プレースホルダー：`REDACTED`, `CHANGEME`, `jwt-ci`, `webhook-ci`。

- 設定集約：`pyproject.toml`

  ```toml
  [tool.black]  line-length = 100
  [tool.isort]  profile = "black"
  [tool.flake8] max-line-length = 100
  [tool.mypy]   strict = true
  ```

- SSOT整合：`scripts/ops/validate_orch_md.py` が `TASKS/APPROVALS/FLAGS/LOCKS` を照合。

---

## 10. 初期セットアップ（必須）

1. 生成：`ORCH/STATE/LOCKS/`, `ORCH/releases/`, `ORCH/LOGS/YYYY-MM/`。
2. `ORCH/STATE/FLAGS.md`：

AUTO_DECIDE=on
FREEZE=off

3. `.gitattributes` 追加（LF 強制）。
4. `scripts/ops/` 配置：`validate_orch_md.py`, `scan_secrets.py`, `rollback_release.ps1`, `deploy.ps1`。
   - 追加ユーティリティ：`normalize_eol.py`（CRLF→LF 正規化）

   - 使用例（README）：
     - validate：`python scripts/ops/validate_orch_md.py --strict`
     - scan_secrets：`python scripts/ops/scan_secrets.py --fail-on-detect`
     - rollback：`pwsh scripts/ops/rollback_release.ps1 -CheckOnly`
     - deploy：`pwsh scripts/ops/deploy.ps1 -Env staging`
5. `pyproject.toml` で mypy/flake8/black/isort を統合。
6. CI 強化：lint/type/test/coverage/secret/EOL fail 必須。
7. `config/staging.json` と pytest-e2e 構築（環境変数上書き可）。
8. docs作成：

   - `docs/protected_targets.md`（SSOT、AUDIT 月次レビュー。結論は `ORCH/STATE/CONTINUOUS_IMPROVEMENT.md` にリンク）
   - `docs/auto_decide_exceptions.md`（本文閾値は不変。軽微パッチのみ一時緩和の手順）
   - `docs/deploy.md`（Canary 上書き手順・Rollback 併記）

### 10.1 deploy.ps1 配置差異への対処（再確認）

- 推奨：リポジトリ直下の `deploy.ps1` を `scripts/ops/deploy.ps1` へ移設（Git 履歴保持）。
- 暫定（最小diff運用）：移設できない場合、`docs/deploy.md` に参照先の差異を明記し、次リリースで移設を必須化。

---

## 11. 役割

| Role  | 職務 | 責任                     |
| ----- | -- | ---------------------- |
| CMD   | 指揮 | 方針決定／最終承認              |
| WORK  | 実装 | 成果物生成／検証               |
| AUDIT | 監査 | 承認ゲート／ログ保守／docs 月次レビュー |

---

## 12. 失敗分析

全失敗は `handoff/blocked_items.md` に即記録。再発時は規約へ昇格。

---

## 13. 更新履歴

- v2.8 (2025-10-07)：v2.7 監査の差分要点を反映（適用範囲の継続明示、deploy 配置差異対処の再確認、docs SSOT 月次レビュー連携、CI EOL/LF 強制Fail 維持）。
- v2.7：適用範囲継続、deploy 配置差異対処、docs 連携、CI 強制Fail 維持。
- v2.6〜v2.0：Canary 変数上書き、Lock TTL/競合、Rollback idempotent、例外運用別紙化、最小diff 統合。
## AUTO_DECIDE 運用ポリシー（恒久化）

### モード
- on: 自動判断を標準有効。以下のガードレールを必須適用。
- shadow: 観測のみ（意思決定は記録、強制適用しない）。検証・監査時に使用。
- off: 監査・障害対応のため一時停止。

### ガードレール
1. 重複タスクの再追加禁止（待機系・同一内容は一意キーで拒否）
2. ループ検知とフォールバック（同一アクションの連続検知→shadow遷移）
3. ツール呼び出しのバッチ化（1会話での過剰分散を防止、関連操作はバンドル）
4. 進行中タスクは常時1件（todo管理のin_progressは同時1件）
5. 重要ファイル保護（docs/protected_targets.mdの対象は自動変更しない）

### 昇格条件
- 統合・E2E・負荷テストの成功率95%以上
- Canary監視で重大エラーなし（例：/api/tasks, /status, /events の継続成功）
- ログ監査でループ・重複なし（ORCH/LOGS, ORCH/STATE を参照）

### 監査・運用
- 監査期間のshadow運用後、onに昇格。
- 昇格後もCanary監視を継続し、異常時はshadowへ自動フォールバック。

---

## 11. 品質評価基準・参照自動化・恒久化（新設）

- 権威文書（SSOT for Quality）：`docs/quality_criteria.md`
- 目的：品質評価のしきい値・段階的合格（70/85/95）を CI/Canary/AUTO_DECIDE に連携し、参照を自動化・恒久化する。

### 11.1 参照の自動化
- CI にて `python scripts/ops/validate_quality_doc.py --strict` を実行し、以下を検証する。
  1) 必須セクションの存在（「段階的合格判定」「推奨しきい値」「HTTP API」「SSE」「自動判定」）
  2) ドキュメントが最新（更新日付をコミットと整合）であること（将来拡張）
  3) 強制しきい値（成功率95%、P95≤1500ms、SSE再接続≤5s、ドロップ率≤5%）の定義が保持されていること
- 検証結果を `data/results/quality_doc_validation.json` に保存。Fail は CI を即時失敗。

### 11.2 Canary/Config の恒久化
- 監視間隔の最適値はスイープテスト（3/5/10/15秒×10分）により決定し、`config/monitoring.json` に反映。
- 重点監視 API（例：`/api/prediction`, `/api/metrics`, `/api/trends`, `/events`, `/jobs/{id}/events`）は `config/monitoring.json` の `canary_endpoints` に SSOT 管理。
- Canary 成果（安定通過）が 24h 継続した場合、`AUTO_DECIDE` の対象に昇格（ルール7）。

### 11.3 ゲート連携
- 70点到達：Staging 合格（継続検証）。
- 85点到達：Pre-Prod 合格（Canary 継続）。
- 95点到達：AUTO_DECIDE による自動承認対象。
- しきい値違反（強制項目）検知時は CI Fail とし、`ORCH/STATE/CONTINUOUS_IMPROVEMENT.md` に改善計画を追記。

### 11.4 変更管理
- 品質基準の改定は最小差分で実施し、`ORCH/STATE/APPROVALS.md` に記録（evidence: `ORCH/patches/YYYY-MM/<task>-quality-update.diff.md`）。
- 例外運用は `docs/auto_decide_exceptions.md` に限定し、強制しきい値の緩和は禁止。

---

## 14. パス記述ポリシー（監査・証跡は絶対パス必須／Windows区切り）

- 対象: 監査記録・承認証跡（`ORCH/STATE/APPROVALS.md:evidence`）・ツール呼び出しログ・監査対象の成果物参照（`artifacts/**` など）。
- 要件: Windows の絶対パスを必須とする（ドライブレターまたは UNC）。区切りは `\`（バックスラッシュ）。
  - 例: `C:\Users\User\Trae\ORCH-Next\ORCH\patches\2025-10\006-A007.diff.md`
  - 例: `\\server\share\ORCH-Next\artifacts\phase4_dashboard\run.log`
- 禁止: 相対パス、`..` の使用、`/`（フォワードスラッシュ）による区切り。
- ドキュメントにおける補助的記載: 可搬性のため説明文中にリポジトリ相対パスを併記しても良いが、監査評価は絶対パスのみを基準とする。
- 検証: `python scripts/ops/validate_orch_md.py --strict` は `APPROVALS.md:evidence` が Windows 絶対パスかつ `\` 区切りであることを検証する。

更新履歴（追加）
- 2025-10-07: 監査・証跡の絶対パス必須（Windows 区切り）を明記。検証手順（`--strict`）を導入。