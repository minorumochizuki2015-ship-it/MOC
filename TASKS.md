# TASKS

## カバレッジ Quality Gate ロードマップ

- 現状: diff-cover --fail-under=80
- 段階的引き上げ計画:
  - フェーズ1: 80% → 85%
  - フェーズ2: 85% → 90%
  - フェーズ3: 90% → 92%（長期的目標）
- 実施のタイミング: 大きな機能追加の直後は据え置き、安定期に引き上げ
- 例外運用: 生成コードや実験的モジュールは omit に含める（.coveragerc 管理）

## pandas 依存分離方針

- 原則: requirements.txt に pandas を明記（tests require pandas）
- 代替（軽量化目的）:
  - 該当テストの先頭で `pytest.importorskip("pandas")` を使用し、未インストール時は skip 扱い
  - 将来的には extras_require を導入（例: `pip install .[tests]`）
- CI 運用:
  - Windows ジョブは `python -m pytest` を使用して venv の依存を確実に適用
  - coverage.xml の生成を `--cov-report=xml:coverage.xml` で明示

## 2025-10-16 E2E テスト実行完了

### 実行内容

- Playwright 環境構築（pip install playwright + chromium インストール）
- `test_style_manager_preview_query.py` の実行（BASE_URL=<http://127.0.0.1:5002）>
- テスト修正：`wait_for_selector` → `wait_for_function` でページ選択肢の読み込み待機を改善

### 検証結果

- ✅ E2E テスト PASSED（1 passed in 3.06s）
- ✅ /style-manager でページ選択→読み込み後、iframe.src に `style_base_url=http://127.0.0.1:5002/` が付与されることを確認
- ✅ localStorage.STYLE_BASE_URL の値が正しく query parameter に反映されることを確認

### 運用ノート

- E2E 環境は BASE_URL で切り替え可能（5000番ポート検証時は `$env:BASE_URL='http://127.0.0.1:5000'` に変更）
- テストは /api/pages からページ一覧を取得し、最初の有効なページで iframe 読み込みを実行
- style_base_url の値は localStorage → query parameter → サーバ FixLog の流れで追跡可能

---

## 最新更新（2025-10-15）

### 完了

- **CORS エラー修正完了**（src/dashboard.py）
  - Flask アプリケーションに CORS ヘッダー追加
  - `Access-Control-Allow-Origin: *`
  - `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
  - `Access-Control-Allow-Headers: Content-Type, Authorization, X-Style-Base-Url`
  - OPTIONS プリフライトリクエスト対応ルート追加
  - style-manager ページでの API 呼び出しエラー解消確認済み

### 以前の完了項目（2025-10-11）

- kernel 最小API 実装（src/core/kernel.py）と shim 更新（kernel.py）
- ユニットテスト追加（tests/unit/test_kernel.py）
- CI（Windows）プリフライト追加：kernel healthcheck、data/baseline ディレクトリ準備
- CI（Windows）差分カバレッジゲート：diff-cover --fail-under=80
- ドキュメント更新（README.md／RELEASE_NOTES.md／docs/operations.md／docs/checklists/*）

### 進行中／予定

- ロギング方針統一（pytest 時の FileIO 抑制、共通 logging_config）
- mypy strict 警告削減（現状14件）
- Streaming 対応（generate/_chat の stream=True）

## 2025-10-11 Status Sync

Completed

- CI 型安全ゲート必須化：Ubuntu/Windows 双方で `mypy --strict --show-error-codes app src` により型エラーでジョブ fail。
- mypy.ini 整理：`ignore_missing_imports=False`、`warn_unused_ignores=True`、`files=app, src, tests` に統一。

Remaining (High priority)

- Logging 統一（残）：`src/` および `app/shared/` の `logging.getLogger()` を統一ファクトリ／取得関数へ置換。pytest 実行時に不要な FileHandler を抑制確認。
- mypy 警告ゼロ化：CI の指摘（想定 14 件）を 0 件へ。typing 補強／必要最小限の `# type: ignore[code]` 整理。進捗は `docs/mypy_strict_plan.md` へ反映。

Remaining (Optional CI optimization)

- キャッシュ：pip・mypy のキャッシュ活用（`--sqlite-cache`）。
- レポート：`mypy --html-report=artifacts/mypy` を生成しアーティファクトに添付。
- Windows venv 保障：`.venv` 不在時に `python -m venv .venv` を作成するステップ追加。

Next actions

1) CI 再実行 → 指摘 14 件を収集。
2) `docs/mypy_strict_plan.md` に「ファイル／行／error_code／対応方針」を記録。
3) ログ統一の対象ファイルを順次置換し、pytest 合格と副作用抑制を確認。
4) 必要に応じて CI 最適化パッチを適用。

Related absolute paths

- c:\Users\User\Trae\ORCH-Next\.github\workflows\ci.yml
- c:\Users\User\Trae\ORCH-Next\mypy.ini
- c:\Users\User\Trae\ORCH-Next\docs\mypy_strict_plan.md
- c:\Users\User\Trae\ORCH-Next\src\
- c:\Users\User\Trae\ORCH-Next\app\shared\

---

## 2025-10-13 Status Sync（Style Manager ハンドオーバー）

### 概要

- UI 主要ページ（/dashboard, /style-manager, /tasks）および /healthz は 200 応答に復旧。
- 重複起動／暫定UIルートの問題を解消。ルート登録は `style_manager = create_style_api(app)` に統一。

### 完了

- `src/dashboard.py` から暫定スタイル管理ルート／重複APIを削除し、`create_style_api(app)` 呼び出しへ統一。
- Flask 起動手順の是正：`$env:FLASK_APP="src.dashboard"; python -m flask run --port 5000`。
- 引継ぎMD更新（RCA・是正・再発防止・検証手順）：`handoff/style_manager_handover_20251013.md`。

### 未完了タスク（優先度順）

- [ ] T-001 P1 (2025-10-15) Playwright UI E2E（要素選択/スタイル適用/保存）
  - 完了条件: 依存追記（requirements-dev.txt に playwright / pytest-playwright 追加）＆ CI/ローカルで E2E 緑確認
- [ ] T-002 P2 (2025-10-18) CSS/JS の静的アセット化とバージョニング
- [ ] T-003 P3 (2025-10-15) 本マイルストーンを TASKS.md に反映（本節）
- [ ] /style-manager 404 再検証 & ルート統合確認（`create_style_api` のみで登録維持）
- [ ] scripts/ops/start_ui_server.ps1 の `FLASK_APP=src.dashboard` 強制設定確認・必要なら修正
- [ ] Playwright インストール（`python -m pip install playwright` → `python -m playwright install`）

### マイルストーン

| 期日 | マイルストーン | 達成基準 | 責任者 | 依存 |
|---|---|---|---|---|
| 2025-10-20 | M1 | Playwright E2E がレビュー/CI合格 | me | T-001 |

### 次の一手（実行順）

1) Playwright を導入しブラウザをインストール（上記コマンド）
2) `/style-manager` と `/api/styles` の到達性スモークを tests/e2e に追加
3) `scripts/ops/start_ui_server.ps1` に `FLASK_APP` 強制設定が入っているか確認し、必要なら最小修正

### 更新（2025-10-13 追加）

- 追加: `scripts/ops/install_playwright.ps1`（Python検出・pip/ブラウザ導入自動化）
- 追加: `scripts/ops/start_ui_server.ps1`（PortガードONデフォルト、`FLASK_APP=src.dashboard` 強制）
- 追加: `scripts/ops/check_port.py`（CI前ポート衝突検出）
- 追加: `tests/e2e/test_style_manager.py`（/style-manager, /api/styles スモーク）
- 追加/更新: `docs/checklists/ui_server_runbook.md`（起動ガード・検証・E2E手順）
- 追記: `docs/MILESTONES.md`（M1: Playwright E2E）、`docs/WORKING_RULES.md`（起動・ルート責務・E2E必須）

### 次の一手（更新後の優先度順）

1) NT-006: Playwright インストール（scripts/ops/install_playwright.ps1 実行）
2) T-001: Style Manager の要素選択/保存フロー E2E 拡張
3) NT-007: スモークをCIに組み込み（`pytest -m e2e`）+ 失敗時アーティファクト収集
4) NT-005: 起動ガード（CI常時ON）運用確認
5) T-002: CSS/JS 静的アセット化と版管理
エラーが

### 2025-10-13 Hotfix（起動ガード/スモーク再検証）

- 修正: `scripts/ops/start_ui_server.ps1` 先頭で `Set-Location (Join-Path $PSScriptRoot "..\\..")` により CWD をプロジェクトルートへ変更、`PYTHONPATH` にルートを追加し `src.dashboard` import error を解消。
- 検証: サーバ起動後に `tests/e2e/test_style_manager.py -m e2e` を実行し 2/2 pass を確認（/style-manager, /api/styles）。
- 推奨CI: `pwsh scripts/ops/start_ui_server.ps1 -Port 5000 -ForceGuard` → `pytest -q tests/e2e -m e2e` → 後処理でサーバ停止。

### 2025-10-13 設計メモ（T-002/T-003）

T-002: 静的アセット bundling / versioning 設計

- ツール候補:
  - Vite（fast dev server + build、static/dist へ出力）
  - Flask-Assets（Jinja連携が容易、filterにてminify）
- 出力パス: `static/dist/`
- キャッシュバスティング: ファイル名クエリに `?v=<sha256短縮>` を付与（例: `/static/dist/app.js?v=abc123`）
- 運用:
  - dev: ViteのHMRを使用（必要ならプロキシ設定）
  - CI: build完了後に `static/dist/` を成果物に添付、Flaskテンプレートの参照先をdistに切替

T-003: ドキュメント追従

- `docs/checklists/ui_server_runbook.md` に CI統合フロー（port guard→server起動→pytest→アーティファクト→停止）とE2E手順を追記
- `docs/MILESTONES.md` の M1 完了条件を「CIでE2E緑」に更新（Windows job基準）

## P0: 多層ガードと説明責任カード（即採用）

- [Owner] CI へ Lighthouse＋リンク切れチェックを追加（Windows テストジョブ）
- [Owner] 説明責任カード生成スクリプト（scripts/ops/gen_root_cause_card.py）を CI から実行し ORCH/patches/ に保存
- [QA] UI-Audit（axe/visual/LCP）と新規ガードの同時実行確認、失敗時アーティファクト収集の検証

## P1: セマンティック・アンカーと minimal diff パイプライン（MVP）

- [FE] Style Manager に data-sem-role / data-sem-intent を最小差分で付与（apply ボタン・カラー入力）
- [QA] E2E をアンカー参照へ移行（Playwright locators を data-sem-* ベースへ）
- [Ops] minimal diff パイプライン（diff --numstat の自動チェック）を CI に統合（段階導入）

## 次アクション（進行中）

- PR 作成 → CI 緑＆UI-Audit パス確認 → マージ
- ドキュメント更新（MILESTONES.md / docs/checklists/ui_audit_checklist.md）

---

## 2025-10-15 Status Sync（/preview FixLog・観測強化）

### 目的

- /preview 経由の表示失敗・上流エラーの原因切り分けを容易にし、説明責任のためのログ項目を標準化する。

### 実装（完了）

- src/dashboard.py
  - 成功時ログ: `PREVIEW_OK target=<URL> origin=<ORIGIN> style_base_url=<VAL> meta_refresh=<bool>`
  - 失敗時ログ: `PREVIEW_UPSTREAM_ERR status=<CODE> target=<URL> style_base_url=<VAL>`（502 マッピング時）
  - 応答ヘッダー付与（成功時）:
    - `X-Preview-Target`: /preview が取得した対象 URL
    - `X-Preview-Origin`: ターゲットのオリジン（base 正規化に使用）
    - `X-Disable-ServiceWorker`: `true`（プレビューでは SW を無効化）
    - `X-Preview-Same-Origin`: `true`（同一オリジンとして提供）
  - 応答ヘッダー付与（502 マッピング時）:
    - `X-Upstream-Status`: 上流応答ステータス
    - `X-Preview-Target`: 対象 URL
  - 受信パラメータ/ヘッダー（省略可）:
- `style_base_url`（query）または `X-Style-Base-Url`（header）をログに記録（UI 側で送れる場合に活用）

### E2E（完了）

- tests/e2e/test_preview_e2e.py を拡張：
  - 成功時のヘッダー検証（X-Preview-* と SW 無効化ヘッダー）
  - 非2xx上流応答を 502へ写し替え時のヘッダー検証（X-Upstream-Status, X-Preview-Target）

### 運用メモ

- STYLE_BASE_URL は UI ローカル設定のため、サーバ側では値を推定できない。必要に応じて UI から `X-Style-Base-Url` を付与して送信し、FixLog の相関分析に活用する。
- /static の 404 は errorhandler(404) にて `STATIC_404 path=<path> resolved=<file>` を記録済み。配置不一致の早期検知に有効。

### 次の一手（必要に応じて）

- UI 側で `X-Style-Base-Url` ヘッダーを送る仕組み（fetch の共通ラッパ）を導入し、プレビュー経路の相関ログを強化。
- /preview のヘッダーを Playwright からも直接検証するユーティリティを追加（Response オブジェクト取得）。

### 2025-10-16 UI 連携の微修正

- /style-manager と /dashboard のプレビュー読み込み（iframe.src）に `style_base_url=<localStorage.STYLE_BASE_URL or window.location.origin>` を付与。
  - サーバ側 FixLog（PREVIEW_OK / PREVIEW_UPSTREAM_ERR）の style_base_url と UI 設定の相関が容易に。
  - E2E 追加: `tests/e2e/test_style_manager_preview_query.py` で iframe.src に `style_base_url` が含まれることを検証。
