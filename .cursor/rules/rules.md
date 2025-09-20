## ✅【完全統合版】`rules.md` for Cursor Workspace

このドキュメントは `.cursor/rules/` フォルダに配置された **すべてのローカルルールファイル（`.mdc`）** を記述した README です。各ルールは Cursor により自動適用されるもので、保存時チェック、CI連携、ファイル保護、セキュリティ統制などに関わります。

---

### 🔖 構成一覧

| No. | ファイル名 | 概要 | 自動適用 | 補足 |
|-----|------------|------|-----------|------|
| 1   | `backup-rule.mdc` | ファイル変更前の自動バックアップ作成 | ✅ Always Apply | `./backups/` に保存。失敗時はロールバック |
| 2   | `checkpoint.mdc` | 大規模変更前に git checkpoint を必須化 | ✅ Always Apply | PLAN のみ返す構成あり |
| 3   | `eol-precommit.mdc` | LF + UTF-8(no BOM) 強制 | ✅ Always Apply | .bat/.cmd を除く |
| 4   | `format.mdc` | 保存時に `black` + `isort` 強制整形 | ✅ Always Apply | `pyproject.toml` に準拠 |
| 5   | `guard.mdc` | 保護ファイル（`main_modern.py`など）は PLAN→PATCH制 | ✅ Always Apply | DryRun → Apply 必須 |
| 6   | `mypy.mdc` | `src/**` を対象に `mypy strict` を強制 | ✅ Always Apply | `backups/**` は除外 |
| 7   | `no-self-mod.mdc` | `.cursor/**` や `tools/checkpoint.ps1` 自己修正禁止 | ✅ Always Apply | PLAN のみ可 |
| 8   | `patch-diff.mdc` | 最小 unified diff のみ許容 | ✅ Always Apply | 空白変更／全置換禁止 |
| 9   | `plan-test-patch.mdc` | Plan → Test → Patch を強制 | ✅ Always Apply | チェックポイント必須 |
| 10  | `powershell.mdc` | PS スクリプトは DryRun前提＋制限強化 | ✅ Always Apply | 三引数 -replace 禁止 |
| 11  | `python.mdc` | Pythonスタイルガイド強制 | ✅ Always Apply | 純関数＋logging＋型 |
| 12  | `security.mdc` | 秘密漏洩対策（API_KEY等） | ✅ Always Apply | ログへの出力禁止 |
| 13  | `venv.mdc` | `.venv/Scripts/python.exe` 強制 | ✅ Always Apply | グローバル実行禁止 |
| 14  | `auto-gate.mdc` | 自動ゲート3点でルール違反防止 | ✅ Always Apply | 機械的チェック強制 |
| 15  | `rule-priority.mdc` | ルール優先順位の明確化 | ✅ Always Apply | 判断プロセス統一 |
| 16  | `quality-gate.mdc` | 品質保証プロセスの強化 | ✅ Always Apply | 必須チェックリスト |

---

### 🛡️ ルール補足（重要ルール解説）

#### 📌 `backup-rule.mdc`

重要ファイル（`main_modern.py`, `start_modern_ui.bat` 等）を変更する前に、`backups/` に自動保存します。失敗時は変更をロールバックし、安全性を担保。

#### 📌 `guard.mdc`

保護ファイルに対して直接変更はできず、**Plan → Apply** の承認ステップが必要です。Plan中に DryRun、Apply時は atomic write（原子的書込）が必須です。

#### 📌 `format.mdc`

保存と同時に `black` と `isort` により整形され、未整形コードは保存できません。

#### 📌 `mypy.mdc`

型注釈・strict チェックを全コードに適用。`Optional` や `Any` の使用も明示が必要です。

#### 📌 `plan-test-patch.mdc`

開発サイクルは `Plan → Test → Patch` の 3段階で構成され、テストパスが確認されるまで PATCH 出力は拒否されます。

#### 📌 `auto-gate.mdc`

自動ゲート3点（保護ファイルブロック、1ファイル制限、コミットメッセージチェック）により、ルール違反を機械的に阻止します。pre-commitフックとして自動実行され、違反時は即座にコミット拒否されます。

#### 📌 `rule-priority.mdc`

ルール優先順位を明確化し、判断プロセスを統一します。安全ルール > 技術的ルール > ユーザー指示の順で優先し、ルール違反時はPlanのみ返します。

#### 📌 `quality-gate.mdc`

品質保証プロセスを強化し、必須チェックリストを提供します。変更前・中・後の各段階で必要な確認項目を明示し、テスト合格前の実装を禁止します。

---

### 💡 推奨運用

- `.cursor/rules/` に本ルール一覧（この `rules.md`）を **ルール仕様書**として保存
- `.pre-commit-config.yaml` と連携させて、`black`, `isort`, `mypy`, `pytest` のCI自動実行
- GitHub Actions（`.github/workflows/ci.yml`）による PR 時チェック自動化

---

### 📝 保存パス推奨

```
.cursor/
├── rules/
│   ├── *.mdc
│   └── rules.md   👈 ← 本ファイル
```

---

### 🚀 更新履歴

| 日付 | 担当 | 内容 |
|------|------|------|
| 2025-09-16 | ChatGPT（Cursor連携）| 画像ルール解析 → 完全統合版生成 |
