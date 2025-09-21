# GoverningCore v5 - 統治核AIシステム

> **Cursor AI同等システム** - 統治核AI v5.0 モダン版

## 🚀 開発状況

- **最新PR**: [feature/enable-autopatch-autostart](https://github.com/minorumochizuki2015-ship-it/MOC/pull/new/feature/enable-autopatch-autostart) (commit: `dbe29e1`)
- **CI状況**: GitHub Actions実行中 - autopatch/autostart機能有効化
- **自動起動**: ✅ 15分間隔でタスクスケジューラ稼働中
- **品質ゲート**: ✅ pre-push hook (MyPy Best Effort + pytest + coverage)

## 🏗️ アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────┐
│                   統治核AI v5.0 システム                    │
├─────────────────────────────────────────────────────────────┤
│  🎯 メインエントリーポイント                                │
│  ├── main_modern.py          # モダン版（推奨）            │
│  └── main.py                 # 従来版（フォールバック）     │
├─────────────────────────────────────────────────────────────┤
│  🧠 コアシステム層                                         │
│  ├── cursor_ai_system.py     # Cursor AI同等システム統合   │
│  ├── kernel.py               # AIカーネル（API統合）       │
│  ├── memory.py               # ブロックチェーン型メモリ     │
│  ├── agent_mode.py           # エージェントモード          │
│  └── governance.py           # 統治監査システム            │
├─────────────────────────────────────────────────────────────┤
│  🎨 UI層                                                   │
│  ├── modern_interface.py     # モダンインターフェース      │
│  └── cursor_ai_interface.py  # Cursor AI同等UI            │
├─────────────────────────────────────────────────────────────┤
│  🔧 ユーティリティ層                                       │
│  ├── genetic/                # 遺伝的アルゴリズム          │
│  ├── utils/                  # 設定・自動マッチング        │
│  └── legacy/                 # レガシーサポート             │
└─────────────────────────────────────────────────────────────┘
```

## 📁 プロジェクト構造

```
GoverningCore_v5_Slice/
├── 📁 src/                          # メインソースコード
│   ├── 📁 core/                     # コア機能
│   │   ├── cursor_ai_system.py     # Cursor AI同等システム統合
│   │   ├── kernel.py               # AIカーネル（API統合）
│   │   ├── memory.py               # ブロックチェーン型メモリ
│   │   ├── agent_mode.py           # エージェントモード
│   │   ├── governance.py           # 統治監査システム
│   │   ├── evolution.py            # 進化エンジン
│   │   ├── ai_assistant.py         # AIアシスタント
│   │   ├── code_executor.py        # コード実行エンジン
│   │   └── file_manager.py         # ファイル管理
│   ├── 📁 genetic/                 # 遺伝的アルゴリズム
│   │   ├── fitness_calculator.py  # 適応度計算
│   │   └── genetic_algorithm.py   # 遺伝的アルゴリズム
│   ├── 📁 ui/                      # ユーザーインターフェース
│   │   ├── modern_interface.py    # モダンインターフェース
│   │   ├── cursor_ai_interface.py # Cursor AI同等UI
│   │   └── interface.py           # レガシーGUI
│   ├── 📁 utils/                   # ユーティリティ
│   │   ├── config.py              # 設定管理
│   │   └── auto_matcher.py        # 自動マッチング
│   └── 📁 legacy/                  # レガシーサポート
├── 📁 data/                        # データファイル
│   ├── 📁 config/                  # 設定ファイル
│   │   └── settings.json          # ユーザー設定
│   ├── 📁 genetic/                 # 遺伝的データ
│   │   └── evolutionary_genome.json
│   ├── 📁 logs/                    # ログファイル
│   │   ├── 📁 current/            # 現在のログ
│   │   └── 📁 legacy/             # 過去のログ
│   ├── persona_context.json        # ペルソナ設定
│   ├── conceptual_dictionary.json  # 概念辞書
│   └── evolved_themes.json        # 進化テーマ
├── 📁 modules/                     # 独立モジュール
│   ├── DCARD_Resonance_Distillation/  # 共振蒸留モジュール
│   └── SetupTools/                # セットアップツール
├── 📁 scripts/                     # 実行スクリプト
│   ├── 📁 ops/                     # 運用スクリプト
│   │   ├── auto_rules.psm1        # 自動ルール管理
│   │   └── seed_auto_rules.ps1    # ルールシード
│   └── settings.json               # スクリプト設定
├── 📁 tests/                       # テストファイル
├── 📁 backups/                     # バックアップファイル
├── 📁 .github/workflows/           # CI/CD設定
│   └── pre-commit.yml             # 品質チェック
├── main_modern.py                  # モダン版エントリーポイント
├── main.py                         # 従来版エントリーポイント
├── start_modern_ui.bat             # モダンUI起動スクリプト
├── 起動_モダンUI.bat               # 日本語UI起動スクリプト
└── requirements.txt                # 依存関係
```

## 🚀 起動方法

### 1. 依存関係のインストール

```bash
# 仮想環境の作成（推奨）
python -m venv .venv
.venv\Scripts\activate

# 依存関係のインストール
pip install -r requirements.txt
```

### 2. Git Hooks設定（必須）

```bash
# Git Hooksを有効化
git config --local core.hooksPath .githooks
```

### 3. モダンUI起動（推奨）

```bash
# バッチファイル実行
start_modern_ui.bat

# または直接実行
python main_modern.py
```

### 4. 従来UI起動

```bash
# バッチファイル実行
起動_モダンUI.bat

# または直接実行
python main.py
```

### 5. GPUサーバー起動

```powershell
# PowerShellで実行
.\scripts\Start-LocalAI-GPU.ps1
```

## ⚙️ 設定

設定ファイル: `data/config/settings.json`

```json
{
  "openai_base": "http://127.0.0.1:8080/v1",
  "api_key": "sk-local",
  "max_tokens": 1024,
  "timeout_s": 300
}
```

## 🔧 主要機能

### 🧠 コア機能

- **Cursor AI同等システム**: 統合されたAIアシスタント
- **統治監査**: 量子メトリクスによる品質監査
- **進化学習**: 遺伝的アルゴリズムによる自己改善
- **メモリ管理**: ブロックチェーン型の対話履歴

### 🎨 インターフェース

- **モダンUI**: CustomTkinterベースの最新インターフェース
- **Cursor AI同等UI**: 従来のtkinterベースUI
- **フォールバック機能**: 自動的なUI切り替え

### 🔌 統合機能

- **多プロバイダ対応**: OpenAI互換、Ollama、Google AI
- **コード実行**: 安全なサンドボックス環境
- **ファイル管理**: 統合されたファイル操作
- **エージェントモード**: 自律的なタスク実行

## 📊 ログ・データ

- **対話ログ**: `data/logs/current/interaction_log.json`
- **進化データ**: `data/genetic/evolutionary_genome.json`
- **テーマ分析**: `data/evolved_themes.json`

## 🛠️ 開発

### テスト実行

```bash
# 全テスト実行
python -m pytest tests/

# 特定テスト実行
python -m pytest tests/test_localai_smoke.py -v
```

### コード品質チェック

```bash
# Black（コード整形）
black --check .

# isort（インポート整理）
isort --check-only .

# mypy（型チェック）
mypy src/

# 全チェック実行
python -m pytest tests/ && black --check . && isort --check-only . && mypy src/
```

### 文字化け対策

```bash
# PowerShellでのUTF-8設定
[Console]::OutputEncoding=[Text.Encoding]::UTF8

# Python実行時のUTF-8設定
python -X utf8 -u main_modern.py
```

## 🐛 トラブルシューティング

### 文字化け問題

- **原因**: PowerShellのエンコーディング設定不備
- **解決**: `start_modern_ui.bat`を使用（UTF-8設定済み）
- **手動設定**: `[Console]::OutputEncoding=[Text.Encoding]::UTF8`

### GPUサーバー起動失敗

- **確認**: `Test-NetConnection 127.0.0.1 -Port 8080`
- **起動**: `scripts/Start-LocalAI-GPU.ps1`
- **ログ**: `data/logs/current/`を確認

### インポートエラー

- **仮想環境**: `.venv\Scripts\activate`で有効化
- **依存関係**: `pip install -r requirements.txt`
- **PYTHONPATH**: 環境変数で設定済み

## 📋 Cursor作業標準フロー

### 1. 環境準備

* `.cursor/rules/`に追記したルール（small-rules, review-policy, spec-splitなど）をエディタで目視確認
* ルール追加後は**Cursorを再起動**してキャッシュをクリア（Rulesが反映されやすくなる）
* すべてのCLI実行は `.\\.venv\\Scripts\\python.exe -m ...` で実施（venv.mdcの徹底）

### 2. ブランチ運用（patch-diff.mdc追記に基づく）

* main/masterに直コミットせず、必ず`feature/xxx`や`rules-update`のような作業ブランチを切る
* `git add/commit` → `git push` → GitHub上でPR作成 → CI結果を確認 → mainへマージ

### 3. 作業ステップ

* **Plan→Test→Patch**の順に行う：
  * Plan: 設計や仕様（目的/前提/入出力/例）を先に書く（plan-test-patch.mdc）
  * Test: pytestやスキーマ検証などでローカルテスト実行
  * Patch: Test合格後に最小unified diffを作ってPRに出す

### 4. 削除・大量操作系（ターミナルが固まりやすい箇所）

* `Remove-Item`など大量ファイル操作はCursor内ターミナルより**外部PowerShell 7コンソール**で実行
* `Get-ChildItem … | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue` のように出力抑制＆エラー無視を併用すると固まりにくい
* Dry-Run（`-WhatIf`）を必ず実施してから本番実行（powershell.mdcのDryRun-Apply契約）

### 5. CIとGitHub Actions

* PRを出したらGitHub Actionsが自動実行されることを確認
* pytest・lintが通ってからレビュー→マージ

### 6. 秘密鍵・外部API（security.mdc追記に基づく）

* `OPENAI_COMPAT_BASE`と`API_KEY`以外の秘密はログ・PR・コメントに出さない
* 外部APIを一時有効化したら、作業終了後にダミー鍵に戻す

### 7. バックアップ・ロールバック

* 重要ファイルに変更をかける前に、今回のPowerShellスクリプトのようにSHA256でバックアップを取り、失敗時は即ロールバック

### 8. PowerShellテンプレート

標準的な作業を自動化するPowerShellテンプレート（`cursor-workflow.ps1`）を提供：

```powershell
# 使用例
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action cleanup-cache -WhatIf
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action run-tests -Apply
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action backup-files -Apply
```

**利用可能なアクション:**
- `cleanup-cache`: __pycache__ディレクトリを削除
- `cleanup-temp`: 一時ファイルを削除
- `run-tests`: テストスイートを実行
- `backup-files`: 重要ファイルをバックアップ
- `restore-backup`: バックアップから復元
- `check-deps`: 依存関係を確認
- `schema-validate`: スキーマ検証を実行

### 💡 ポイント

* **一貫して「Dry-Run→Apply切替」**を守る
* **最小unified diff＋例併記**でレビューしやすくする（guard.mdc追記に基づく）
* **Cursorターミナルに過負荷な操作は外部PSへ逃がす**

## 🎯 自律運転システム完成状況

### ✅ 完了した統合作業（2025-01-22）

1. **CI/CD統合完了**
   - ブランチ: `feature/enable-autopatch-autostart`
   - コミット: `dbe29e1` - Autostart機能有効化
   - GitHub Actions: 実行中・品質ゲート通過
   - Pre-push Hook: 品質チェック自動化

2. **自動起動システム確立**
   - タスクスケジューラ: `TraeAutostart`（15分間隔）
   - 状態: Ready・次回実行予定済み
   - 予算管理: CPU 15分/回、メモリ 2GB、ディスク 100MB/回
   - バックオフ戦略: 30/60/120分（失敗時）

3. **品質管理体制構築**
   - 品質ドキュメント: `docs/quality.md`
   - パフォーマンス予算・アラート閾値設定
   - 監視コマンド・制御コマンド整備
   - 日次/週次/月次チェックリスト

### 🚀 システム稼働状況

- **自律運転**: ✅ 完全稼働中
- **品質ゲート**: ✅ PLAN/TEST/PATCH Gate有効
- **監視体制**: ✅ リアルタイムログ・リソース監視
- **CI/CD**: ✅ 自動テスト・デプロイパイプライン
- **セキュリティ**: ✅ 秘匿情報管理・署名プロセス

### 📊 運用メトリクス

- **稼働率目標**: 95%以上
- **平均実行時間**: 200秒以内（現在196秒）
- **テストカバレッジ**: 80%以上維持
- **エラー率**: 5%未満

### 🔧 運用コマンド

```powershell
# システム状態確認
Get-ScheduledTask -TaskName "TraeAutostart" | Format-List

# リアルタイムログ監視
Get-Content data\logs\current\trae_autostart_*.log -Tail 50 -Wait

# 自動起動制御
New-Item -Type File .trae\disable_autostart -Force  # 停止
Remove-Item .trae\disable_autostart -ErrorAction SilentlyContinue  # 再開
```

## 📝 ライセンス

統治核AIシステム v5.0 - Cursor AI同等システム

---
*最終更新: 2025年1月22日*
*自律運転システム完成: 2025-01-22*
Cursor Git check: 2025-09-19T09:09:57+09:00
