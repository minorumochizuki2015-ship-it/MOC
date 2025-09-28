# GoverningCore v5 - 統治核AIシステム

> **Cursor AI同等システム** - 統治核AI v5.0 モダン版

## 🚀 開発状況

- **最新PR**: [feature/enable-autopatch-autostart](https://github.com/minorumochizuki2015-ship-it/MOC/pull/new/feature/enable-autopatch-autostart) (commit: `dbe29e1`)
- **CI状況**: GitHub Actions実行中 - autopatch/autostart機能有効化
- **自動起動**: ✅ 15分間隔でタスクスケジューラ稼働中
- **品質ゲート**: ✅ pre-push hook (MyPy Best Effort + pytest + coverage)
- **自動データ投入**: ✅ Intake APIサーバー + 自動データ生成システム稼働中

## 📱 APK解析ツール

### 🎯 概要
HeyDooon APKファイルの構造とデータを解析するGUIアプリケーション。CustomTkinterを使用したモダンなインターフェースで、APKファイルの詳細分析が可能です。

### ✨ 主要機能
- **GUI解析**: ドラッグ&ドロップ対応のモダンUI
- **構造解析**: ファイル構造、マニフェスト、リソース分析
- **実装ヒント**: ゲーム開発に役立つ実装提案生成
- **履歴管理**: 解析結果の保存・参照機能
- **エクスポート**: JSON形式での詳細結果出力

### 🚀 起動方法
```bash
# GUI版APK解析ツール起動
start_apk_analyzer.bat

# または
python start_apk_analyzer.py
```

### 📁 関連ファイル
- `src/app_ui/apk_analyzer_app.py` - メインGUIアプリケーション
- `src/utils/apk_analyzer.py` - APK解析エンジン
- `tests/test_apk_analyzer.py` - テストスイート
- `docs/APK_ANALYZER_README.md` - 詳細ドキュメント

### 🔧 依存関係
```bash
pip install customtkinter>=5.2.0 lxml>=4.9.0 xmltodict>=0.13.0
```

## 🔄 自動データ投入システム

### 📡 Intake APIサーバー

Trae起動時に自動的にデータを受信・処理するHTTPサーバーが稼働します：

- **エンドポイント**: `http://127.0.0.1:8787/intake/post`
- **機能**: データ受信、スキーマ検証、重複チェック、自動保存
- **ディレクトリ**: `data/intake/` (accepted, errors, processed)
- **ログ**: `data/logs/current/intake_server_*.log`

```bash
# サーバー起動確認
curl http://127.0.0.1:8787/intake/status

# データ投入例
curl -X POST http://127.0.0.1:8787/intake/post \
  -H "Content-Type: application/json" \
  -d '{"source":"test","title":"テスト","domain":"general","prompt":"テストプロンプト"}'
```

### 🤖 自動データ生成システム

完全自動化されたデータ生成・投入システム：

#### 主要コンポーネント

1. **auto-post.ps1** - 自動データ生成・投入スクリプト
   - 一定間隔でのデータ生成（デフォルト: 30秒間隔）
   - API接続失敗時のファイル保存フォールバック
   - キルスイッチ機能（`.trae/disable_auto_post`）
   - 詳細ログ記録

2. **trae_autostart_enhanced.ps1** - 統合自動起動スクリプト
   - Intake APIサーバーの起動・監視
   - 自動データ生成の開始・管理
   - 既存Autostart処理との統合
   - リソース監視・バックオフ機能

3. **start_trae_auto.bat** - ワンクリック起動
   - 環境変数設定
   - PowerShellスクリプト実行
   - UTF-8エンコーディング対応

4. **setup_scheduler.ps1** - タスクスケジューラ設定
   - 自動起動タスクの登録
   - スケジュール管理
   - 権限設定

#### 使用方法

```powershell
# 即座に開始
.\start_trae_auto.bat

# スケジュール設定（管理者権限必要）
.\scripts\setup_scheduler.ps1

# 手動実行
.\scripts\auto-post.ps1 -IntervalSeconds 60 -MaxIterations 10

# 停止
New-Item -Type File .trae\disable_auto_post -Force
```

#### システム特徴

- **完全自動化**: Trae起動時に自動でデータ投入開始
- **フォールバック機能**: API障害時はファイル保存で継続
- **継続監視**: サーバー状態・リソース使用量を監視
- **キルスイッチ**: 緊急停止機能
- **ログ記録**: 詳細な実行ログ・エラーログ
- **リソース管理**: CPU・メモリ使用量制限

#### 監視・制御コマンド

```powershell
# システム状態確認
Get-Process | Where-Object {$_.ProcessName -like "*python*" -or $_.ProcessName -like "*powershell*"}

# ログ監視
Get-Content data\logs\current\auto_post_*.log -Tail 20 -Wait
Get-Content data\logs\current\intake_server_*.log -Tail 20 -Wait

# 自動投入制御
New-Item -Type File .trae\disable_auto_post -Force  # 停止
Remove-Item .trae\disable_auto_post -ErrorAction SilentlyContinue  # 再開

# データ確認
Get-ChildItem data\intake\accepted\ | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

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

# メトリクス確認
Get-Content data\logs\current\metrics.tsv -Tail 5
```

## 🔄 最新の改善作業（2025-09-22）

### ✅ trae_autostart.ps1 統合機能完成

1. **構文エラー修正完了**
   - 変数参照エラー修正: `"$name"` → `"${name}"`
   - Try/Catch構文の整理と統合
   - PowerShell構文チェック通過確認

2. **統合機能実装**
   - SFT取り込み処理の一体化
   - 重複防止機能の統合
   - ローテーション機能の統合
   - メトリクス記録機能の統合

3. **動作確認完了**
   - ドライランモード: 正常動作確認
   - `-Apply`モード: 実際の処理実行確認
   - メトリクス記録: `data/logs/current/metrics.tsv`への継続記録確認

### 📊 メトリクス機能状況

- **記録ファイル**: `data/logs/current/metrics.tsv`
- **記録項目**: タイムスタンプ、accepted、dup、errors、train_mb、lines
- **更新頻度**: 自動起動実行時（15分間隔）
- **最新記録**: 2025-09-22 06:16:03 - accepted=3, dup=1, errors=0, train_mb=0, lines=10

### 🎯 統合システム完成

- **SFT処理**: ✅ 自動取り込み・重複防止・エラーハンドリング
- **メトリクス**: ✅ 継続的な記録・TSVファイル管理
- **ログ管理**: ✅ 構造化ログ・ローテーション
- **品質保証**: ✅ ドライラン・構文チェック・動作確認

## 📝 ライセンス

統治核AIシステム v5.0 - Cursor AI同等システム

---
*最終更新: 2025年9月22日*
*自律運転システム完成: 2025-01-22*
*統合機能完成: 2025-09-22*
Cursor Git check: 2025-09-19T09:09:57+09:00
