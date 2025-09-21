# GoverningCore v5 - 統治核AIシステム

> **Cursor AI同等システム** - 統治核AI v5.0 モダン版 + 学習インテーク・アプリ

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
│  📥 学習インテーク・アプリ（新規追加）                      │
│  ├── app/intake_service/     # FastAPI Webアプリ          │
│  │   ├── api.py              # REST API エンドポイント     │
│  │   ├── ui.py               # Web UI ルーター            │
│  │   ├── schema.py           # データスキーマ              │
│  │   └── classifier.py       # ドメイン分類器              │
│  ├── tools/                  # データ処理ツール            │
│  │   ├── intake_filter.py    # データフィルタ・分類        │
│  │   ├── intake_admin.py     # 管理CLI                    │
│  │   └── export_sft_dataset.py # SFTデータセット生成      │
│  └── scripts/ops/            # 運用スクリプト              │
│       ├── start-intake-app.ps1 # アプリ起動               │
│       ├── push-to-intake.ps1   # HTTP Push               │
│       └── drop-to-intake.ps1   # ファイルDROP            │
├─────────────────────────────────────────────────────────────┤
│  🔧 ユーティリティ層                                       │
│  ├── genetic/                # 遺伝的アルゴリズム          │
│  ├── utils/                  # 設定・自動マッチング        │
│  └── legacy/                 # レガシーサポート             │
└─────────────────────────────────────────────────────────────┘
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

### 4. 学習インテーク・アプリ起動（新機能）

```bash
# PowerShellで実行
.\scripts\ops\start-intake-app.ps1

# ブラウザでアクセス
# http://127.0.0.1:8787/ui/
```

### 5. GPUサーバー起動

```powershell
# PowerShellで実行
.\scripts\Start-LocalAI-GPU.ps1
```

## 📥 学習インテーク・アプリ（新機能）

### 概要

**完全自動化された学習データ収集・管理システム**

- **ローカル専用**: 外部API不要、完全オフライン動作
- **Web UI**: ブラウザベースの直感的な操作画面
- **自動パイプライン**: POST/保存 → フィルタ → バケット → SFT更新まで自動完了
- **エディタ連動**: Cursor/Traeからの自動データ投入

### 主要機能

#### 1. データ投入

- **HTTP Push**: `POST http://127.0.0.1:8787/intake/post?auto=1`
- **ファイルDROP**: `data/intake/inbox/`にJSONファイルを配置
- **Web UI**: ブラウザフォームから直接投入

#### 2. 自動処理パイプライン

- **フィルタリング**: 重複除去、機微情報検出、品質チェック
- **ドメイン分類**: コード、文書、特許などの自動分類
- **バケット管理**: ドメイン別のデータ整理
- **SFT生成**: 学習用データセットの自動生成

#### 3. 管理・監視

- **リアルタイム監視**: システム状態の可視化
- **ライブ履歴**: 処理イベントのリアルタイム表示
- **手動操作**: 承認、拒否、編集、削除
- **ヘルスチェック**: システム稼働状況の確認

### 使用方法

#### 1. アプリ起動

```powershell
# 学習インテーク・アプリ起動
.\scripts\ops\start-intake-app.ps1

# ブラウザでアクセス
# http://127.0.0.1:8787/ui/
```

#### 2. データ投入

**HTTP Push（推奨）:**

```powershell
$body = @{
  source='Cursor'; title='test-case'; domain='code'; task_type='edit'
  prompt='プロンプト'; output='出力'; success=$true
  success_reasons='成功理由'; failure_reasons=''
  used_methods='SRP'; references='src/example.py'; privacy_level='none'
  tags='test,auto'
} | ConvertTo-Json -Depth 6

Invoke-RestMethod "http://127.0.0.1:8787/intake/post?auto=1" -Method Post -ContentType 'application/json' -Body $body
```

**ファイルDROP:**

```powershell
# JSONファイルをinboxに配置
@'
{"source":"Trae","title":"drop-test","domain":"code","task_type":"edit","success":true,"prompt":"プロンプト","output":"出力","privacy_level":"none"}
'@ | Set-Content "data\intake\inbox\test.json" -Encoding UTF8
```

#### 3. 自動化設定

**ログオン時自動起動:**

```powershell
SCHTASKS /Create /TN "gc-intake-app" /SC ONLOGON /RL HIGHEST /F /TR "powershell -ExecutionPolicy Bypass -File `"%USERPROFILE%\GoverningCore_v5_Slice\scripts\ops\start-intake-app.ps1`""
```

**データ収集ループ（1分間隔）:**

```powershell
SCHTASKS /Create /TN "gc-data-loop" /SC MINUTE /MO 1 /RL HIGHEST /F /TR "powershell -ExecutionPolicy Bypass -File `"%USERPROFILE%\GoverningCore_v5_Slice\scripts\data-collection-loop.ps1`""
```

### API仕様

#### エンドポイント

- **POST** `/intake/post?auto=1` - データ投入（自動処理）
- **GET** `/ui/` - Web UI
- **GET** `/ui/status` - システム状態
- **GET** `/ui/items` - アイテム一覧
- **POST** `/ui/approve` - アイテム承認
- **POST** `/ui/reject` - アイテム拒否
- **GET** `/healthz` - ヘルスチェック
- **GET** `/docs` - API仕様書

#### データスキーマ

```json
{
  "source": "Cursor|Trae|manual",
  "title": "ケース名",
  "domain": "code|write|patent|auto",
  "task_type": "edit|create|review|debug",
  "prompt": "プロンプト",
  "output": "出力",
  "success": true,
  "success_reasons": "成功理由",
  "failure_reasons": "失敗理由",
  "used_methods": "SRP,DRY",
  "references": "src/example.py,docs/guide.md",
  "privacy_level": "none|no_pii|sensitive",
  "tags": "test,auto,mini-eval"
}
```

### 運用スクリプト

#### ヘルスチェック

```powershell
# システム状態確認
.\scripts\ops\quick-health.ps1

# 詳細診断
.\scripts\ops\health-check.ps1
```

#### テスト・復旧

```powershell
# スモークテスト
.\scripts\ops\smoke-test.ps1

# クイック復旧
.\scripts\ops\quick-recovery.ps1
```

#### エディタ連動

```powershell
# Cursor連動
.\scripts\ops\cursor-integration.ps1 -Title "test" -Success $true -Prompt "p" -Output "o"

# Trae連動
.\scripts\ops\trae-integration.ps1 -Title "test" -Success $true -Prompt "p" -Output "o"
```

## ⚙️ 設定

設定ファイル: `data/config/settings.json`

```json
{
  "openai_base": "http://127.0.0.1:8080",
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
- **学習インテーク**: 自動化された学習データ収集・管理

### 🎨 インターフェース

- **モダンUI**: CustomTkinterベースの最新インターフェース
- **Cursor AI同等UI**: 従来のtkinterベースUI
- **学習インテークWeb UI**: FastAPIベースのWebインターフェース
- **フォールバック機能**: 自動的なUI切り替え

### 🔌 統合機能

- **多プロバイダ対応**: OpenAI互換、Ollama、Google AI
- **コード実行**: 安全なサンドボックス環境
- **ファイル管理**: 統合されたファイル操作
- **エージェントモード**: 自律的なタスク実行
- **自動学習パイプライン**: データ収集→フィルタ→学習→評価

## 📊 ログ・データ

- **対話ログ**: `data/logs/current/interaction_log.json`
- **進化データ**: `data/genetic/evolutionary_genome.json`
- **テーマ分析**: `data/evolved_themes.json`
- **学習データ**: `data/intake/`（inbox, accepted, rejected, buckets）
- **SFTデータ**: `data/sft/train.jsonl`, `data/sft/val.jsonl`
- **イベントログ**: `data/logs/current/intake_events.jsonl`

## 🚀 小回し強化パイプライン（2025年9月21日 完全完成・安定運転）

### 概要

完全ローカル学習→評価→置換の自動化パイプライン。Agent経由のpytest実行による詰まりを機械的に防止し、高速回帰チェックを実現。

### ✅ 最終受け入れチェック結果（2025年9月21日）

- **基本機能**: 全項目PASS（8/8スコア、10-15秒実行）
- **Git設定**: hooksPath設定済み（`.githooks`）
- **運用基盤**: 統合スクリプト群完成
- **パフォーマンス**: ヘルス1.18秒、回帰10-11秒
- **判定**: **GO** - 完全自走可能・安定運転中

## Final Acceptance (2025-09-21) - 安定運転確認

- Health: **1.18s** / OK (RTX3050, port_open=true)
- Mini eval: **8/8** (tools mode, timeout=15s, ~83-84s total)
- Gates: pre-commit / pre-push / nightly wired
- Rollback: `git checkout mini-eval-ok-20250921`
- **小回し強化**: ログ質↑・データ自走粒度↑・学習本格化・安全置換・メトリクス拡張
- **常駐運用**: 30分毎の自動収集→SFT→評価が安定運転中

### 運用状況（2025年9月21日現在）

- **タスクスケジューラ**: ✅ 正常稼働中（30分毎）
- **成功率**: ✅ 100%（直近3回全て成功）
- **レイテンシ**: ✅ 約83-84秒（安定）
- **外部API**: ✅ 完全ブロック（課金ゼロ）

Quick check:

```powershell
.\scripts\ops\quick-health.ps1
```

Weekly report:

```powershell
.\scripts\weekly-report.ps1
```

### 主要ツール

#### 1. ミニ評価（`tools/mini_eval.py`）

```bash
# 高速回帰: tools直呼び・短Timeout（推奨）
python tools/mini_eval.py --mode tools --timeout 12 \
  --baseline data/outputs/mini_eval_baseline.json \
  --out data/outputs/mini_eval.json

# 重い評価: agent経由（pytest実行リスク）
python tools/mini_eval.py --mode agent --timeout 60
```

#### 2. ローカル学習（`tools/train_local.py`）

```bash
# 学習計画生成
python tools/train_local.py --plan-only

# 実学習実行
python tools/train_local.py --trainer-cmd "python scripts/train_lora_local.py --train {train} --val {val} --out {outdir}"
```

#### 3. 自己データ収集（`tools/agent_cli.py`）

```bash
# 単発実行
python tools/agent_cli.py --goal "READMEを要約しdocs/summary.mdへ" --apply

# 自己データ収集ループ（N回）
python tools/agent_cli.py --goal "タスクを実行" --selfplay 3
```

#### 4. SFTデータセット生成（`tools/export_sft_dataset.py`）

```bash
# ログからSFTデータセット生成
python tools/export_sft_dataset.py --min_chars 8 --split 0.9
```

### 環境変数設定

```bash
# ミニ評価のデフォルト設定
set MINI_EVAL_MODE=tools          # tools直呼び（高速）
set MINI_EVAL_TIMEOUT=15          # タイムアウト15秒

# ローカル学習のトレーナー設定
set LOCAL_LORA_TRAINER="python scripts/train_lora_local.py --train {train} --val {val} --out {outdir}"

# 学習インテーク自動処理
set AUTO_PROCESS=1                # 自動パイプライン有効化
```

### 自動化フロー

1. **データ収集**: `agent_cli.py --selfplay N` または 学習インテーク・アプリ
2. **SFT生成**: `export_sft_dataset.py`
3. **学習実行**: `train_local.py`
4. **回帰評価**: `mini_eval.py --mode tools`
5. **失敗時自動停止**: 回帰検出で即中断

### 品質ゲート

- **pre-commit**: コード整形・型チェック・品質ゲート
- **pre-push**: 超高速回帰チェック（tools直呼び・12秒）
- **CI/CD**: 完全回帰チェック（agent経由・60秒）
- **手動**: 環境変数で柔軟な設定

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

### 学習インテーク・アプリ関連

- **サーバー起動失敗**: `.\scripts\ops\start-intake-app.ps1`で再起動
- **UI表示エラー**: ブラウザで`http://127.0.0.1:8787/ui/`にアクセス
- **データ投入失敗**: `.\scripts\ops\smoke-test.ps1`でテスト実行
- **自動処理停止**: `.\scripts\ops\quick-recovery.ps1`で復旧

## 📋 段階記録（2025年9月20日）

### 完了した段階

#### **M0: ルート検出レイヤ導入** ✅

- **コミット**: `64505e3`
- **内容**: パス解決レイヤの堅牢化
- **ファイル**: `src/common/paths.py`, `main_modern.py`

#### **M1: サーバー起動スクリプト移動** ✅

- **コミット**: `4869950`
- **内容**: サーバー起動スクリプトの整理
- **移動**: `start_server_*.bat` → `scripts/server/`

#### **M2: 文書と設定の移動** ✅

- **コミット**: `700c2c5`
- **内容**: 文書・設定ファイルの整理
- **移動**: `README.md` → `docs/`, `settings.json` → `config/`

#### **参照の穴埋め** ✅

- **コミット**: `7aaea66`
- **内容**: 設定ファイル解決機能追加
- **機能**: `resolve_config()` 関数

#### **ヘッドレス診断コマンド** ✅

- **コミット**: `5e9ca0d`
- **内容**: 1秒診断システム構築
- **ファイル**: `tools/quick_diagnose.py`, `scripts/ops/quick-diagnose.ps1`

#### **push前ブロック機能** ✅

- **コミット**: `d1051b3`
- **内容**: push前自動チェック機能
- **ファイル**: `.githooks/pre-push.ps1`, `.githooks/pre-push.bat`

#### **最終ハードニング** ✅

- **コミット**: `979ade3`
- **内容**: ダイアログ完全回避・堅牢化
- **機能**: Python自動検出・フォールバック

#### **学習インテーク・アプリ実装** ✅

- **コミット**: `学習インテーク・アプリ完全実装`
- **内容**: 完全自動化された学習データ収集・管理システム
- **機能**: Web UI、自動パイプライン、エディタ連動、リアルタイム監視

### 現在の安定状態

#### **診断結果**

```json
{
  "base": "http://127.0.0.1:8080",
  "env_has_trailing_v1": false,
  "server_ok": true,
  "server_info": 200,
  "ui_import_ok": true,
  "ui_import_err": null,
  "kernel_double_v1_ok": true,
  "kernel_scan_err": null,
  "config_ok": true,
  "config_info": "C:\\Users\\User\\GoverningCore_v5_Slice\\config\\settings.json",
  "port_open": true,
  "gpu": ["NVIDIA GeForce RTX 3050, 6144 MiB"],
  "start_scripts_found": true,
  "elapsed_ms": 917
}
```

#### **品質保証システム**

- **pre-commit**: コード整形・型チェック・品質ゲート
- **pre-push**: ヘッドレス診断・push前ブロック
- **commit-msg**: PTPルール・DCO検証

#### **使用方法**

```powershell
# 手動診断
.\.venv\Scripts\python.exe -X utf8 -u tools/quick_diagnose.py

# push時に自動ブロック
git push
```

### ロールバック用チェックポイント

#### **安定ポイント**

- **`b04f72c`**: checkpoint_20250920_211752（基本安定状態）
- **`979ade3`**: 最終ハードニング完了
- **`学習インテーク・アプリ`**: 完全自動化システム実装完了（現在のHEAD）

#### **ロールバック方法**

```bash
# 基本安定状態に戻る
git reset --hard b04f72c

# 最終ハードニング状態に戻る
git reset --hard 979ade3

# 学習インテーク・アプリ状態に戻る
git reset --hard HEAD
```

## 📋 Cursor作業標準フロー

### 1. 環境準備

- `.cursor/rules/`に追記したルール（small-rules, review-policy, spec-splitなど）をエディタで目視確認
- ルール追加後は**Cursorを再起動**してキャッシュをクリア（Rulesが反映されやすくなる）
- すべてのCLI実行は `.\\.venv\\Scripts\\python.exe -m ...` で実施（venv.mdcの徹底）

### 2. ブランチ運用（patch-diff.mdc追記に基づく）

- main/masterに直コミットせず、必ず`feature/xxx`や`rules-update`のような作業ブランチを切る
- `git add/commit` → `git push` → GitHub上でPR作成 → CI結果を確認 → mainへマージ

### 3. 作業ステップ

- **Plan→Test→Patch**の順に行う：
  - Plan: 設計や仕様（目的/前提/入出力/例）を先に書く（plan-test-patch.mdc）
  - Test: pytestやスキーマ検証などでローカルテスト実行
  - Patch: Test合格後に最小unified diffを作ってPRに出す

### 4. 削除・大量操作系（ターミナルが固まりやすい箇所）

- `Remove-Item`など大量ファイル操作はCursor内ターミナルより**外部PowerShell 7コンソール**で実行
- `Get-ChildItem … | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue` のように出力抑制＆エラー無視を併用すると固まりにくい
- Dry-Run（`-WhatIf`）を必ず実施してから本番実行（powershell.mdcのDryRun-Apply契約）

### 5. CIとGitHub Actions

- PRを出したらGitHub Actionsが自動実行されることを確認
- pytest・lintが通ってからレビュー→マージ

### 6. 秘密鍵・外部API（security.mdc追記に基づく）

- `OPENAI_COMPAT_BASE`と`API_KEY`以外の秘密はログ・PR・コメントに出さない
- 外部APIを一時有効化したら、作業終了後にダミー鍵に戻す

### 7. バックアップ・ロールバック

- 重要ファイルに変更をかける前に、今回のPowerShellスクリプトのようにSHA256でバックアップを取り、失敗時は即ロールバック

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

- **一貫して「Dry-Run→Apply切替」**を守る
- **最小unified diff＋例併記**でレビューしやすくする（guard.mdc追記に基づく）
- **Cursorターミナルに過負荷な操作は外部PSへ逃がす**

## 🤖 AI共有・引継ぎ情報

### 📊 現在の実装状況（2025年1月20日時点）

#### ✅ **完了済み機能**

1. **進化アルゴリズムシステム**
   - 遺伝的アルゴリズム（`src/genetic/genetic_algorithm.py`）
   - 適応度計算器（`src/genetic/fitness_calculator.py`）
   - 進化エンジン（`src/core/evolution.py`）
   - ベイジアン最適化（`src/core/simple_bo.py`）

2. **エージェント機能**
   - AgentMode（`src/core/agent_mode.py`）
   - 計画-実行フロー
   - タスク管理システム
   - UI統合（`src/ui/modern_interface.py`）

3. **UI安定化システム**
   - レイアウト変動抑制（≦2px）
   - ボタン幅統一機能
   - テキスト切り詰め機能
   - エラーハンドリング改善

4. **サーバー接続管理**
   - 接続状態監視
   - 自動再接続
   - エラー処理改善
   - パフォーマンス最適化

5. **学習インテーク・アプリ（新規追加）**
   - FastAPI Webアプリケーション
   - 自動データ処理パイプライン
   - リアルタイム監視・管理
   - エディタ連動機能

#### ⚠️ **現在の課題**

1. **SimpleBO履歴読み込みエラー**: `'result'`キーエラー（修正済み）
2. **psutilエラー表示**: UIでのエラー表示（修正済み）
3. **文字化け問題**: 一部で発生（Unicode正規化で対応済み）

#### 技術スタック

- **Python**: 3.10+
- **UI**: CustomTkinter + Tkinter + FastAPI
- **AI**: OpenAI互換API、Ollama
- **進化**: 遺伝的アルゴリズム + ベイジアン最適化
- **メモリ**: ブロックチェーン型対話履歴
- **品質管理**: mypy + black + isort + pytest
- **Web**: FastAPI + uvicorn + Jinja2

#### 📁 **重要ファイル**

```
src/
├── core/
│   ├── cursor_ai_system.py     # メインシステム統合
│   ├── kernel.py               # AIカーネル
│   ├── agent_mode.py           # エージェント機能
│   ├── evolution.py            # 進化エンジン
│   └── simple_bo.py            # ベイジアン最適化
├── genetic/
│   ├── genetic_algorithm.py    # 遺伝的アルゴリズム
│   └── fitness_calculator.py   # 適応度計算
└── ui/
    └── modern_interface.py     # モダンUI

app/
└── intake_service/
    ├── api.py                  # FastAPI Webアプリ
    ├── ui.py                   # Web UI ルーター
    ├── schema.py               # データスキーマ
    └── classifier.py           # ドメイン分類器

tools/
├── intake_filter.py            # データフィルタ・分類
├── intake_admin.py             # 管理CLI
└── export_sft_dataset.py       # SFTデータセット生成

scripts/ops/
├── start-intake-app.ps1        # アプリ起動
├── push-to-intake.ps1          # HTTP Push
└── drop-to-intake.ps1          # ファイルDROP
```

#### 起動方法

```bash
# 1. 仮想環境有効化
.venv\Scripts\activate

# 2. モダンUI起動
python main_modern.py

# 3. 学習インテーク・アプリ起動
.\scripts\ops\start-intake-app.ps1

# 4. バッチファイル起動（推奨）
start_modern_ui.bat
```

#### 🔄 **新セッションでの引継ぎ手順**

1. **環境確認**

   ```bash
   # 仮想環境確認
   .venv\Scripts\python.exe --version
   
   # 依存関係確認
   pip list | findstr "customtkinter psutil requests fastapi uvicorn"
   ```

2. **設定確認**

   ```bash
   # 設定ファイル確認
   type data\config\settings.json
   ```

3. **動作確認**

   ```bash
   # サーバー接続確認
   python -c "import requests; print(requests.get('http://127.0.0.1:8080/v1/models').status_code)"
   
   # 学習インテーク・アプリ確認
   python -c "import requests; print(requests.get('http://127.0.0.1:8787/healthz').status_code)"
   ```

4. **起動テスト**

   ```bash
   # モダンUI起動
   python main_modern.py
   
   # 学習インテーク・アプリ起動
   .\scripts\ops\start-intake-app.ps1
   ```

#### 開発ルール（絶対的ルール）

1. **差分比較必須**: 修正前後で差分を比較し、既存機能を保護
2. **段階的実装**: 小さな変更を段階的に実施し、各段階で動作確認
3. **実地テスト必須**: 修正後は必ず実地テストを実行し、動作を確認
4. **既存機能保護**: 修正時に既存機能を破損させないことを最優先
5. **ロールバック準備**: 問題発生時は即座にロールバック可能な状態を維持

#### 自動ゲート（機械的ルール違反防止）

**自動ゲート3点**でルール違反を機械的に阻止：

1. **保護ファイル改変ブロック** (`tools/check_protected.py`)
   - `main_modern.py`と`start_modern_ui.bat`の変更を自動ブロック
   - 変更時は`[GUARD]`エラーでコミット拒否

2. **1コミット=1ファイル小差分** (`tools/check_onefile.py`)
   - 1回のコミットで1ファイルのみ変更（400行以内）
   - 複数ファイル変更時は`[PATCH]`エラーでコミット拒否

3. **コミットメッセージにPlan→Test→Patch必須** (`tools/check_commit_msg.py`)
   - コミットメッセージに`Plan:`、`Test:`、`Patch:`セクション必須
   - 不足時は`[PTP]`エラーでコミット拒否

**運用フロー**:

```bash
# 1. チェックポイント作成
powershell -ExecutionPolicy Bypass -File tools/new_checkpoint.ps1 -Apply

# 2. Plan→Test→Patch実行
git add <1ファイルのみ>
git commit -m "Plan: <要約>
Test: <実施と結果>
Patch: <対象ファイル名>"
```

#### 🐛 **既知の問題と解決策**

1. **SimpleBO履歴読み込みエラー**
   - 原因: 混合ログ形式での`'result'`キー不足
   - 解決: `src/core/simple_bo.py`でフィルタリング実装済み

2. **psutilエラー表示**
   - 原因: UIでのエラーハンドリング不適切
   - 解決: `src/ui/modern_interface.py`で例外処理改善済み

3. **文字化け問題**
   - 原因: エンコーディング設定不備
   - 解決: Unicode正規化と制御文字除去で対応済み

4. **学習インテーク・アプリ関連**
   - 原因: サーバー起動失敗、UI表示エラー、データ投入失敗
   - 解決: 運用スクリプトで自動復旧機能実装済み

#### パフォーマンス指標

- **UI安定性**: レイアウト変動≦2px ✅
- **サーバー接続**: 正常動作 ✅
- **進化アルゴリズム**: 正常動作 ✅
- **エージェント機能**: 正常動作 ✅
- **文字化け**: 解決済み ✅
- **学習インテーク・アプリ**: 完全自動化 ✅

## 📝 ライセンス

統治核AIシステム v5.0 - Cursor AI同等システム + 学習インテーク・アプリ

---
*最終更新: 2025年1月20日*
Cursor Git check: 2025-09-19T09:09:57+09:00
