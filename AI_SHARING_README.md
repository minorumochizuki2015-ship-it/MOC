# 🤖 AI共有用プロジェクト状況レポート

> **作成日時**: 2025年9月20日 6:02 JST  
> **プロジェクト**: GoverningCore_v5_Slice - Cursor AI同等システム  
> **目的**: 別AIとの状況共有・引き継ぎ用

## 📊 現在の状況サマリー

### ✅ **完了済み項目**

- **Cursor Rules統合**: 6つの新ルール追加完了
- **Git統合**: ブランチ戦略・DCO・commitlint設定完了
- **CI/CD**: GitHub Actions設定完了
- **推論最適化**: モデルID修正・GPU設定最適化完了
- **PowerShell自動化**: ワークフロー自動化スクリプト完成

### ⚠️ **現在の課題**

- **推論速度**: 10トークン/秒（改善の余地あり）
- **CPU使用率**: 大幅改善済み（304秒→12秒）

## 🏗️ プロジェクト構造

```
GoverningCore_v5_Slice/
├── .cursor/rules/           # Cursor AIルール設定
│   ├── guard.mdc           # small-rules追加済み
│   ├── patch-diff.mdc      # review-policy追加済み
│   ├── plan-test-patch.mdc # spec-split追加済み
│   ├── powershell.mdc      # dryrun-apply-contract追加済み
│   ├── security.mdc        # secret-guard追加済み
│   └── venv.mdc           # venv-enforce追加済み
├── .github/workflows/       # CI/CD設定
│   ├── ci.yml              # メインCI
│   ├── commit-gates.yml    # DCO・commitlint
│   └── pre-commit.yml      # コード品質チェック
├── data/                    # データ・設定
│   ├── config/settings.json # 最適化済み設定
│   ├── logs/               # ログファイル
│   └── backups/            # バックアップ
├── src/                     # ソースコード
│   ├── core/               # コア機能
│   ├── ui/                 # UI関連
│   ├── utils/              # ユーティリティ
│   └── genetic/            # 遺伝的アルゴリズム
├── llama.cpp/              # ローカルAIサーバー
├── modules/                # モジュール
└── tools/                  # ツール類
```

## ⚙️ 現在の設定

### **AIサーバー設定** (`data/config/settings.json`)

```json
{
  "openai_base": "http://127.0.0.1:8080/v1",
  "api_key": "sk-local",
  "model_id_coder": "/models/qwen2-7b-instruct-q4_k_m.gguf",
  "default_model_id": "/models/qwen2-7b-instruct-q4_k_m.gguf",
  "max_tokens": 2048,
  "timeout_s": 60,
  "temperature": 0.25,
  "top_p": 0.95,
  "repeat_penalty": 1.1,
  "context_size": 4096,
  "gpu_layers": 35,
  "server_port": 8080,
  "server_host": "127.0.0.1"
}
```

### **推論性能**

- **ポート**: 8080 (正常稼働中)
- **モデル**: qwen2-7b-instruct-q4_k_m.gguf
- **推論速度**: 10トークン/秒
- **CPU使用率**: 12.45秒 (大幅改善)
- **メモリ使用量**: 189MB

## 🔧 追加されたルール

### 1. **small-rules** (guard.mdc)

- 1ルール=1懸念の原則
- 最小unified diff + 実行コマンド併記
- 大仕様は複数MDCへ分割

### 2. **review-policy** (patch-diff.mdc)

- ブランチ→PR→レビュー→mainマージ
- 最小unified diffのみ提示
- 全置換・整形差分を拒否

### 3. **spec-split** (plan-test-patch.mdc)

- テンプレート穴埋め仕様提示
- 設計と実行の分離
- Plan合格前のPatch生成禁止

### 4. **dryrun-apply-contract** (powershell.mdc)

- Dry-Run既定
- 実行前preflight必須
- 失敗時即ロールバック

### 5. **secret-guard** (security.mdc)

- 機密は`OPENAI_COMPAT_BASE`/`API_KEY`のみ
- ログ/PR/コメント出力禁止
- 外部API一時有効化

### 6. **venv-enforce** (venv.mdc)

- 全CLIは`.\\.venv\\Scripts\\python.exe -m ...`で実行
- グローバル実行禁止

## 🚀 利用可能なツール

### **PowerShell自動化** (`cursor-workflow.ps1`)

```powershell
# 使用例
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action cleanup-cache -WhatIf
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action run-tests -Apply
pwsh -NoProfile -File .\cursor-workflow.ps1 -Action backup-files -Apply
```

**利用可能なアクション:**

- `cleanup-cache`: __pycache__ディレクトリ削除
- `cleanup-temp`: 一時ファイル削除
- `run-tests`: テストスイート実行
- `backup-files`: 重要ファイルバックアップ
- `restore-backup`: バックアップから復元
- `check-deps`: 依存関係確認
- `schema-validate`: スキーマ検証実行

## 📈 パフォーマンス改善履歴

### **Before (修正前)**

- CPU使用率: 304.81秒
- メモリ使用量: 208MB
- 推論速度: 10トークン/秒
- モデルID不一致

### **After (修正後)**

- CPU使用率: 12.45秒 (96%改善)
- メモリ使用量: 189MB (9%改善)
- 推論速度: 10トークン/秒 (変化なし)
- モデルID統一済み

## 🔄 次の最適化提案

### **1. GPU設定の更なる最適化**

```json
{
  "gpu_layers": 40,      // 35→40に増加
  "context_size": 2048,  // 4096→2048に削減
  "batch_size": 512      // 新規追加
}
```

### **2. サーバー起動パラメータ最適化**

```bash
python -m llama_cpp.server \
  --model /path/to/qwen2-7b-instruct-q4_k_m.gguf \
  --gpu-layers 40 \
  --ctx-size 2048 \
  --batch-size 512 \
  --threads 8
```

### **3. モデル量子化検討**

- 現在: q4_k_m (適切)
- 候補: q4_0, q3_k_m (より軽量)

## 🛠️ 開発環境

- **OS**: Windows 10 (10.0.26100)
- **Shell**: PowerShell 7
- **Python**: 仮想環境 (.venv)
- **AIサーバー**: llama.cpp (ポート8080)
- **Git**: ブランチ戦略 + DCO + commitlint
- **CI/CD**: GitHub Actions

## 📝 重要な注意事項

1. **既存README.mdは上書き禁止**
2. **すべてのCLI実行は.venv経由**
3. **Dry-Run→Apply切替を徹底**
4. **最小unified diff + 例併記**
5. **機密情報のログ出力禁止**

## 🔗 関連ファイル

- **メインREADME**: `README.md` (上書き禁止)
- **設定ファイル**: `data/config/settings.json`
- **PowerShell自動化**: `cursor-workflow.ps1`
- **Cursor Rules**: `.cursor/rules/*.mdc`
- **CI/CD設定**: `.github/workflows/*.yml`

---

**最終更新**: 2025年9月20日 6:02 JST  
**作成者**: Cursor AI Assistant  
**目的**: 別AIとの状況共有・引き継ぎ


