# GoverningCore v5 - 統治核AIシステム

## 📁 プロジェクト構造

```
GoverningCore_v5_Slice/
├── 📁 src/                          # メインソースコード
│   ├── 📁 core/                     # コア機能
│   │   ├── kernel.py               # AIカーネル（API統合）
│   │   ├── governance.py           # 統治監査システム
│   │   ├── memory.py               # ブロックチェーン型メモリ
│   │   └── evolution.py            # 進化エンジン
│   ├── 📁 genetic/                 # 遺伝的アルゴリズム
│   │   ├── fitness_calculator.py  # 適応度計算
│   │   └── genetic_algorithm.py   # 遺伝的アルゴリズム
│   ├── 📁 ui/                      # ユーザーインターフェース
│   │   └── interface.py           # メインGUI
│   └── 📁 utils/                   # ユーティリティ
│       ├── config.py              # 設定管理
│       └── auto_matcher.py        # 自動マッチング
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
│   ├── Start-LocalAI-GPU.ps1      # GPU起動スクリプト
│   └── ops/                       # 運用スクリプト
├── 📁 tests/                       # テストファイル
├── 📁 docs/                        # ドキュメント
├── 📁 backups/                     # バックアップファイル
├── main.py                        # エントリーポイント
└── requirements.txt               # 依存関係
```

## 🚀 起動方法

### 1. 依存関係のインストール
```bash
pip install -r requirements.txt
```

### 2. 起動（推奨）
```
起動.bat をダブルクリック
```

### 3. 直接起動
```powershell
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

- **統治監査**: 量子メトリクスによる品質監査
- **進化学習**: 遺伝的アルゴリズムによる自己改善
- **メモリ管理**: ブロックチェーン型の対話履歴
- **多プロバイダ対応**: OpenAI互換、Ollama、Google AI

## 📊 ログ・データ

- **対話ログ**: `data/logs/current/interaction_log.json`
- **進化データ**: `data/genetic/evolutionary_genome.json`
- **テーマ分析**: `data/evolved_themes.json`

## 🛠️ 開発

### テスト実行
```bash
python -m pytest tests/
```

### コード品質チェック
```bash
python -m flake8 src/
```

## 📝 ライセンス

統治核AIシステム v5.0

