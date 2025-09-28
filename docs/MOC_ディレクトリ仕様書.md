# MOC ディレクトリ仕様書

## 📋 概要

MOC（Master of Code）プロジェクトのディレクトリ構造を整理し、ゲーム解析・開発に適した構造に再編成するための仕様書です。

## 🎯 整理の目的

1. **開発効率の向上**: 関連ファイルの論理的なグループ化
2. **保守性の向上**: 明確な責任分離とファイル配置
3. **可読性の向上**: 直感的なディレクトリ構造
4. **拡張性の確保**: 将来の機能追加に対応可能な構造

## 📁 現在の問題点

### ルートディレクトリの混雑
- テストファイル、スクリプト、設定ファイルが混在
- 一時的なファイルや実験的なファイルが残存
- 目的別の分類が不明確

### データディレクトリの複雑化
- 解析結果、テスト出力、バックアップが混在
- 重複データや古いデータの蓄積
- 用途不明なディレクトリの存在

## 🏗️ 新しいディレクトリ構造（提案）

```
MOC/
├── 📊 analysis/                    # ゲーム解析関連
│   ├── apk/                       # APK解析結果
│   │   ├── results/               # 解析結果JSON
│   │   ├── reports/               # 解析レポート
│   │   └── cache/                 # 解析キャッシュ
│   ├── unity/                     # Unity解析結果
│   │   ├── projects/              # 解析済みプロジェクト
│   │   ├── assets/                # 抽出アセット
│   │   └── scripts/               # 抽出スクリプト
│   └── tools/                     # 解析ツール
│       ├── apk_analyzer/          # APK解析ツール
│       ├── unity_analyzer/        # Unity解析ツール
│       └── frida_scripts/         # 動的解析スクリプト
│
├── 🎮 development/                 # ゲーム開発関連
│   ├── projects/                  # 開発中プロジェクト
│   │   ├── heydoon_clone/         # HeyDooonクローン
│   │   └── templates/             # プロジェクトテンプレート
│   ├── assets/                    # 共通アセット
│   │   ├── images/                # 画像リソース
│   │   ├── sounds/                # 音声リソース
│   │   └── fonts/                 # フォントリソース
│   └── scripts/                   # 開発スクリプト
│       ├── generators/            # コード生成スクリプト
│       └── utilities/             # 開発ユーティリティ
│
├── 🔧 tools/                      # 開発ツール
│   ├── launchers/                 # 起動スクリプト
│   │   ├── apk_analyzer.bat      # APK解析ツール起動
│   │   ├── unity_launcher.bat    # Unity起動
│   │   └── modern_ui.bat         # モダンUI起動
│   ├── automation/                # 自動化スクリプト
│   │   ├── test_runners/          # テスト実行
│   │   └── build_scripts/         # ビルドスクリプト
│   └── utilities/                 # ユーティリティ
│       ├── cleanup/               # クリーンアップツール
│       └── validation/            # 検証ツール
│
├── 📚 docs/                       # ドキュメント
│   ├── specifications/            # 仕様書
│   ├── guides/                    # ガイド・チュートリアル
│   ├── api/                       # API仕様
│   └── analysis_reports/          # 解析レポート
│
├── 🧪 workspace/                  # 作業領域
│   ├── experiments/               # 実験的なコード
│   ├── prototypes/                # プロトタイプ
│   ├── temp/                      # 一時ファイル
│   └── sandbox/                   # サンドボックス
│
├── ⚙️ config/                     # 設定・構成
│   ├── project/                   # プロジェクト設定
│   ├── tools/                     # ツール設定
│   └── environment/               # 環境設定
│
└── 📦 core/                       # コアシステム（既存のsrc/）
    ├── api/                       # APIサーバー
    ├── app_core/                  # アプリケーションコア
    ├── app_ui/                    # UIコンポーネント
    ├── core/                      # システムコア
    ├── utils/                     # ユーティリティ
    └── legacy/                    # レガシーコード
```

## 🔄 移行計画

### フェーズ1: 新しいディレクトリ構造の作成
1. 新しいディレクトリ構造を作成
2. 既存ファイルの分類・整理
3. 移動対象ファイルの特定

### フェーズ2: ファイルの移動・整理
1. 設定ファイルの移動
2. ツール・スクリプトの移動
3. ドキュメントの移動
4. データファイルの整理

### フェーズ3: 参照の更新
1. スクリプト内のパス参照更新
2. 設定ファイルのパス更新
3. ドキュメントのリンク更新

### フェーズ4: 検証・テスト
1. 移動後の動作確認
2. テストの実行
3. 問題の修正

## 📋 移動対象ファイル一覧

### 🔧 ツール・スクリプト
```
移動元 → 移動先
start_*.bat → tools/launchers/
create_*.py → tools/automation/
test_*.py → workspace/experiments/ (または削除)
```

### 📊 解析関連
```
移動元 → 移動先
data/apk_analysis/ → analysis/apk/results/
data/unity_analysis/ → analysis/unity/
data/frida_scripts/ → analysis/tools/frida_scripts/
```

### 🎮 開発関連
```
移動元 → 移動先
data/clone_generation/ → development/projects/
assets/ → development/assets/
```

### 📚 ドキュメント
```
移動元 → 移動先
docs/ → docs/ (整理のみ)
README.md → docs/guides/
unity_setup_guide.md → docs/guides/
```

## ⚠️ 注意事項

1. **バックアップ**: 移動前に重要なファイルをバックアップ
2. **段階的実行**: 一度に全てを移動せず、段階的に実行
3. **動作確認**: 各段階で動作確認を実施
4. **ロールバック準備**: 問題発生時のロールバック手順を準備

## 🎯 期待される効果

1. **開発効率向上**: 関連ファイルの素早い発見
2. **保守性向上**: 明確な責任分離
3. **新規参加者の理解促進**: 直感的な構造
4. **プロジェクト拡張の容易性**: 論理的な分類

## 📝 更新履歴

- 2024-01-XX: 初版作成
- 2024-01-XX: 移行計画詳細化