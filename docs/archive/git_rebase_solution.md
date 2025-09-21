[1mdiff --git a/README.md b/README.md[m
[1mindex e0d9335..3f53e6d 100644[m
[1m--- a/README.md[m
[1m+++ b/README.md[m
[36m@@ -89,6 +89,7 @@[m [mGoverningCore_v5_Slice/[m
 ## 🚀 起動方法[m
 [m
 ### 1. 依存関係のインストール[m
[32m+[m
 ```bash[m
 # 仮想環境の作成（推奨）[m
 python -m venv .venv[m
[36m@@ -99,12 +100,14 @@[m [mpip install -r requirements.txt[m
 ```[m
 [m
 ### 2. Git Hooks設定（必須）[m
[32m+[m
 ```bash[m
 # Git Hooksを有効化[m
 git config --local core.hooksPath .githooks[m
 ```[m
 [m
 ### 3. モダンUI起動（推奨）[m
[32m+[m
 ```bash[m
 # バッチファイル実行[m
 start_modern_ui.bat[m
[36m@@ -114,6 +117,7 @@[m [mpython main_modern.py[m
 ```[m
 [m
 ### 4. 従来UI起動[m
[32m+[m
 ```bash[m
 # バッチファイル実行[m
 起動_モダンUI.bat[m
[36m@@ -123,6 +127,7 @@[m [mpython main.py[m
 ```[m
 [m
 ### 5. GPUサーバー起動[m
[32m+[m
 ```powershell[m
 # PowerShellで実行[m
 .\scripts\Start-LocalAI-GPU.ps1[m
[36m@@ -131,6 +136,7 @@[m [mpython main.py[m
 ## ⚙️ 設定[m
 [m
 設定ファイル: `data/config/settings.json`[m
[32m+[m
 ```json[m
 {[m
   "openai_base": "http://127.0.0.1:8080/v1",[m
[36m@@ -143,17 +149,20 @@[m [mpython main.py[m
 ## 🔧 主要機能[m
 [m
 ### 🧠 コア機能[m
[32m+[m
 - **Cursor AI同等システム**: 統合されたAIアシスタント[m
 - **統治監査**: 量子メトリクスによる品質監査[m
 - **進化学習**: 遺伝的アルゴリズムによる自己改善[m
 - **メモリ管理**: ブロックチェーン型の対話履歴[m
 [m
 ### 🎨 インターフェース[m
[32m+[m
 - **モダンUI**: CustomTkinterベースの最新インターフェース[m
 - **Cursor AI同等UI**: 従来のtkinterベースUI[m
 - **フォールバック機能**: 自動的なUI切り替え[m
 [m
 ### 🔌 統合機能[m
[32m+[m
 - **多プロバイダ対応**: OpenAI互換、Ollama、Google AI[m
 - **コード実行**: 安全なサンドボックス環境[m
 - **ファイル管理**: 統合されたファイル操作[m
[36m@@ -168,6 +177,7 @@[m [mpython main.py[m
 ## 🛠️ 開発[m
 [m
 ### テスト実行[m
[32m+[m
 ```bash[m
 # 全テスト実行[m
 python -m pytest tests/[m
[36m@@ -177,6 +187,7 @@[m [mpython -m pytest tests/test_localai_smoke.py -v[m
 ```[m
 [m
 ### コード品質チェック[m
[32m+[m
 ```bash[m
 # Black（コード整形）[m
 black --check .[m
[36m@@ -192,6 +203,7 @@[m [mpython -m pytest tests/ && black --check . && isort --check-only . && mypy src/[m
 ```[m
 [m
 ### 文字化け対策[m
[32m+[m
 ```bash[m
 # PowerShellでのUTF-8設定[m
 [Console]::OutputEncoding=[Text.Encoding]::UTF8[m
[36m@@ -203,16 +215,19 @@[m [mpython -X utf8 -u main_modern.py[m
 ## 🐛 トラブルシューティング[m
 [m
 ### 文字化け問題[m
[32m+[m
 - **原因**: PowerShellのエンコーディング設定不備[m
 - **解決**: `start_modern_ui.bat`を使用（UTF-8設定済み）[m
 - **手動設定**: `[Console]::OutputEncoding=[Text.Encoding]::UTF8`[m
 [m
 ### GPUサーバー起動失敗[m
[32m+[m
 - **確認**: `Test-NetConnection 127.0.0.1 -Port 8080`[m
 - **起動**: `scripts/Start-LocalAI-GPU.ps1`[m
 - **ログ**: `data/logs/current/`を確認[m
 [m
 ### インポートエラー[m
[32m+[m
 - **仮想環境**: `.venv\Scripts\activate`で有効化[m
 - **依存関係**: `pip install -r requirements.txt`[m
 - **PYTHONPATH**: 環境変数で設定済み[m
