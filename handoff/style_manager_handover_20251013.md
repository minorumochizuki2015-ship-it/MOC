# スタイル管理システム 引継ぎ書（2025-10-13）

ーーーーーー 
結論：下記を別セッションに丸ごと貼り付け→あなたの追記で即引継ぎ完了。 
【引継ぎプロンプト｜無損失ハンドオーバー】 

目的：この会話の“現在の作業状態”を完全継承し、同一ルールで継続実行せよ。 
優先度：安全>正確>再現性>速度>簡潔。私への質問は不明箇所のみ最小回数。 

▼固定運用ルール 
- 実行系：.\.venv\Scripts\python.exe（pipは `python -m pip`） 
- 整形：Black+isort。EOL/encoding= UTF-8 LF（*.batのみCRLF） 
- 型：mypy strict（主に src/**） 
- pre-commit：Black/isort 実行 
- ログ：data/logs/current/ 
- 保護：start_modern_ui.bat / main_modern.py は Plan→承認→Patch＋原子的書込＋直後検証（失敗即ロールバック） 
- 秘密保持：OPENAI_COMPAT_BASE / API_KEY のみ使用。秘密は出力・ログへ書かない。 
- 変更出力：最小 unified diff。全置換禁止。 

▼あなたの初回応答タスク（必須） 
1) STATE_JSON を受領→整合チェック（必須キー存在/日付/パス）→不明=「不明」と明示 
2) Status Board を生成：要約／直近ブロッカー／次の一手（3件以内） 
3) チェックリスト：未完了タスクを Markdown チェックボックスで列挙（優先度順） 
4) マイルストーン表：日付・達成基準・責任者・依存関係 
5) ディレクトリ構造の要点表示（深さ2〜3、絶対パス起点） 
6) 保護ファイルの変更ガード宣言（Plan→Test→Patch手順の雛形提示） 

▼受領データ：以下の JSON を読み込んで状態を再現せよ（値はそのまま採用） 
STATE_JSON:
```json
{
  "project_name": "ORION UI Style Manager",
  "timestamp_utc": "2025-10-13T08:45:00Z",
  "timezone": "Asia/Tokyo",
  "env": {
    "os": "Windows",
    "python_venv": ".\\.venv\\Scripts\\python.exe",
    "formatters": ["black", "isort"],
    "type_check": "mypy(strict, target=src/**)",
    "log_dir": "data/logs/current/",
    "secrets_policy": "OPENAI_COMPAT_BASE and API_KEY only; never print or log"
  },
  "paths": {
    "root_abs": "C:\\Users\\User\\Trae\\ORCH-Next",
    "related_paths": ["src/", "tests/", "scripts/", "data/", "data/logs/current/", ".cursor/", ".git/"],
    "protected_files": ["start_modern_ui.bat", "main_modern.py"]
  },
  "directory_tree_note": "下の DIR_TREE を信頼（最新）",
  "repositories": [{"name": "", "remote": "", "branch": ""}],
  "current_work": [
    {"title": "UI健全性維持（ヘルスと到達性）", "goal": "/healthzと主要ページの安定稼働の継続検証", "inputs": [], "outputs_expected": ["UI到達性200維持", "Healthz 200/JSON"], "status": "in_progress", "owner": "me"}
  ],
  "past_work_summary": [
    {"when": "2025-10-13", "what": "重複起動の解消と /healthz 実装", "result": "UI到達性復旧", "evidence": ["src/dashboard.py", "docs/README_PORTS.md", "tests/e2e/"]}
  ],
  "next_work": [
    {"title": "Playwright UI E2Eの導入", "definition_of_done": "iframe要素選択・スタイル適用・保存永続化がCIで緑", "estimate_h": 6}
  ],
  "tasks": {
    "todo": [
      {"id": "T-001", "title": "Playwright UI E2E（要素選択/スタイル適用/保存）", "priority": "P1", "due": "2025-10-15", "blocked_by": []},
      {"id": "T-002", "title": "CSS/JSを静的アセットへ分離とバージョニング", "priority": "P2", "due": "2025-10-18", "blocked_by": []},
      {"id": "T-003", "title": "TASKS.mdへ今回のマイルストーンを追記", "priority": "P3", "due": "2025-10-15", "blocked_by": []}
    ],
    "done": [
      {"id": "T-000", "title": "UIサーバ統一と/healthz導入", "completed_at": "2025-10-13", "artifact": ["src/dashboard.py", "docs/checklists/ui_server_runbook.md"]}
    ],
    "blocked": []
  },
  "deliverables": [
    {"name": "Health/Reachability Tests", "path": "tests/e2e/", "hash_or_version": "n/a", "short_desc": "/healthzと主要ページの200検証"}
  ],
  "tests": [
    {"name": "pytest", "cmd": ".\\.venv\\Scripts\\python.exe -m pytest -q", "last_result": "pass"}
  ],
  "milestones": [
    {"name": "M1", "due": "2025-10-20", "acceptance": "Playwright E2EがCIで安定緑", "owner": "me", "depends_on": ["T-001"]}
  ],
  "communications": [
    {"channel": "docs", "link_or_path": "docs/README_PORTS.md", "note": "ポート運用ルール"}
  ],
  "risks": [
    {"risk": "UI回帰（ブラウザ層）", "impact": "M", "mitigation": "Playwright E2E導入とスクショ比較"}
  ],
  "pending_decisions": [
    {"topic": "E2Eフレームワークの詳細設定", "options": ["Playwright", "Selenium"], "preferred": "Playwright", "deadline": "2025-10-15"}
  ]
}
```

DIR_TREE (最新のディレクトリ構造。先頭は絶対パス): 
```
C:\Users\User\Trae\ORCH-Next
├─ src
│  ├─ dashboard.py
│  ├─ style_manager.py
│  └─ ...
├─ tests
│  ├─ e2e
│  └─ ...
├─ scripts
│  └─ ops
│     ├─ start_ui_server.ps1
│     ├─ check_port.py
│     └─ write_port_snapshot.ps1
├─ data
│  └─ logs
│     └─ current
├─ docs
│  ├─ README_PORTS.md
│  └─ checklists
│     └─ ui_server_runbook.md
└─ .venv
```

▼出力フォーマット（あなたの返答はこの順）に基づく初期情報（参考）

1) 【Status Board】
- UIは /dashboard・/style-manager・/tasks に到達200、/healthz 200。重複起動問題は解消済。
- 直近ブロッカー：ブラウザ層の操作E2E未整備。
- 次の一手：Playwright導入／CSS/JS分離／TASKS.md更新。

2) 【チェックリスト】
- [ ] T-001: Playwright UI E2E（P1, 期限: 2025-10-15）
- [ ] T-002: CSS/JS静的アセット化（P2, 期限: 2025-10-18）
- [ ] T-003: TASKS.mdへ反映（P3, 期限: 2025-10-15）

3) 【マイルストーン】
| 期日 | マイルストーン | 達成基準 | 責任 | 依存 |
|---|---|---|---|---|
| 2025-10-20 | M1 | Playwright E2Eがレビュー/CI合格 | me | T-001 |

4) 【ディレクトリ要点】
- ルート: C:\\Users\\User\\Trae\\ORCH-Next
- src: dashboard.py（/healthz 実装）、style_manager.py（UIロジック）
- tests/e2e: healthz・到達性テストが存在
- scripts/ops: 起動ガード・ポートチェック・スナップショット
- docs: ポート運用READMEとランブック

5) 【次の一手】
- .\\.venv\\Scripts\\python.exe -m pip install playwright && .\\.venv\\Scripts\\python.exe -m playwright install
- .\\.venv\\Scripts\\python.exe -m pytest -q
- pwsh scripts/ops/start_ui_server.ps1 -Port 5000

6) 【保護ファイル変更手順テンプレ】
- Plan(JSON) → Test → 最小diff(PATCH) → 原子的書込 → 直後検証 → ロールバック条件

---

付記：UIの到達URL
- http://localhost:5000/dashboard
- http://localhost:5000/style-manager
- http://localhost:5000/tasks
- http://localhost:5000/healthz

---

## 今回の作業ミスの記録と RCA（2025-10-13）

【症状】
- `/style-manager` が 404 を返す、または簡易版 UI（暫定テンプレート）が表示される。

【一次原因】
- `src/dashboard.py` 内に暫定のスタイル管理ルート（簡易 HTML）が重複定義され、正式な `create_style_api(app)` のテンプレートを上書きしていた。

【二次原因】
- Flask 起動時に `FLASK_APP` を未指定で起動したため、目的のアプリではないプロジェクトエントリが起動し、`/style-manager` ルートが未登録のサーバが動作した。

【第三原因】
- `StyleManager` を直接インスタンス化しようとする暫定コードが存在し、責務分離（API/テンプレート生成は `style_manager.py` に集約）の方針と不一致だった。

【影響】
- UI到達不可、スタイル適用・リセット不可、検証工数の増大。

【根拠】
- コード差分：`src/dashboard.py` から暫定UIルートを削除し、`style_manager = create_style_api(app)` に統一。
- ログ：`GET /style-manager` が 404 を返す記録、`FLASK_APP=src.dashboard` 指定後は 200 に復旧。
- 構成：`src/style_manager.py` に `/style-manager` と `/api/styles` 系の正式ルートとテンプレートが定義済み。

【是正措置】
- `src/dashboard.py` から暫定 UI ルートと重複 API を削除。
- ルート登録は `style_manager = create_style_api(app)` のみを使用。
- 起動を標準化：`$env:FLASK_APP="src.dashboard"; python -m flask run --port 5000`。

【再発防止策】
- ルート定義の単一責務：Style Manager は `src/style_manager.py` のみに集約。`src/dashboard.py` では追加独自ページ（例：`/metrics`）のみを定義。
- 起動ガード：`scripts/ops/start_ui_server.ps1` で `FLASK_APP=src.dashboard` を強制設定する（要運用ルール追記）。
- スモークテスト：`/style-manager` と `/api/styles` の 200/JSON を `tests/e2e` に追加（CIで毎回検証）。
- 変更プロセス順守：Runbook に従い Plan → Test → Patch → 原子的書込 → 直後検証 → ロールバック条件の明示。

【検証手順（Windows／PowerShell）】
1) サーバ起動：
   - ``$env:FLASK_APP="src.dashboard"; python -m flask run --port 5000``
2) 到達性確認：
   - ``Invoke-WebRequest http://localhost:5000/style-manager``（`StatusCode=200`）
   - ``Invoke-WebRequest http://localhost:5000/api/styles``（スタイル JSON が返る）
3) 動的CSSの生成確認：
   - スタイル適用の POST 後、``static/css/dynamic_overrides.css`` が更新されること（`src/style_manager.py` の `generate_css`）。

【関連ファイル】
- ``src/dashboard.py``（Style Manager 統合呼び出し）
- ``src/style_manager.py``（API/テンプレート/動的CSS生成）
- ``static/css/dynamic_overrides.css``（自動生成ファイル）
- ``static/css/dynamic_styles.json``（現在のスタイル値の保存）