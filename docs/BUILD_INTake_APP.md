# Cursor向け実装指示書：ローカル統治核AI用「学習インテーク・アプリ」

## 0) 目的

* 会話/作業の成果を **JSON/テキストで投入 → フィルタ/正規化 → ドメイン別バケットへ追記 → SFT→LoRA→評価** に自動連結。
* すべてローカル。外部API・外部通信は禁止。

## 1) 非機能・制約（project\_rules.md 準拠）

* EOL=LF、整形=Black+isort、型=MyPy strict。
* 1差分=1ファイル（最小unified diff）。
* 生成物は `data/` 配下。秘匿情報の出力禁止。
* 実行は `.\.venv\Scripts\python.exe` 固定。
* 外部鍵/リモートエンドポイント検出時は**即Fail**（既存 quick\_diagnose を流用）。

## 2) 作るもの（最小セット）

```
app/
  intake_service/
    __init__.py
    api.py              # FastAPI ローカルAPI (127.0.0.1:8787)
    schema.py           # 入力スキーマ/バリデーション
    classifier.py       # domain推定の簡易規則
tools/
  intake_filter.py      # inbox→queue/accepted/rejected、重複/機微除去
  intake_admin.py       # list/approve/reject/edit/delete（CLI）
data/
  intake/
    inbox/ queue/ accepted/ rejected/
    buckets/ code/ write/ patent/
```

## 3) 標準スキーマ（最小）

```json
{
  "id": "uuid",
  "ts": "2025-09-21T04:55:00+09:00",
  "source": "trae|cursor|manual",
  "title": "短い要約",
  "domain": "code|write|patent|unknown",
  "task_type": "edit|search|fix|draft|refactor|spec",
  "success": true,
  "prompt": "...",
  "output": "...",
  "rationale_success": "何が効いたか",
  "rationale_failure": null,
  "math_or_rules": "使った式/根拠/規約",
  "refs": ["path/or/url"],
  "privacy": "no_pii|pii_redacted",
  "tags": ["mini-eval-case-?"]
}
```

* **SFT変換**（JSONL）：`{"instruction": <prompt>, "input": "", "output": <output>, "meta": {...}}`

## 4) ローカルAPI（FastAPI）仕様

* POST `/intake/post` : JSON投入。OKなら `data/intake/inbox/` に `YYYYMMDD_HHMMSS_<uuid>.json`
* POST `/intake/post_text` : テキストを受け取り、最小スキーマに自動梱包
* GET  `/intake/items` : inbox/queue/accepted の一覧（軽量メタのみ）
* POST `/intake/approve` : id 指定で queue→accepted
* POST `/intake/reject`  : id 指定で queue→rejected
* POST `/intake/edit`    : id 指定で JSON差し替え（title/domain等の修正）

## 5) 既存パイプラインとの接続

* **`tools/intake_filter.py`** を `gc-data-loop` の冒頭で呼ぶ：

  * 必須キー検査、サイズ/機微検査、`sha1(prompt+output)` 重複除去
  * `domain` 未設定は `classifier.py` の簡易規則で補完
  * OK→ `accepted/` & `buckets/<domain>/YYYYMMDD.jsonl` 追記、NG→ `rejected/`
  * 台帳追記：`data/intake/index.jsonl`
* 以降は既存の `export_sft_dataset.py → train_local.py → mini_eval → model-swap.ps1` がそのまま動作。

---

# マイルストーン（最短経路・受入条件つき）

## M0：骨格 & ローカルAPI起動（\~1差分×2〜3）

**実装**

* `app/intake_service/{api.py,schema.py,classifier.py}` 作成（FastAPI, uvicorn）
* `.githooks/pre-push` に **静的ガード**：外部SDK/鍵の検出を維持

**受入**

* `uvicorn app.intake_service.api:app --host 127.0.0.1 --port 8787` が起動
* `POST /intake/post` で `data/intake/inbox/*.json` 作成
* quick\_diagnose が緑（外部API鍵なし）

## M1：フィルタ & バケット化（\~1差分×2）

**実装**

* `tools/intake_filter.py`：inbox→queue/accepted/rejected、重複/機微除去、バケット追記
* `gc-data-loop` の先頭で `intake_filter.py` を呼ぶ1行追記（**既定: Dry-Run→後続継続**）

**受入**

* inboxへ2件投入→`accepted/` と `rejected/` に分岐
* `buckets/<domain>/YYYYMMDD.jsonl` へ追記される
* `data/intake/index.jsonl` に台帳が増える

## M2：レビューCLI（編集/削除/承認）（\~1差分）

**実装**

* `tools/intake_admin.py`：`list|approve|reject|edit|delete --id ...`

**受入**

* queue のアイテムを approve→accepted へ移動
* `edit` で title/domain 修正が反映

## M3：SFT出力の自動化（ドメイン別）（\~1差分）

**実装**

* 既存 `export_sft_dataset.py` を **入力に buckets/** を指定できるよう軽微拡張（必要なら）

**受入**

* `data/sft/{code,write,patent}/{train,val}.jsonl` が生成
* `stats.json` に件数/dup\_ratioを出力

## M4：学習→評価→採否の自動ゲート（\~1差分）

**実装**

* `tools/train_local.py --domain <d>` から終了時に `mini_eval --suite <d>` を自動実行
* 合格なら `scripts/model-swap.ps1` 呼び出し、**即回帰→不合格は自動リバート**

**受入**

* ダミーLoRAでフロー通過（評価が緑→採用、赤→ロールバック）
* 履歴：`data/logs/current/mini_eval_history.jsonl` に追記

---

# 受入テスト（60秒サニティ）

1. API起動 → `POST /intake/post` を2件
2. `tools/intake_filter.py` 手動実行 → accepted/rejected/buckets を確認
3. `export_sft_dataset.py` → sft/train,val が増える
4. `mini_eval.py --mode tools --timeout 15` → スコア満点
5. `quick_diagnose.py` → 外部鍵なし、BASE=127.0.0.1

---

# 実装メモ（Cursor向け）

* 依存：`fastapi`, `uvicorn`, `pydantic`, `python-multipart`（必要時）
* 全HTTPは `127.0.0.1` 限定。**CORS無効**、**外部送信禁止**。
* `classifier.py` は簡易規則（拡張子・語彙）でOK。誤判定はM2のCLIで上書き可能。
* 例外/警告は **ログへ**、終了コードで親に返す。
* すべての新規ファイルは **1ファイル=1差分** でコミット。

---

# 付録：サンプルPOST（Trae/他エディタから）

```bash
curl -s -X POST http://127.0.0.1:8787/intake/post -H "Content-Type: application/json" -d '{
  "id":"123e4567-e89b-12d3-a456-426614174000",
  "ts":"2025-09-21T12:00:00+09:00",
  "source":"trae",
  "title":"関数分解の成功",
  "domain":"code",
  "task_type":"refactor",
  "success":true,
  "prompt":"関数を小さく分解して責務を分離したい",
  "output":"xxx.py を A/B/C に分割...",
  "rationale_success":"凝集度↑と結合度↓",
  "math_or_rules":"SRP, cyclomatic complexity",
  "refs":["src/xxx.py"],
  "privacy":"no_pii",
  "tags":["mini-eval-case-7"]
}'
```

