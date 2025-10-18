# デプロイ運用手順（Canary/Lock/Rollback）

本ドキュメントはデプロイ運用の参照先です。実体スクリプトは `scripts/ops/deploy.ps1` に配置します。

## 暫定注記
- 以前の参照がリポジトリ直下 `deploy.ps1` を指している場合は、今後は `scripts/ops/deploy.ps1` を利用してください（本ドキュメントが参照差異を明記）。

## Canary 上書き
- 既定設定：`config/staging.json`
- 上書き可能な環境変数：
  - `HEALTHCHECK_URL`
  - `RETRY_SEC`
  - `MAX_WAIT_SEC`
  - `SUCCESS_REQUIRED`

### 既定エンドポイント
- Windows（Waitress/NSSM）運用の既定 Base URL は `http://127.0.0.1:5001`
- `HEALTHCHECK_URL` を未指定の場合はこの既定を採用する運用ルールとします（CI/運用ドキュメントに準拠）。

## 使用例
```powershell
pwsh scripts/ops/deploy.ps1 -Env staging
```

## Rollback 連携
- 失敗時は `scripts/ops/rollback_release.ps1 -CheckOnly` で事前検証し、問題なければ実行。