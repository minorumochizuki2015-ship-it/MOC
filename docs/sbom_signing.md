# SBOM 署名/検証 設計と段階導入計画

本ドキュメントは、ORCH-Next における SBOM (Software Bill of Materials) の署名・検証を段階的に導入する計画を示します。目標は、供給チェーンの透明性と改ざん耐性を高めることです。初期段階では PoC を実装し、その後 in‑toto / SLSA provenance による本格的な保証へ拡張します。

## ゴール
- SBOM を CI で自動生成・署名・検証
- 署名検証失敗時に CI を FAIL とする
- 将来的に in‑toto レイアウト/SLSA provenance を追加し、完全なサプライチェーン可観測性へ拡張

## 段階導入

### Stage 0: ベースライン
- CycloneDX 形式の SBOM を生成（既存 CI の `cyclonedx-bom` ステップ）
- SBOM をアーティファクトとして保存

### Stage 1: PoC 署名/検証（ローカル RSA）
- 署名: `scripts/sbom/sign_sbom.py`
  - `observability/sbom/sbom.json` を RSA-PSS(SHA256) で署名
  - 鍵は CI 実行時に一時生成（`observability/sbom/keys/` に `private.pem` / `public.pem` を保存）
- 検証: `scripts/sbom/verify_sbom.py`
  - 署名ファイル `observability/sbom/sbom.sig` を検証
  - 成功/失敗で戻り値を使い CI を pass/fail

### Stage 2: in‑toto への拡張
- in‑toto layout に基づくステップ定義（ビルド・テスト・SBOM生成）
- 各ステップのメタデータと署名を記録し、layout 検証を CI へ組み込み
- 署名鍵の管理（KMS/Keyless Sigstore の選定）

### Stage 3: SLSA provenance の導入
- ビルドプロバイダを信頼できる署名主体として設定
- provenance（ビルド環境・ソース・依存）とアーティファクトの対応関係を attest
- デプロイ前ゲートで provenance 検証

## 実装詳細（Stage 1 PoC）

### 依存関係
- `cryptography`（RSA キー生成/署名/検証）

### ファイル構成
- `observability/sbom/sbom.json`：CycloneDX 生成済み SBOM
- `observability/sbom/sbom.sig`：署名（Base64）
- `observability/sbom/keys/public.pem`：公開鍵
- `observability/sbom/keys/private.pem`：秘密鍵（CI 内で一時生成）

### 実行手順（ローカル/CI 共通）
```bash
# 1) SBOM 生成（CIでは既存ステップで生成済み）
cyclonedx-bom -o observability/sbom/sbom.json

# 2) 署名
python scripts/sbom/sign_sbom.py --sbom observability/sbom/sbom.json --out observability/sbom/sbom.sig --keys-dir observability/sbom/keys

# 3) 検証（CIでは検証失敗でジョブをfail）
python scripts/sbom/verify_sbom.py --sbom observability/sbom/sbom.json --sig observability/sbom/sbom.sig --keys-dir observability/sbom/keys
```

## 運用・鍵管理方針（暫定）
- PoC 段階では CI 内で鍵を都度生成（短命鍵）
- Stage 2 以降は KMS/Keyless に移行し、鍵を環境へ持ち込まない設計にする

## リスクと緩和策
- 署名方式の暫定性：将来 in‑toto/Sigstore に移行する前提を明記し、PoC を限定運用
- 依存追加の影響：`cryptography` を requirements に追加し、CI で確実にインストール

## 更新履歴
- 2025-10-10: 初版（Stage 1 PoC の設計/手順を記載）