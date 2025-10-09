# Agents Registry Schema

目的
- `data/agents_registry.json` のデータ構造を明文化し、監査・移行・ツール連携を容易にする。

ファイル
- スキーマ: `data/schema/agents_registry.schema.json`
- シード例: `data/agents_registry_seed.json`（既存レジストリとは別ファイル。初期導入時の参考）

形式
- レジストリは次のいずれかの形式を許容:
  1) JSON配列（各要素が Agent）
  2) オブジェクト `{ agents: Agent[] }`

Agent（抜粋）
- `id` (string, 必須)
- `name` (string, 任意)
- `status` ("online"|"offline"|"unknown")
- `last_seen` (ISO8601 date-time)
- `metadata` (object)
- `reports` (Report[])

Report（抜粋）
- `timestamp` (ISO8601 date-time, 必須)
- `status` (string, 必須)
- `message` (string, 任意)
- `artifacts` (string[])

運用メモ
- 既存の `data/agents_registry.json` は上記のいずれかに準拠すればOK。互換維持のためスキーマは両形式を許容。
- 認証鍵は `config/secrets.json`（Git管理外）に配置。雛形は `config/secrets.example.json` を参照。
- API設定は `config/agents_api.json` を参照（認証種別、CORS、レートリミット、ロギング、レジストリパス）。

今後の強化
- スキーマ検証ツール（scripts/ops/validate_agents_registry.py）の追加とCI統合。
- マイグレーション手順（旧形式→新形式）と後方互換の維持。