# 自動パイロット作業指示（Agentsメトリクス整合）

更新: 2025-10-08
対象: ORCH-Next メイン作業コンソール

## 目的
Agents API の集計結果（count）と Prometheus メトリクス `orch_agents_total` の整合を確保する。

## 指示（順序）
1. 登録済みエージェントへ heartbeat を送信してメトリクス更新を促進。
   - POST /api/agents/heartbeat
   - Body: `{ "id": "<agent-id>", "status": "active" }`
2. メトリクス更新ロジックの確認：
   - `orch_agents_total` が `_load_agents()` の結果長（登録数）に連動して更新されるか。
   - 更新タイミング：レジストリ更新（register/update/report）および heartbeat 受信時。
3. 不整合が継続する場合の修正案：
   - `/metrics` 生成処理にて `_load_agents()` を参照し、`orch_agents_total` を直接算出。
   - ステータス別メトリクス `orch_agents_status{status="..."}` もレジストリから集計。
4. 反映後の検証：
   - `/api/agents/list` の `count` と `/metrics` の `orch_agents_total` が一致すること。

## 注意事項
- 本セッションは監視専用。ファイルロックや長時間の占有は行いません。
- 重大なエラー検知時のみ、最小限の通知で報告します。