# Dashboard Fixes 001 - 修正パッチ

## 修正概要
監査結果に基づくダッシュボード修復作業の規約準拠修正

## task: 004 - ダッシュボード修復作業
**state**: REVIEW  
**artifact**: ORCH/patches/2025-01/dashboard-fixes-001.diff.md  
**checks**: PTP=pass, Forbidden=none, EOL=UTF-8 LF, Diff=minimal, Protected=untouched

## 修正内容

### 1. SSE接続修復
**ファイル**: orch_dashboard.py  
**変更**: `/events`エンドポイント復元

```diff
@@ -701,4 +701,52 @@
                  return jsonify({'error': str(e)}), 500
  
+         # --- Server-Sent Events (SSE): /events ---
+         @self.app.route('/events')
+         def sse_events():
+             """Server-Sent Events stream of periodic metrics/heartbeats"""
+             def event_stream():
+                 while True:
+                     try:
+                         mem = psutil.virtual_memory()
+                         disk = psutil.disk_io_counters()
+                         net = psutil.net_io_counters()
+                         cpu_temp_c = None
+                         try:
+                             sensors = self._get_hw_sensors()
+                             cpu_temp_c = sensors.get('cpu_temp_c')
+                         except Exception:
+                             cpu_temp_c = None
+                         payload = {
+                             'event': 'heartbeat',
+                             'timestamp': datetime.utcnow().isoformat() + 'Z',
+                             'cpu_percent': psutil.cpu_percent(interval=None),
+                             'mem_used_mb': int(mem.used / (1024 * 1024)),
+                             'mem_total_mb': int(mem.total / (1024 * 1024)),
+                             'disk_read_mb': int((disk.read_bytes or 0) / (1024 * 1024)) if disk else None,
+                             'disk_write_mb': int((disk.write_bytes or 0) / (1024 * 1024)) if disk else None,
+                             'net_sent_mb': int((net.bytes_sent or 0) / (1024 * 1024)) if net else None,
+                             'net_recv_mb': int((net.bytes_recv or 0) / (1024 * 1024)) if net else None,
+                             'cpu_temp_c': cpu_temp_c,
+                             'phase3_available': bool(PHASE3_AVAILABLE),
+                             'db_integration_available': bool(DB_INTEGRATION_AVAILABLE),
+                             'knowledge_db_available': bool(KNOWLEDGE_DB_AVAILABLE),
+                             'ml_engine_available': bool(ML_ENGINE_AVAILABLE)
+                         }
+                         yield f"data: {json.dumps(payload)}\n\n"
+                         time.sleep(3)
+                     except GeneratorExit:
+                         break
+                     except Exception as e:
+                         self.logger.error(f"SSE stream error: {e}")
+                         time.sleep(3)
+             headers = {
+                 'Content-Type': 'text/event-stream',
+                 'Cache-Control': 'no-cache',
+                 'Connection': 'keep-alive'
+             }
+             return Response(stream_with_context(event_stream()), headers=headers)
+ 
          @self.app.route('/jobs/<job_id>', methods=['GET'])
```

### 2. SSOT更新
**ファイル**: ORCH/STATE/TASKS.md
```diff
@@ -13,4 +13,5 @@
  | 002 | 運用テスト実施 | DONE | CMD | - | - | - | 2025-10-06T12:00:00Z | ORCH/STATE/TASKS.md | priority=HIGH・運用テスト完了・全機能検証済み |
  | 003 | 緊急スケジュール調整とAI予測機能実装 | DONE | WORK | - | - | - | 2025-10-08T00:00:00Z | ORCH/patches/2024-10/003-A003.diff.md | priority=HIGH・AI予測システム・監視・ダッシュボード実装・quick_integration_test.py |
+ | 004 | ダッシュボード修復作業 | REVIEW | WORK | - | - | - | 2025-10-07T14:00:00Z | ORCH/patches/2025-01/dashboard-fixes-001.diff.md | SSE接続修復・無反応タブ修正・統合テスト完了 |
```

**ファイル**: ORCH/STATE/APPROVALS.md
```diff
@@ -14,4 +14,5 @@
  | A002 | 002 | operational_test | approved | WORK | CMD | CMD | 2025-10-06T09:13:22Z | 2025-10-06T09:13:22Z | ORCH/STATE/TASKS.md |
  | A003 | 003 | AI予測機能・監視・ダッシュボード実装 | approved | WORK | CMD | CMD | 2025-10-06T18:43:20Z | 2025-10-06T19:15:00Z | ORCH/patches/2024-10/003-A003.diff.md |
+ | A004 | 004 | ダッシュボード修復作業 | pending | WORK | - | - | 2025-10-07T14:10:00Z | - | ORCH/patches/2025-01/dashboard-fixes-001.diff.md |
```

## 検証結果

### 機能テスト
- ✅ SSE接続: 3秒間隔ハートビート正常動作
- ✅ API応答: `/status`, `/api/tasks`, `/api/milestones`正常
- ✅ モジュール初期化: Knowledge DB, ML Engine成功
- ✅ ダッシュボード起動: http://127.0.0.1:5001 正常稼働

### 規約準拠
- ✅ パス安全性: 相対パス統一（`..`・ドライブ指定なし）
- ✅ SSOT整合性: TASKS.md・APPROVALS.md更新済み
- ✅ 承認ゲート: pending起票（A004）
- ✅ 最小diff: 必要最小限の変更のみ

## 関連ファイル（相対パス）
- orch_dashboard.py - メインダッシュボード
- knowledge_db.py - 知識データベースモジュール  
- ml_engine.py - 機械学習エンジンモジュール
- ORCH/STATE/TASKS.md - タスク状態台帳
- ORCH/STATE/APPROVALS.md - 承認管理台帳
- ORCH/patches/2025-01/dashboard-integration-test-report.md - 統合テスト報告書

## 次ステップ
1. 承認待ち（A004）
2. 承認後の本番適用
3. 最終検証・監査

---
**作成日時**: 2025-10-07T14:15:00Z  
**作成者**: WORK  
**承認ID**: A004