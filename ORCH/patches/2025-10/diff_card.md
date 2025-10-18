---
task_id: ui-audit-p0
sha_in: 2eab2049ba280245406220fdfa9e2eb25039fc00
sha_out: 318f06f15feed26c9fea8951b574d74365a13302
metrics:
  lighthouse: pending_CI
  lcp: pending_CI
  cls: pending_CI
  linkinator_404: pending_CI
  playwright_tests: pending_CI
rollback_cmd: "git revert 318f06f15feed26c9fea8951b574d74365a13302"
---

Accountability Card (Root Cause & Rollback)

- Branch: feature/ui-audit-p0
- Timestamp: 2025-10-13T21:45:41.686216

Minimal Diff Summary
--------------------
47 files changed, 4301 insertions(+), 3688 deletions(-)

Unified Diff
------------
```
diff --git a/app/__init__.py b/app/__init__.py
index b4ac3b0..0309ef4 100644
--- a/app/__init__.py
+++ b/app/__init__.py
@@ -4,11 +4,11 @@ Application factory for ORCH-Next
 - URL Map dump on startup for audit/observability
 """
 
-import os
 import logging
+import os
 from typing import List
-from flask import Flask
 
+from flask import Flask
 
 logger = logging.getLogger(__name__)
 
@@ -31,9 +31,7 @@ def _verify_assets(app: Flask) -> None:
     if missing_templates:
         for mt in missing_templates:
             logger.error(f"Missing template detected (fail-fast): {mt}")
-        raise RuntimeError(
-            "Required templates are missing. See logs for details."
-        )
+        raise RuntimeError("Required templates are missing. See logs for details.")
 
     # Static directory is optional in this repository, but if present ensure it is readable
     if os.path.exists(static_dir) and not os.path.isdir(static_dir):
@@ -54,11 +52,13 @@ def _dump_url_map(app: Flask) -> None:
     try:
         rules = []
         for rule in app.url_map.iter_rules():
-            rules.append({
-                "endpoint": rule.endpoint,
-                "methods": sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}]),
-                "rule": str(rule),
-            })
+            rules.append(
+                {
+                    "endpoint": rule.endpoint,
+                    "methods": sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}]),
+                    "rule": str(rule),
+                }
+            )
         logger.info({"event": "url_map_dump", "rules": rules})
     except Exception as e:
         logger.warning({"event": "url_map_dump_failed", "error": str(e)})
@@ -80,9 +80,9 @@ def create_app() -> Flask:
 
     # Register blueprints if available
     try:
-        from src.blueprints.ui_routes import ui_bp
         from src.blueprints.api_routes import api_bp
         from src.blueprints.sse_routes import sse_bp
+        from src.blueprints.ui_routes import ui_bp
 
         app.register_blueprint(ui_bp)
         app.register_blueprint(api_bp, url_prefix="/api")
@@ -99,4 +99,4 @@ def create_app() -> Flask:
     # Log URL map for audit
     _dump_url_map(app)
 
-    return app
\ No newline at end of file
+    return app
diff --git a/backups/dashboard_legacy/orch_dashboard_advanced_20251012_123718.py b/backups/dashboard_legacy/orch_dashboard_advanced_20251012_123718.py
index 1c2c7ac..f7e56a5 100644
--- a/backups/dashboard_legacy/orch_dashboard_advanced_20251012_123718.py
+++ b/backups/dashboard_legacy/orch_dashboard_advanced_20251012_123718.py
@@ -30,12 +30,10 @@ from flask import (
     stream_with_context,
     url_for,
 )
-from flask_cors import CORS
-from flask_socketio import SocketIO, emit
 from flask_caching import Cache
 from flask_compress import Compress
-
-
+from flask_cors import CORS
+from flask_socketio import SocketIO, emit
 
 # Ensure log handlers are cleanly closed on process exit to avoid ResourceWarning
 atexit.register(logging.shutdown)
@@ -56,6 +54,7 @@ sys.path.append(str(Path(__file__).parent.parent.parent / "src"))
 # 自動再訓練スケジューラーのインポート
 try:
     from src.auto_retrain_scheduler import AutoRetrainScheduler
+
     AUTO_RETRAIN_AVAILABLE = True
 except ImportError:
     AUTO_RETRAIN_AVAILABLE = False
@@ -223,6 +222,7 @@ class OrchDashboard:
         self.monitoring_system = None
         try:
             from src.monitoring_system import MonitoringSystem
+
             self.monitoring_system = MonitoringSystem()
             self.logger.info("Monitoring system initialized")
         except Exception as e:
@@ -232,6 +232,7 @@ class OrchDashboard:
         self.security_manager = None
         try:
             from src.security_manager import SecurityManager
+
             self.security_manager = SecurityManager()
             self.logger.info("Security manager initialized")
         except Exception as e:
@@ -763,17 +764,22 @@ class OrchDashboard:
                         "dashboard": "running",
                         "monitoring": "active" if self.monitoring_system else "inactive",
                         "security": "active" if self.security_manager else "inactive",
-                        "ml_engine": "active" if self.ml_engine else "inactive"
+                        "ml_engine": "active" if self.ml_engine else "inactive",
                     },
                     "system": {
                         "cpu_percent": psutil.cpu_percent(interval=0.1),
                         "memory_percent": psutil.virtual_memory().percent,
-                        "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
-                    }
+                        "disk_percent": (
+                            psutil.disk_usage("/").percent
+                            if os.name != "nt"
+                            else psutil.disk_usage("C:").percent
+                        ),
+                    },
                 }
                 return jsonify(status), 200
             except Exception as e:
                 return jsonify({"status": "error", "message": str(e)}), 500
+
         @self.app.route("/status")
         def status():
             try:
@@ -2239,7 +2245,7 @@ class OrchDashboard:
             """自動再訓練スケジューラーの状態取得"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 status = self.auto_retrain_scheduler.get_status()
                 return jsonify(status)
@@ -2252,11 +2258,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー開始"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.start())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを開始しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを開始しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練開始エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2266,11 +2275,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー停止"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.stop())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを停止しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを停止しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練停止エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2280,15 +2292,15 @@ class OrchDashboard:
             """手動再訓練実行"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
-                
+
                 async def run_manual_retrain():
                     results = await self.auto_retrain_scheduler.retrain_models()
                     self.auto_retrain_scheduler.save_retrain_log(results)
                     return results
-                
+
                 # 非同期実行
                 asyncio.create_task(run_manual_retrain())
                 return jsonify({"success": True, "message": "手動再訓練を開始しました"})
@@ -2301,13 +2313,15 @@ class OrchDashboard:
         def api_monitoring_performance():
             """パフォーマンス監視データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     performance_data = self.monitoring_system.get_performance_summary()
-                    return jsonify({
-                        "success": True,
-                        "data": performance_data,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": performance_data,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2318,13 +2332,15 @@ class OrchDashboard:
         def api_monitoring_alerts():
             """アラート統計データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     alert_stats = self.monitoring_system.get_alert_statistics()
-                    return jsonify({
-                        "success": True,
-                        "data": alert_stats,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": alert_stats,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2335,13 +2351,11 @@ class OrchDashboard:
         def api_monitoring_status():
             """監視システム全体ステータス取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     status = self.monitoring_system.get_system_status()
-                    return jsonify({
-                        "success": True,
-                        "data": status,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {"success": True, "data": status, "timestamp": datetime.now().isoformat()}
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2352,17 +2366,21 @@ class OrchDashboard:
         def api_monitoring_metrics_history():
             """メトリクス履歴データ取得"""
             try:
-                hours = request.args.get('hours', 24, type=int)
-                metric_type = request.args.get('type', 'all')
-                
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
-                    history_data = self.monitoring_system.get_metrics_history(hours=hours, metric_type=metric_type)
-                    return jsonify({
-                        "success": True,
-                        "data": history_data,
-                        "parameters": {"hours": hours, "type": metric_type},
-                        "timestamp": datetime.now().isoformat()
-                    })
+                hours = request.args.get("hours", 24, type=int)
+                metric_type = request.args.get("type", "all")
+
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
+                    history_data = self.monitoring_system.get_metrics_history(
+                        hours=hours, metric_type=metric_type
+                    )
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": history_data,
+                            "parameters": {"hours": hours, "type": metric_type},
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2407,21 +2425,21 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # 認証実行
                 token = self.security_manager.authenticate_user(username, password)
                 if token:
                     return jsonify({"success": True, "token": token})
                 else:
                     return jsonify({"error": "認証に失敗しました"}), 401
-                    
+
             except Exception as e:
                 self.logger.error(f"ログインエラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2432,22 +2450,22 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
                 role = data.get("role", "user")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # ユーザー登録
                 success = self.security_manager.register_user(username, password, role)
                 if success:
                     return jsonify({"success": True, "message": "ユーザーが正常に登録されました"})
                 else:
                     return jsonify({"error": "ユーザー登録に失敗しました"}), 400
-                    
+
             except Exception as e:
                 self.logger.error(f"ユーザー登録エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2458,10 +2476,10 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 logs = self.security_manager.get_audit_logs()
                 return jsonify({"logs": logs})
-                    
+
             except Exception as e:
                 self.logger.error(f"監査ログ取得エラー: {e}")
                 return jsonify({"error": str(e)}), 500
diff --git a/backups/dashboard_legacy/orch_dashboard_v1_20251012_123239.py b/backups/dashboard_legacy/orch_dashboard_v1_20251012_123239.py
index 09340c8..f4901a6 100644
--- a/backups/dashboard_legacy/orch_dashboard_v1_20251012_123239.py
+++ b/backups/dashboard_legacy/orch_dashboard_v1_20251012_123239.py
@@ -52,6 +52,7 @@ sys.path.append(str(Path(__file__).parent.parent.parent / "src"))
 # 自動再訓練スケジューラーのインポート
 try:
     from src.auto_retrain_scheduler import AutoRetrainScheduler
+
     AUTO_RETRAIN_AVAILABLE = True
 except ImportError:
     AUTO_RETRAIN_AVAILABLE = False
@@ -219,6 +220,7 @@ class OrchDashboard:
         self.monitoring_system = None
         try:
             from src.monitoring_system import MonitoringSystem
+
             self.monitoring_system = MonitoringSystem()
             self.logger.info("Monitoring system initialized")
         except Exception as e:
@@ -228,6 +230,7 @@ class OrchDashboard:
         self.security_manager = None
         try:
             from src.security_manager import SecurityManager
+
             self.security_manager = SecurityManager()
             self.logger.info("Security manager initialized")
         except Exception as e:
@@ -759,17 +762,22 @@ class OrchDashboard:
                         "dashboard": "running",
                         "monitoring": "active" if self.monitoring_system else "inactive",
                         "security": "active" if self.security_manager else "inactive",
-                        "ml_engine": "active" if self.ml_engine else "inactive"
+                        "ml_engine": "active" if self.ml_engine else "inactive",
                     },
                     "system": {
                         "cpu_percent": psutil.cpu_percent(interval=0.1),
                         "memory_percent": psutil.virtual_memory().percent,
-                        "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
-                    }
+                        "disk_percent": (
+                            psutil.disk_usage("/").percent
+                            if os.name != "nt"
+                            else psutil.disk_usage("C:").percent
+                        ),
+                    },
                 }
                 return jsonify(status), 200
             except Exception as e:
                 return jsonify({"status": "error", "message": str(e)}), 500
+
         @self.app.route("/status")
         def status():
             try:
@@ -2235,7 +2243,7 @@ class OrchDashboard:
             """自動再訓練スケジューラーの状態取得"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 status = self.auto_retrain_scheduler.get_status()
                 return jsonify(status)
@@ -2248,11 +2256,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー開始"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.start())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを開始しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを開始しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練開始エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2262,11 +2273,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー停止"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.stop())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを停止しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを停止しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練停止エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2276,15 +2290,15 @@ class OrchDashboard:
             """手動再訓練実行"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
-                
+
                 async def run_manual_retrain():
                     results = await self.auto_retrain_scheduler.retrain_models()
                     self.auto_retrain_scheduler.save_retrain_log(results)
                     return results
-                
+
                 # 非同期実行
                 asyncio.create_task(run_manual_retrain())
                 return jsonify({"success": True, "message": "手動再訓練を開始しました"})
@@ -2297,13 +2311,15 @@ class OrchDashboard:
         def api_monitoring_performance():
             """パフォーマンス監視データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     performance_data = self.monitoring_system.get_performance_summary()
-                    return jsonify({
-                        "success": True,
-                        "data": performance_data,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": performance_data,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2314,13 +2330,15 @@ class OrchDashboard:
         def api_monitoring_alerts():
             """アラート統計データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     alert_stats = self.monitoring_system.get_alert_statistics()
-                    return jsonify({
-                        "success": True,
-                        "data": alert_stats,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": alert_stats,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2331,13 +2349,11 @@ class OrchDashboard:
         def api_monitoring_status():
             """監視システム全体ステータス取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     status = self.monitoring_system.get_system_status()
-                    return jsonify({
-                        "success": True,
-                        "data": status,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {"success": True, "data": status, "timestamp": datetime.now().isoformat()}
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2348,17 +2364,21 @@ class OrchDashboard:
         def api_monitoring_metrics_history():
             """メトリクス履歴データ取得"""
             try:
-                hours = request.args.get('hours', 24, type=int)
-                metric_type = request.args.get('type', 'all')
-                
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
-                    history_data = self.monitoring_system.get_metrics_history(hours=hours, metric_type=metric_type)
-                    return jsonify({
-                        "success": True,
-                        "data": history_data,
-                        "parameters": {"hours": hours, "type": metric_type},
-                        "timestamp": datetime.now().isoformat()
-                    })
+                hours = request.args.get("hours", 24, type=int)
+                metric_type = request.args.get("type", "all")
+
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
+                    history_data = self.monitoring_system.get_metrics_history(
+                        hours=hours, metric_type=metric_type
+                    )
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": history_data,
+                            "parameters": {"hours": hours, "type": metric_type},
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2403,21 +2423,21 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # 認証実行
                 token = self.security_manager.authenticate_user(username, password)
                 if token:
                     return jsonify({"success": True, "token": token})
                 else:
                     return jsonify({"error": "認証に失敗しました"}), 401
-                    
+
             except Exception as e:
                 self.logger.error(f"ログインエラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2428,22 +2448,22 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
                 role = data.get("role", "user")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # ユーザー登録
                 success = self.security_manager.register_user(username, password, role)
                 if success:
                     return jsonify({"success": True, "message": "ユーザーが正常に登録されました"})
                 else:
                     return jsonify({"error": "ユーザー登録に失敗しました"}), 400
-                    
+
             except Exception as e:
                 self.logger.error(f"ユーザー登録エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2454,10 +2474,10 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 logs = self.security_manager.get_audit_logs()
                 return jsonify({"logs": logs})
-                    
+
             except Exception as e:
                 self.logger.error(f"監査ログ取得エラー: {e}")
                 return jsonify({"error": str(e)}), 500
diff --git a/backups/dashboard_legacy/orch_dashboard_v2_20251012_125034.py b/backups/dashboard_legacy/orch_dashboard_v2_20251012_125034.py
index 2edabe8..46266a9 100644
--- a/backups/dashboard_legacy/orch_dashboard_v2_20251012_125034.py
+++ b/backups/dashboard_legacy/orch_dashboard_v2_20251012_125034.py
@@ -22,8 +22,8 @@ import psutil
 from flask import (
     Flask,
     Response,
-    jsonify,
     g,
+    jsonify,
     redirect,
     render_template,
     request,
@@ -31,12 +31,10 @@ from flask import (
     stream_with_context,
     url_for,
 )
-from flask_cors import CORS
-from flask_socketio import SocketIO, emit
 from flask_caching import Cache
 from flask_compress import Compress
-
-
+from flask_cors import CORS
+from flask_socketio import SocketIO, emit
 
 # Ensure log handlers are cleanly closed on process exit to avoid ResourceWarning
 atexit.register(logging.shutdown)
@@ -57,6 +55,7 @@ sys.path.append(str(Path(__file__).parent.parent.parent / "src"))
 # 自動再訓練スケジューラーのインポート
 try:
     from src.auto_retrain_scheduler import AutoRetrainScheduler
+
     AUTO_RETRAIN_AVAILABLE = True
 except ImportError:
     AUTO_RETRAIN_AVAILABLE = False
@@ -224,6 +223,7 @@ class OrchDashboard:
         self.monitoring_system = None
         try:
             from src.monitoring_system import MonitoringSystem
+
             self.monitoring_system = MonitoringSystem()
             self.logger.info("Monitoring system initialized")
         except Exception as e:
@@ -233,6 +233,7 @@ class OrchDashboard:
         self.security_manager = None
         try:
             from src.security_manager import SecurityManager
+
             self.security_manager = SecurityManager()
             self.logger.info("Security manager initialized")
         except Exception as e:
@@ -498,10 +499,10 @@ class OrchDashboard:
         @self.app.before_request
         def before_request():
             g.start_time = time.time()
-        
+
         @self.app.after_request
         def after_request(response):
-            if hasattr(g, 'start_time'):
+            if hasattr(g, "start_time"):
                 duration = time.time() - g.start_time
                 if duration > 1.0:  # 1秒以上の場合ログ出力
                     self.logger.warning(f"Slow request: {request.path} took {duration:.2f}s")
@@ -777,17 +778,22 @@ class OrchDashboard:
                         "dashboard": "running",
                         "monitoring": "active" if self.monitoring_system else "inactive",
                         "security": "active" if self.security_manager else "inactive",
-                        "ml_engine": "active" if self.ml_engine else "inactive"
+                        "ml_engine": "active" if self.ml_engine else "inactive",
                     },
                     "system": {
                         "cpu_percent": psutil.cpu_percent(interval=0.1),
                         "memory_percent": psutil.virtual_memory().percent,
-                        "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
-                    }
+                        "disk_percent": (
+                            psutil.disk_usage("/").percent
+                            if os.name != "nt"
+                            else psutil.disk_usage("C:").percent
+                        ),
+                    },
                 }
                 return jsonify(status), 200
             except Exception as e:
                 return jsonify({"status": "error", "message": str(e)}), 500
+
         @self.app.route("/status")
         def status():
             try:
@@ -2253,7 +2259,7 @@ class OrchDashboard:
             """自動再訓練スケジューラーの状態取得"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 status = self.auto_retrain_scheduler.get_status()
                 return jsonify(status)
@@ -2266,11 +2272,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー開始"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.start())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを開始しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを開始しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練開始エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2280,11 +2289,14 @@ class OrchDashboard:
             """自動再訓練スケジューラー停止"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
+
                 asyncio.create_task(self.auto_retrain_scheduler.stop())
-                return jsonify({"success": True, "message": "自動再訓練スケジューラーを停止しました"})
+                return jsonify(
+                    {"success": True, "message": "自動再訓練スケジューラーを停止しました"}
+                )
             except Exception as e:
                 self.logger.error(f"再訓練停止エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2294,15 +2306,15 @@ class OrchDashboard:
             """手動再訓練実行"""
             if not self.auto_retrain_scheduler:
                 return jsonify({"error": "自動再訓練機能が利用できません"}), 503
-            
+
             try:
                 import asyncio
-                
+
                 async def run_manual_retrain():
                     results = await self.auto_retrain_scheduler.retrain_models()
                     self.auto_retrain_scheduler.save_retrain_log(results)
                     return results
-                
+
                 # 非同期実行
                 asyncio.create_task(run_manual_retrain())
                 return jsonify({"success": True, "message": "手動再訓練を開始しました"})
@@ -2315,13 +2327,15 @@ class OrchDashboard:
         def api_monitoring_performance():
             """パフォーマンス監視データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     performance_data = self.monitoring_system.get_performance_summary()
-                    return jsonify({
-                        "success": True,
-                        "data": performance_data,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": performance_data,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2332,13 +2346,15 @@ class OrchDashboard:
         def api_monitoring_alerts():
             """アラート統計データ取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     alert_stats = self.monitoring_system.get_alert_statistics()
-                    return jsonify({
-                        "success": True,
-                        "data": alert_stats,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": alert_stats,
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2349,13 +2365,11 @@ class OrchDashboard:
         def api_monitoring_status():
             """監視システム全体ステータス取得"""
             try:
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
                     status = self.monitoring_system.get_system_status()
-                    return jsonify({
-                        "success": True,
-                        "data": status,
-                        "timestamp": datetime.now().isoformat()
-                    })
+                    return jsonify(
+                        {"success": True, "data": status, "timestamp": datetime.now().isoformat()}
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2366,17 +2380,21 @@ class OrchDashboard:
         def api_monitoring_metrics_history():
             """メトリクス履歴データ取得"""
             try:
-                hours = request.args.get('hours', 24, type=int)
-                metric_type = request.args.get('type', 'all')
-                
-                if hasattr(self, 'monitoring_system') and self.monitoring_system:
-                    history_data = self.monitoring_system.get_metrics_history(hours=hours, metric_type=metric_type)
-                    return jsonify({
-                        "success": True,
-                        "data": history_data,
-                        "parameters": {"hours": hours, "type": metric_type},
-                        "timestamp": datetime.now().isoformat()
-                    })
+                hours = request.args.get("hours", 24, type=int)
+                metric_type = request.args.get("type", "all")
+
+                if hasattr(self, "monitoring_system") and self.monitoring_system:
+                    history_data = self.monitoring_system.get_metrics_history(
+                        hours=hours, metric_type=metric_type
+                    )
+                    return jsonify(
+                        {
+                            "success": True,
+                            "data": history_data,
+                            "parameters": {"hours": hours, "type": metric_type},
+                            "timestamp": datetime.now().isoformat(),
+                        }
+                    )
                 else:
                     return jsonify({"error": "監視システムが利用できません"}), 503
             except Exception as e:
@@ -2421,21 +2439,21 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # 認証実行
                 token = self.security_manager.authenticate_user(username, password)
                 if token:
                     return jsonify({"success": True, "token": token})
                 else:
                     return jsonify({"error": "認証に失敗しました"}), 401
-                    
+
             except Exception as e:
                 self.logger.error(f"ログインエラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2446,22 +2464,22 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 data = request.get_json()
                 username = data.get("username")
                 password = data.get("password")
                 role = data.get("role", "user")
-                
+
                 if not username or not password:
                     return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
-                
+
                 # ユーザー登録
                 success = self.security_manager.register_user(username, password, role)
                 if success:
                     return jsonify({"success": True, "message": "ユーザーが正常に登録されました"})
                 else:
                     return jsonify({"error": "ユーザー登録に失敗しました"}), 400
-                    
+
             except Exception as e:
                 self.logger.error(f"ユーザー登録エラー: {e}")
                 return jsonify({"error": str(e)}), 500
@@ -2472,10 +2490,10 @@ class OrchDashboard:
             try:
                 if not self.security_manager:
                     return jsonify({"error": "セキュリティマネージャーが利用できません"}), 503
-                
+
                 logs = self.security_manager.get_audit_logs()
                 return jsonify({"logs": logs})
-                    
+
             except Exception as e:
                 self.logger.error(f"監査ログ取得エラー: {e}")
                 return jsonify({"error": str(e)}), 500
diff --git a/backups/snapshot_20251008_171544/data/validation/sources/search_corpus/algorithms_python b/backups/snapshot_20251008_171544/data/validation/sources/search_corpus/algorithms_python
--- a/backups/snapshot_20251008_171544/data/validation/sources/search_corpus/algorithms_python
+++ b/backups/snapshot_20251008_171544/data/validation/sources/search_corpus/algorithms_python
@@ -1 +1 @@
-Subproject commit 9372040da93cf7f77fc4ec2fd9ce5f2761b8800b
+Subproject commit 9372040da93cf7f77fc4ec2fd9ce5f2761b8800b-dirty
diff --git a/data/validation/sources/search_corpus/algorithms_python b/data/validation/sources/search_corpus/algorithms_python
--- a/data/validation/sources/search_corpus/algorithms_python
+++ b/data/validation/sources/search_corpus/algorithms_python
@@ -1 +1 @@
-Subproject commit 9372040da93cf7f77fc4ec2fd9ce5f2761b8800b
+Subproject commit 9372040da93cf7f77fc4ec2fd9ce5f2761b8800b-dirty
diff --git a/deep_performance_analyzer.py b/deep_performance_analyzer.py
index b4cf1c4..8772560 100644
--- a/deep_performance_analyzer.py
+++ b/deep_performance_analyzer.py
@@ -4,48 +4,50 @@
 """
 
 import asyncio
-import aiohttp
-import time
-import psutil
-import json
-import threading
-from datetime import datetime
-from typing import Dict, List, Any
-import statistics
 import cProfile
-import pstats
 import io
+import json
+import os
+import pstats
+import statistics
+import sys
+import threading
+import time
 from concurrent.futures import ThreadPoolExecutor
+from datetime import datetime
+from typing import Any, Dict, List
+
+import aiohttp
+import psutil
 import requests
-import sys
-import os
+
 
 class DeepPerformanceAnalyzer:
     def __init__(self, base_url: str = "http://localhost:5000"):
         self.base_url = base_url
         self.results = {}
-        
+
     def profile_endpoint(self, endpoint: str, duration: int = 10) -> Dict[str, Any]:
         """エンドポイントの詳細プロファイリング"""
         print(f"\n=== {endpoint} の詳細分析 ===")
-        
+
         # プロファイラーの設定
         profiler = cProfile.Profile()
-        
+
         response_times = []
         errors = 0
         start_time = time.time()
-        
+
         def make_request():
             try:
                 response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                 return response.elapsed.total_seconds(), response.status_code
             except Exception as e:
                 return None, 500
-        
+
         # プロファイリング開始
         profiler.enable()
-        
+
         while time.time() - start_time < duration:
             elapsed, status = make_request()
             if elapsed is not None and status == 200:
@@ -53,99 +55,103 @@ class DeepPerformanceAnalyzer:
             else:
                 errors += 1
             time.sleep(0.1)
-        
+
         profiler.disable()
-        
+
         # プロファイル結果の分析
         s = io.StringIO()
         ps = pstats.Stats(profiler, stream=s)
-        ps.sort_stats('cumulative')
+        ps.sort_stats("cumulative")
         ps.print_stats(20)
         profile_output = s.getvalue()
-        
+
         if response_times:
             result = {
-                'endpoint': endpoint,
-                'total_requests': len(response_times),
-                'errors': errors,
-                'avg_response_time': statistics.mean(response_times),
-                'median_response_time': statistics.median(response_times),
-                'p95_response_time': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times),
-                'min_response_time': min(response_times),
-                'max_response_time': max(response_times),
-                'profile_data': profile_output[:1000]  # 最初の1000文字のみ
+                "endpoint": endpoint,
+                "total_requests": len(response_times),
+                "errors": errors,
+                "avg_response_time": statistics.mean(response_times),
+                "median_response_time": statistics.median(response_times),
+                "p95_response_time": (
+                    statistics.quantiles(response_times, n=20)[18]
+                    if len(response_times) > 20
+                    else max(response_times)
+                ),
+                "min_response_time": min(response_times),
+                "max_response_time": max(response_times),
+                "profile_data": profile_output[:1000],  # 最初の1000文字のみ
             }
         else:
             result = {
-                'endpoint': endpoint,
-                'total_requests': 0,
-                'errors': errors,
-                'error_message': 'すべてのリクエストが失敗'
+                "endpoint": endpoint,
+                "total_requests": 0,
+                "errors": errors,
+                "error_message": "すべてのリクエストが失敗",
             }
-        
+
         return result
-    
+
     def analyze_system_resources(self, duration: int = 30) -> Dict[str, Any]:
         """システムリソースの詳細分析"""
         print(f"\n=== システムリソース分析 ({duration}秒) ===")
-        
+
         cpu_samples = []
         memory_samples = []
         disk_samples = []
         network_samples = []
-        
+
         start_time = time.time()
-        
+
         while time.time() - start_time < duration:
             # CPU使用率
             cpu_percent = psutil.cpu_percent(interval=1)
             cpu_samples.append(cpu_percent)
-            
+
             # メモリ使用率
             memory = psutil.virtual_memory()
             memory_samples.append(memory.percent)
-            
+
             # ディスクI/O
             disk_io = psutil.disk_io_counters()
             if disk_io:
-                disk_samples.append({
-                    'read_bytes': disk_io.read_bytes,
-                    'write_bytes': disk_io.write_bytes
-                })
-            
+                disk_samples.append(
+                    {"read_bytes": disk_io.read_bytes, "write_bytes": disk_io.write_bytes}
+                )
+
             # ネットワークI/O
             network_io = psutil.net_io_counters()
             if network_io:
-                network_samples.append({
-                    'bytes_sent': network_io.bytes_sent,
-                    'bytes_recv': network_io.bytes_recv
-                })
-        
+                network_samples.append(
+                    {"bytes_sent": network_io.bytes_sent, "bytes_recv": network_io.bytes_recv}
+                )
+
         return {
-            'cpu': {
-                'avg': statistics.mean(cpu_samples),
-                'max': max(cpu_samples),
-                'min': min(cpu_samples),
-                'samples': cpu_samples
+            "cpu": {
+                "avg": statistics.mean(cpu_samples),
+                "max": max(cpu_samples),
+                "min": min(cpu_samples),
+                "samples": cpu_samples,
             },
-            'memory': {
-                'avg': statistics.mean(memory_samples),
-                'max': max(memory_samples),
-                'min': min(memory_samples),
-                'samples': memory_samples
+            "memory": {
+                "avg": statistics.mean(memory_samples),
+                "max": max(memory_samples),
+                "min": min(memory_samples),
+                "samples": memory_samples,
             },
-            'disk_io_samples': len(disk_samples),
-            'network_io_samples': len(network_samples)
+            "disk_io_samples": len(disk_samples),
+            "network_io_samples": len(network_samples),
         }
-    
-    def concurrent_load_analysis(self, endpoint: str, workers: int = 10, duration: int = 30) -> Dict[str, Any]:
+
+    def concurrent_load_analysis(
+        self, endpoint: str, workers: int = 10, duration: int = 30
+    ) -> Dict[str, Any]:
         """並行負荷での詳細分析"""
         print(f"\n=== 並行負荷分析: {endpoint} ({workers}ワーカー, {duration}秒) ===")
-        
+
         response_times = []
         errors = 0
         lock = threading.Lock()
-        
+
         def worker():
             nonlocal errors
             start_time = time.time()
@@ -158,131 +164,140 @@ class DeepPerformanceAnalyzer:
                     with lock:
                         errors += 1
                 time.sleep(0.01)  # 短い間隔
-        
+
         # ワーカースレッドの開始
         threads = []
         start_time = time.time()
-        
+
         for _ in range(workers):
             thread = threading.Thread(target=worker)
             thread.start()
             threads.append(thread)
-        
+
         # すべてのスレッドの完了を待機
         for thread in threads:
             thread.join()
-        
+
         total_time = time.time() - start_time
-        
+
         if response_times:
             return {
-                'endpoint': endpoint,
-                'workers': workers,
-                'duration': total_time,
-                'total_requests': len(response_times),
-                'errors': errors,
-                'throughput_rps': len(response_times) / total_time,
-                'avg_response_time': statistics.mean(response_times),
-                'p95_response_time': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times),
-                'error_rate': errors / (len(response_times) + errors) * 100
+                "endpoint": endpoint,
+                "workers": workers,
+                "duration": total_time,
+                "total_requests": len(response_times),
+                "errors": errors,
+                "throughput_rps": len(response_times) / total_time,
+                "avg_response_time": statistics.mean(response_times),
+                "p95_response_time": (
+                    statistics.quantiles(response_times, n=20)[18]
+                    if len(response_times) > 20
+                    else max(response_times)
+                ),
+                "error_rate": errors / (len(response_times) + errors) * 100,
             }
         else:
             return {
-                'endpoint': endpoint,
-                'workers': workers,
-                'total_requests': 0,
-                'errors': errors,
-                'error_message': 'すべてのリクエストが失敗'
+                "endpoint": endpoint,
+                "workers": workers,
+                "total_requests": 0,
+                "errors": errors,
+                "error_message": "すべてのリクエストが失敗",
             }
-    
+
     def memory_leak_detection(self, endpoint: str, iterations: int = 100) -> Dict[str, Any]:
         """メモリリーク検出"""
         print(f"\n=== メモリリーク検出: {endpoint} ===")
-        
+
         memory_usage = []
-        
+
         for i in range(iterations):
             # リクエスト前のメモリ使用量
             memory_before = psutil.virtual_memory().percent
-            
+
             try:
                 requests.get(f"{self.base_url}{endpoint}", timeout=5)
             except Exception:
                 pass
-            
+
             # リクエスト後のメモリ使用量
             memory_after = psutil.virtual_memory().percent
             memory_usage.append(memory_after)
-            
+
             if i % 10 == 0:
                 print(f"  反復 {i}: メモリ使用率 {memory_after:.1f}%")
-        
+
         # メモリ使用量の傾向分析
         if len(memory_usage) > 10:
-            first_half = memory_usage[:len(memory_usage)//2]
-            second_half = memory_usage[len(memory_usage)//2:]
-            
+            first_half = memory_usage[: len(memory_usage) // 2]
+            second_half = memory_usage[len(memory_usage) // 2 :]
+
             avg_first = statistics.mean(first_half)
             avg_second = statistics.mean(second_half)
-            
+
             memory_increase = avg_second - avg_first
-            
+
             return {
-                'endpoint': endpoint,
-                'iterations': iterations,
-                'memory_increase': memory_increase,
-                'avg_memory_first_half': avg_first,
-                'avg_memory_second_half': avg_second,
-                'potential_leak': memory_increase > 1.0,  # 1%以上の増加でリーク疑い
-                'memory_samples': memory_usage
+                "endpoint": endpoint,
+                "iterations": iterations,
+                "memory_increase": memory_increase,
+                "avg_memory_first_half": avg_first,
+                "avg_memory_second_half": avg_second,
+                "potential_leak": memory_increase > 1.0,  # 1%以上の増加でリーク疑い
+                "memory_samples": memory_usage,
             }
         else:
-            return {'error': 'サンプル数が不足'}
-    
+            return {"error": "サンプル数が不足"}
+
     def generate_comprehensive_report(self) -> str:
         """包括的なレポート生成"""
         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
         report_file = f"deep_performance_report_{timestamp}.json"
-        
+
         print("\n=== 包括的パフォーマンス分析開始 ===")
-        
+
         # 主要エンドポイントの分析
-        endpoints = ['/', '/api/status', '/tasks', '/approvals']
-        
+        endpoints = ["/", "/api/status", "/tasks", "/approvals"]
+
         analysis_results = {
-            'timestamp': timestamp,
-            'endpoint_analysis': {},
-            'system_resources': {},
-            'concurrent_load': {},
-            'memory_leak_detection': {}
+            "timestamp": timestamp,
+            "endpoint_analysis": {},
+            "system_resources": {},
+            "concurrent_load": {},
+            "memory_leak_detection": {},
         }
-        
+
         # エンドポイント別詳細分析
         for endpoint in endpoints:
             print(f"\n--- {endpoint} の分析中 ---")
-            analysis_results['endpoint_analysis'][endpoint] = self.profile_endpoint(endpoint, 15)
-        
+            analysis_results["endpoint_analysis"][endpoint] = self.profile_endpoint(endpoint, 15)
+
         # システムリソース分析
-        analysis_results['system_resources'] = self.analyze_system_resources(30)
-        
+        analysis_results["system_resources"] = self.analyze_system_resources(30)
+
         # 並行負荷分析
-        for endpoint in ['/', '/api/status']:
-            analysis_results['concurrent_load'][endpoint] = self.concurrent_load_analysis(endpoint, 15, 20)
-        
+        for endpoint in ["/", "/api/status"]:
+            analysis_results["concurrent_load"][endpoint] = self.concurrent_load_analysis(
+                endpoint, 15, 20
+            )
+
         # メモリリーク検出
-        for endpoint in ['/', '/api/status']:
-            analysis_results['memory_leak_detection'][endpoint] = self.memory_leak_detection(endpoint, 50)
-        
+        for endpoint in ["/", "/api/status"]:
+            analysis_results["memory_leak_detection"][endpoint] = self.memory_leak_detection(
+                endpoint, 50
+            )
+
         # レポート保存
-        with open(report_file, 'w', encoding='utf-8') as f:
+        with open(report_file, "w", encoding="utf-8") as f:
             json.dump(analysis_results, f, indent=2, ensure_ascii=False)
-        
+
         print(f"\n=== 分析完了: {report_file} ===")
         return report_file
 
+
 def main():
     analyzer = DeepPerformanceAnalyzer()
-    
+
     # ダッシュボードの稼働確認
     try:
         response = requests.get("http://localhost:5000/", timeout=5)
@@ -290,11 +305,12 @@ def main():
     except Exception as e:
         print(f"ダッシュボードに接続できません: {e}")
         return
-    
+
     # 包括的分析の実行
     report_file = analyzer.generate_comprehensive_report()
-    
+
     print(f"\n詳細分析レポートが生成されました: {report_file}")
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/final_performance_test.py b/final_performance_test.py
index 921f541..cd37a22 100644
--- a/final_performance_test.py
+++ b/final_performance_test.py
@@ -4,258 +4,280 @@
 修正後のダッシュボードの性能を評価
 """
 
-import requests
-import time
-import statistics
 import json
-from datetime import datetime
-from concurrent.futures import ThreadPoolExecutor, as_completed
+import statistics
 import threading
+import time
+from concurrent.futures import ThreadPoolExecutor, as_completed
+from datetime import datetime
+
+import requests
+
 
 class FinalPerformanceTest:
     def __init__(self, base_url="http://127.0.0.1:5000"):
         self.base_url = base_url
         self.results = {}
-        
+
     def test_endpoint(self, endpoint, num_requests=10):
         """エンドポイントのパフォーマンステスト"""
         url = f"{self.base_url}{endpoint}"
         response_times = []
         errors = 0
-        
+
         print(f"Testing {endpoint}...")
-        
+
         for i in range(num_requests):
             try:
                 start_time = time.time()
                 response = requests.get(url, timeout=10)
                 end_time = time.time()
-                
+
                 response_time = (end_time - start_time) * 1000  # ms
                 response_times.append(response_time)
-                
+
                 if response.status_code != 200:
                     errors += 1
                     print(f"  Request {i+1}: {response.status_code} - {response_time:.1f}ms")
                 else:
                     print(f"  Request {i+1}: OK - {response_time:.1f}ms")
-                    
+
             except Exception as e:
                 errors += 1
                 print(f"  Request {i+1}: ERROR - {str(e)}")
-                
+
             time.sleep(0.1)  # 短い間隔
-        
+
         if response_times:
             avg_time = statistics.mean(response_times)
-            p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)
+            p95_time = (
+                statistics.quantiles(response_times, n=20)[18]
+                if len(response_times) >= 20
+                else max(response_times)
+            )
             min_time = min(response_times)
             max_time = max(response_times)
         else:
             avg_time = p95_time = min_time = max_time = 0
-            
+
         return {
-            'endpoint': endpoint,
-            'total_requests': num_requests,
-            'successful_requests': num_requests - errors,
-            'errors': errors,
-            'avg_response_time_ms': round(avg_time, 2),
-            'p95_response_time_ms': round(p95_time, 2),
-            'min_response_time_ms': round(min_time, 2),
-            'max_response_time_ms': round(max_time, 2),
-            'error_rate': round((errors / num_requests) * 100, 2)
+            "endpoint": endpoint,
+            "total_requests": num_requests,
+            "successful_requests": num_requests - errors,
+            "errors": errors,
+            "avg_response_time_ms": round(avg_time, 2),
+            "p95_response_time_ms": round(p95_time, 2),
+            "min_response_time_ms": round(min_time, 2),
+            "max_response_time_ms": round(max_time, 2),
+            "error_rate": round((errors / num_requests) * 100, 2),
         }
-    
+
     def concurrent_test(self, endpoint, concurrent_users=5, requests_per_user=5):
         """並行負荷テスト"""
-        print(f"\nConcurrent test for {endpoint} ({concurrent_users} users, {requests_per_user} requests each)...")
-        
+        print(
+            f"\nConcurrent test for {endpoint} ({concurrent_users} users, {requests_per_user} requests each)..."
+        )
+
         def user_requests(user_id):
             user_times = []
             user_errors = 0
-            
+
             for i in range(requests_per_user):
                 try:
                     start_time = time.time()
                     response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                     end_time = time.time()
-                    
+
                     response_time = (end_time - start_time) * 1000
                     user_times.append(response_time)
-                    
+
                     if response.status_code != 200:
                         user_errors += 1
-                        
+
                 except Exception:
                     user_errors += 1
-                    
+
             return user_times, user_errors
-        
+
         all_times = []
         total_errors = 0
-        
+
         with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
             futures = [executor.submit(user_requests, i) for i in range(concurrent_users)]
-            
+
             for future in as_completed(futures):
                 times, errors = future.result()
                 all_times.extend(times)
                 total_errors += errors
-        
+
         total_requests = concurrent_users * requests_per_user
-        
+
         if all_times:
             avg_time = statistics.mean(all_times)
-            p95_time = statistics.quantiles(all_times, n=20)[18] if len(all_times) >= 20 else max(all_times)
+            p95_time = (
+                statistics.quantiles(all_times, n=20)[18]
+                if len(all_times) >= 20
+                else max(all_times)
+            )
         else:
             avg_time = p95_time = 0
-            
+
         return {
-            'endpoint': endpoint,
-            'concurrent_users': concurrent_users,
-            'total_requests': total_requests,
-            'successful_requests': total_requests - total_errors,
-            'errors': total_errors,
-            'avg_response_time_ms': round(avg_time, 2),
-            'p95_response_time_ms': round(p95_time, 2),
-            'error_rate': round((total_errors / total_requests) * 100, 2)
+            "endpoint": endpoint,
+            "concurrent_users": concurrent_users,
+            "total_requests": total_requests,
+            "successful_requests": total_requests - total_errors,
+            "errors": total_errors,
+            "avg_response_time_ms": round(avg_time, 2),
+            "p95_response_time_ms": round(p95_time, 2),
+            "error_rate": round((total_errors / total_requests) * 100, 2),
         }
-    
+
     def run_full_test(self):
         """完全なパフォーマンステストを実行"""
         print("=== 最終パフォーマンステスト開始 ===")
         print(f"テスト対象: {self.base_url}")
         print(f"開始時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
-        
+
         # テスト対象エンドポイント
-        endpoints = [
-            '/',
-            '/api/status',
-            '/tasks',
-            '/approvals'
-        ]
-        
+        endpoints = ["/", "/api/status", "/tasks", "/approvals"]
+
         # 単一リクエストテスト
         print("\n--- 単一リクエストテスト ---")
         sequential_results = []
         for endpoint in endpoints:
             result = self.test_endpoint(endpoint, num_requests=10)
             sequential_results.append(result)
-            print(f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95")
-        
+            print(
+                f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95"
+            )
+
         # 並行負荷テスト
         print("\n--- 並行負荷テスト ---")
         concurrent_results = []
-        for endpoint in ['/', '/api/status']:  # 主要エンドポイントのみ
+        for endpoint in ["/", "/api/status"]:  # 主要エンドポイントのみ
             result = self.concurrent_test(endpoint, concurrent_users=5, requests_per_user=5)
             concurrent_results.append(result)
-            print(f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95")
-        
+            print(
+                f"  {endpoint}: {result['avg_response_time_ms']}ms avg, {result['p95_response_time_ms']}ms P95"
+            )
+
         # 結果の保存
         final_results = {
-            'test_timestamp': datetime.now().isoformat(),
-            'base_url': self.base_url,
-            'sequential_tests': sequential_results,
-            'concurrent_tests': concurrent_results,
-            'summary': self.generate_summary(sequential_results, concurrent_results)
+            "test_timestamp": datetime.now().isoformat(),
+            "base_url": self.base_url,
+            "sequential_tests": sequential_results,
+            "concurrent_tests": concurrent_results,
+            "summary": self.generate_summary(sequential_results, concurrent_results),
         }
-        
+
         # レポート保存
-        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
+        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
         report_file = f"final_performance_report_{timestamp}.json"
-        
-        with open(report_file, 'w', encoding='utf-8') as f:
+
+        with open(report_file, "w", encoding="utf-8") as f:
             json.dump(final_results, f, indent=2, ensure_ascii=False)
-        
+
         print(f"\n=== テスト完了 ===")
         print(f"レポート保存: {report_file}")
-        
+
         # サマリー表示
-        self.print_summary(final_results['summary'])
-        
+        self.print_summary(final_results["summary"])
+
         return final_results
-    
+
     def generate_summary(self, sequential_results, concurrent_results):
         """テスト結果のサマリーを生成"""
         # 最も遅いエンドポイント
-        slowest_seq = max(sequential_results, key=lambda x: x['avg_response_time_ms'])
-        fastest_seq = min(sequential_results, key=lambda x: x['avg_response_time_ms'])
-        
+        slowest_seq = max(sequential_results, key=lambda x: x["avg_response_time_ms"])
+        fastest_seq = min(sequential_results, key=lambda x: x["avg_response_time_ms"])
+
         # エラー率
-        total_errors = sum(r['errors'] for r in sequential_results)
-        total_requests = sum(r['total_requests'] for r in sequential_results)
+        total_errors = sum(r["errors"] for r in sequential_results)
+        total_requests = sum(r["total_requests"] for r in sequential_results)
         overall_error_rate = (total_errors / total_requests) * 100 if total_requests > 0 else 0
-        
+
         # P95の評価
-        high_p95_endpoints = [r for r in sequential_results if r['p95_response_time_ms'] > 1000]
-        
+        high_p95_endpoints = [r for r in sequential_results if r["p95_response_time_ms"] > 1000]
+
         return {
-            'overall_error_rate': round(overall_error_rate, 2),
-            'slowest_endpoint': {
-                'endpoint': slowest_seq['endpoint'],
-                'avg_time_ms': slowest_seq['avg_response_time_ms'],
-                'p95_time_ms': slowest_seq['p95_response_time_ms']
+            "overall_error_rate": round(overall_error_rate, 2),
+            "slowest_endpoint": {
+                "endpoint": slowest_seq["endpoint"],
+                "avg_time_ms": slowest_seq["avg_response_time_ms"],
+                "p95_time_ms": slowest_seq["p95_response_time_ms"],
             },
-            'fastest_endpoint': {
-                'endpoint': fastest_seq['endpoint'],
-                'avg_time_ms': fastest_seq['avg_response_time_ms'],
-                'p95_time_ms': fastest_seq['p95_response_time_ms']
+            "fastest_endpoint": {
+                "endpoint": fastest_seq["endpoint"],
+                "avg_time_ms": fastest_seq["avg_response_time_ms"],
+                "p95_time_ms": fastest_seq["p95_response_time_ms"],
             },
-            'high_p95_endpoints': len(high_p95_endpoints),
-            'performance_grade': self.calculate_grade(sequential_results),
-            'recommendations': self.generate_recommendations(sequential_results)
+            "high_p95_endpoints": len(high_p95_endpoints),
+            "performance_grade": self.calculate_grade(sequential_results),
+            "recommendations": self.generate_recommendations(sequential_results),
         }
-    
+
     def calculate_grade(self, results):
         """パフォーマンスグレードを計算"""
-        avg_p95 = statistics.mean([r['p95_response_time_ms'] for r in results])
-        
+        avg_p95 = statistics.mean([r["p95_response_time_ms"] for r in results])
+
         if avg_p95 < 200:
-            return 'A'
+            return "A"
         elif avg_p95 < 500:
-            return 'B'
+            return "B"
         elif avg_p95 < 1000:
-            return 'C'
+            return "C"
         elif avg_p95 < 2000:
-            return 'D'
+            return "D"
         else:
-            return 'F'
-    
+            return "F"
+
     def generate_recommendations(self, results):
         """改善提案を生成"""
         recommendations = []
-        
+
         for result in results:
-            if result['p95_response_time_ms'] > 2000:
-                recommendations.append(f"{result['endpoint']}: 重大なパフォーマンス問題 (P95: {result['p95_response_time_ms']}ms)")
-            elif result['p95_response_time_ms'] > 1000:
-                recommendations.append(f"{result['endpoint']}: パフォーマンス改善が必要 (P95: {result['p95_response_time_ms']}ms)")
-            
-            if result['error_rate'] > 5:
-                recommendations.append(f"{result['endpoint']}: エラー率が高い ({result['error_rate']}%)")
-        
+            if result["p95_response_time_ms"] > 2000:
+                recommendations.append(
+                    f"{result['endpoint']}: 重大なパフォーマンス問題 (P95: {result['p95_response_time_ms']}ms)"
+                )
+            elif result["p95_response_time_ms"] > 1000:
+                recommendations.append(
+                    f"{result['endpoint']}: パフォーマンス改善が必要 (P95: {result['p95_response_time_ms']}ms)"
+                )
+
+            if result["error_rate"] > 5:
+                recommendations.append(
+                    f"{result['endpoint']}: エラー率が高い ({result['error_rate']}%)"
+                )
+
         if not recommendations:
             recommendations.append("パフォーマンスは良好です")
-            
+
         return recommendations
-    
+
     def print_summary(self, summary):
         """サマリーを表示"""
         print(f"\n=== パフォーマンスサマリー ===")
         print(f"総合エラー率: {summary['overall_error_rate']}%")
         print(f"パフォーマンスグレード: {summary['performance_grade']}")
-        print(f"最も遅いエンドポイント: {summary['slowest_endpoint']['endpoint']} ({summary['slowest_endpoint']['p95_time_ms']}ms P95)")
-        print(f"最も速いエンドポイント: {summary['fastest_endpoint']['endpoint']} ({summary['fastest_endpoint']['p95_time_ms']}ms P95)")
+        print(
+            f"最も遅いエンドポイント: {summary['slowest_endpoint']['endpoint']} ({summary['slowest_endpoint']['p95_time_ms']}ms P95)"
+        )
+        print(
+            f"最も速いエンドポイント: {summary['fastest_endpoint']['endpoint']} ({summary['fastest_endpoint']['p95_time_ms']}ms P95)"
+        )
         print(f"P95 > 1秒のエンドポイント数: {summary['high_p95_endpoints']}")
-        
+
         print(f"\n=== 改善提案 ===")
-        for rec in summary['recommendations']:
+        for rec in summary["recommendations"]:
             print(f"- {rec}")
 
+
 def main():
     """メイン実行"""
     tester = FinalPerformanceTest()
-    
+
     # サーバーの生存確認
     try:
         response = requests.get(f"{tester.base_url}/api/status", timeout=5)
@@ -263,11 +285,12 @@ def main():
     except Exception as e:
         print(f"サーバーに接続できません: {e}")
         return
-    
+
     # テスト実行
     results = tester.run_full_test()
-    
+
     return results
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/generate_test_report.py b/generate_test_report.py
index 9f7839a..ed4d68e 100644
--- a/generate_test_report.py
+++ b/generate_test_report.py
@@ -8,19 +8,20 @@ import json
 import os
 from datetime import datetime
 
+
 class TestReportGenerator:
     def __init__(self):
         self.test_files = [
             ("test_results.json", "基本UI機能テスト"),
             ("api_test_results.json", "API機能テスト"),
             ("element_selection_test_results.json", "要素選択機能テスト"),
-            ("visual_editing_test_results.json", "ビジュアル編集機能テスト")
+            ("visual_editing_test_results.json", "ビジュアル編集機能テスト"),
         ]
-        
+
     def load_test_results(self):
         """全てのテスト結果を読み込み"""
         all_results = {}
-        
+
         for filename, description in self.test_files:
             if os.path.exists(filename):
                 try:
@@ -34,9 +35,9 @@ class TestReportGenerator:
             else:
                 print(f"⚠️ {description} ファイルが見つかりません: {filename}")
                 all_results[description] = {"error": "ファイルが見つかりません"}
-        
+
         return all_results
-    
+
     def generate_html_report(self, all_results):
         """HTMLレポートを生成"""
         html_content = f"""
@@ -179,22 +180,22 @@ class TestReportGenerator:
             <h2>📊 テスト結果サマリー</h2>
             <div class="summary-grid">
 """
-        
+
         # 全体のサマリーを計算
         total_passed = 0
         total_failed = 0
         total_skipped = 0
         total_tests = 0
-        
+
         for test_name, results in all_results.items():
             if "error" not in results and "summary" in results:
                 summary = results["summary"]
                 total_passed += summary.get("passed", 0)
                 total_failed += summary.get("failed", 0)
                 total_skipped += summary.get("skipped", 0)
-        
+
         total_tests = total_passed + total_failed + total_skipped
-        
+
         html_content += f"""
                 <div class="summary-card">
                     <h3>✅ 成功</h3>
@@ -215,14 +216,14 @@ class TestReportGenerator:
             </div>
         </div>
 """
-        
+
         # 各テストセクションの詳細
         for test_name, results in all_results.items():
             html_content += f"""
         <div class="test-section">
             <h2>{test_name}</h2>
 """
-            
+
             if "error" in results:
                 html_content += f"""
             <div class="error">
@@ -239,19 +240,21 @@ class TestReportGenerator:
                ⏭️ {summary.get("skipped", 0)} スキップ
             </p>
 """
-                
+
                 if "results" in results:
                     for result in results["results"]:
                         status = result.get("status", "UNKNOWN").lower()
-                        status_icon = "✅" if status == "pass" else "❌" if status == "fail" else "⏭️"
-                        
+                        status_icon = (
+                            "✅" if status == "pass" else "❌" if status == "fail" else "⏭️"
+                        )
+
                         html_content += f"""
             <div class="test-result {status}">
                 <h4><span class="status-icon">{status_icon}</span>{result.get("test", "Unknown Test")}</h4>
                 <p>{result.get("message", "No message")}</p>
             </div>
 """
-        
+
         html_content += f"""
         </div>
         
@@ -262,23 +265,23 @@ class TestReportGenerator:
 </body>
 </html>
 """
-        
+
         return html_content
-    
+
     def generate_json_report(self, all_results):
         """JSON統合レポートを生成"""
         # 全体のサマリーを計算
         total_passed = 0
         total_failed = 0
         total_skipped = 0
-        
+
         for test_name, results in all_results.items():
             if "error" not in results and "summary" in results:
                 summary = results["summary"]
                 total_passed += summary.get("passed", 0)
                 total_failed += summary.get("failed", 0)
                 total_skipped += summary.get("skipped", 0)
-        
+
         integrated_report = {
             "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "overall_summary": {
@@ -286,33 +289,37 @@ class TestReportGenerator:
                 "total_failed": total_failed,
                 "total_skipped": total_skipped,
                 "total_tests": total_passed + total_failed + total_skipped,
-                "success_rate": round((total_passed / (total_passed + total_failed + total_skipped)) * 100, 2) if (total_passed + total_failed + total_skipped) > 0 else 0
+                "success_rate": (
+                    round((total_passed / (total_passed + total_failed + total_skipped)) * 100, 2)
+                    if (total_passed + total_failed + total_skipped) > 0
+                    else 0
+                ),
             },
-            "test_suites": all_results
+            "test_suites": all_results,
         }
-        
+
         return integrated_report
-    
+
     def generate_report(self):
         """統合レポートを生成"""
         print("🚀 スタイル管理機能統合テストレポート生成開始")
         print("=" * 60)
-        
+
         # テスト結果を読み込み
         all_results = self.load_test_results()
-        
+
         # HTMLレポートを生成
         html_content = self.generate_html_report(all_results)
         with open("style_manager_test_report.html", "w", encoding="utf-8") as f:
             f.write(html_content)
         print("✓ HTMLレポートを生成しました: style_manager_test_report.html")
-        
+
         # JSON統合レポートを生成
         json_report = self.generate_json_report(all_results)
         with open("integrated_test_report.json", "w", encoding="utf-8") as f:
             json.dump(json_report, f, ensure_ascii=False, indent=2)
         print("✓ JSON統合レポートを生成しました: integrated_test_report.json")
-        
+
         # サマリーを表示
         print("\n📊 統合テスト結果サマリー")
         print("=" * 60)
@@ -322,11 +329,12 @@ class TestReportGenerator:
         print(f"⏭️ スキップ: {overall['total_skipped']}")
         print(f"📊 合計: {overall['total_tests']}")
         print(f"📈 成功率: {overall['success_rate']}%")
-        
+
         print(f"\n💾 詳細レポートファイル:")
         print(f"  - HTML: style_manager_test_report.html")
         print(f"  - JSON: integrated_test_report.json")
 
+
 if __name__ == "__main__":
     generator = TestReportGenerator()
-    generator.generate_report()
\ No newline at end of file
+    generator.generate_report()
diff --git a/orch_dashboard_refactored.py b/orch_dashboard_refactored.py
index 1509eba..c2191db 100644
--- a/orch_dashboard_refactored.py
+++ b/orch_dashboard_refactored.py
@@ -3,45 +3,47 @@ ORCH Dashboard - Refactored with Blueprint Architecture
 This is a refactored version of orch_dashboard.py using modular Blueprint structure
 """
 
-import logging
 import json
-import traceback
-import re
+import logging
 import os
-from flask import Flask, render_template, jsonify, request
-from datetime import datetime
+import re
 import time
+import traceback
+from datetime import datetime
 from pathlib import Path
+
+from flask import Flask, jsonify, render_template, request
+
 from src.style_manager import create_style_api
 
 # Configure structured logging with enhanced formatting
 logging.basicConfig(
     level=logging.INFO,
-    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
-    handlers=[
-        logging.StreamHandler(),
-        logging.FileHandler('orch_dashboard_refactored.log')
-    ]
+    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
+    handlers=[logging.StreamHandler(), logging.FileHandler("orch_dashboard_refactored.log")],
 )
 
+
 class BlueprintInitializationError(Exception):
     """Custom exception for Blueprint initialization failures"""
+
     pass
 
+
 class OrchDashboardRefactored:
     """Refactored ORCH Dashboard with Blueprint architecture"""
-    
+
     def __init__(self, base_dir=None, host="127.0.0.1", port=5000):
         self.base_dir = base_dir or Path(__file__).parent
         self.host = host
         self.port = port
         self.app = Flask(__name__)
         self.logger = logging.getLogger(__name__)
-        
+
         # Blueprint initialization tracking
         self.blueprint_status = {}
         self.initialization_start_time = time.time()
-        
+
         # Log initialization with structured format
         init_info = {
             "event": "dashboard_initialization_start",
@@ -49,20 +51,22 @@ class OrchDashboardRefactored:
             "base_directory": str(self.base_dir),
             "host": self.host,
             "port": self.port,
-            "process_id": os.getpid() if 'os' in globals() else None
+            "process_id": os.getpid() if "os" in globals() else None,
         }
-        self.logger.info(f"=== ORCH DASHBOARD REFACTORED INITIALIZATION === {json.dumps(init_info)}")
-        
+        self.logger.info(
+            f"=== ORCH DASHBOARD REFACTORED INITIALIZATION === {json.dumps(init_info)}"
+        )
+
         try:
             # Initialize Flask app configuration with error handling
             self._initialize_flask_config()
-            
+
             # Setup routes using Blueprint architecture with comprehensive error handling
             self._setup_routes()
-            
+
             # Initialize style management system
             self._initialize_style_manager()
-            
+
             # Log successful initialization
             init_duration = time.time() - self.initialization_start_time
             success_info = {
@@ -70,10 +74,12 @@ class OrchDashboardRefactored:
                 "timestamp": datetime.now().isoformat(),
                 "duration_seconds": round(init_duration, 3),
                 "blueprint_status": self.blueprint_status,
-                "total_routes": len(list(self.app.url_map.iter_rules()))
+                "total_routes": len(list(self.app.url_map.iter_rules())),
             }
-            self.logger.info(f"Dashboard initialization completed successfully: {json.dumps(success_info)}")
-            
+            self.logger.info(
+                f"Dashboard initialization completed successfully: {json.dumps(success_info)}"
+            )
+
         except Exception as e:
             # Log initialization failure with full traceback
             error_info = {
@@ -82,43 +88,43 @@ class OrchDashboardRefactored:
                 "error": str(e),
                 "error_type": type(e).__name__,
                 "traceback": traceback.format_exc(),
-                "blueprint_status": self.blueprint_status
+                "blueprint_status": self.blueprint_status,
             }
             self.logger.error(f"Dashboard initialization failed: {json.dumps(error_info)}")
             raise BlueprintInitializationError(f"Failed to initialize dashboard: {e}") from e
-    
+
     def _initialize_flask_config(self):
         """Initialize Flask app configuration with error handling"""
         try:
-            self.app.config['SECRET_KEY'] = 'orch-dashboard-secret-key'
-            self.app.config['JSON_AS_ASCII'] = False
-            self.app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
-            
+            self.app.config["SECRET_KEY"] = "orch-dashboard-secret-key"
+            self.app.config["JSON_AS_ASCII"] = False
+            self.app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
+
             config_info = {
                 "event": "flask_config_initialized",
                 "timestamp": datetime.now().isoformat(),
-                "config_keys": list(self.app.config.keys())
+                "config_keys": list(self.app.config.keys()),
             }
             self.logger.info(f"Flask app configuration completed: {json.dumps(config_info)}")
-            
+
         except Exception as e:
             error_info = {
                 "event": "flask_config_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             self.logger.error(f"Flask configuration failed: {json.dumps(error_info)}")
             raise
-    
+
     def _setup_routes(self):
         """Setup all Flask routes using Blueprint architecture with comprehensive error handling"""
         blueprint_start_time = time.time()
-        
+
         blueprint_info = {
             "event": "blueprint_registration_start",
             "timestamp": datetime.now().isoformat(),
-            "expected_blueprints": ["ui_bp", "api_bp", "sse_bp", "admin_bp"]
+            "expected_blueprints": ["ui_bp", "api_bp", "sse_bp", "admin_bp"],
         }
         self.logger.info(f"=== BLUEPRINT REGISTRATION STARTING === {json.dumps(blueprint_info)}")
 
@@ -130,62 +136,68 @@ class OrchDashboardRefactored:
                 "blueprint_name": "ui_bp",
                 "init_function": None,
                 "url_prefix": None,
-                "critical": True
+                "critical": True,
             },
             {
-                "name": "api_bp", 
+                "name": "api_bp",
                 "import_path": "src.blueprints.api_routes",
                 "blueprint_name": "api_bp",
                 "init_function": "init_api_routes",
                 "url_prefix": "/api",
-                "critical": True
+                "critical": True,
             },
             {
                 "name": "sse_bp",
-                "import_path": "src.blueprints.sse_routes", 
+                "import_path": "src.blueprints.sse_routes",
                 "blueprint_name": "sse_bp",
                 "init_function": "init_sse_routes",
                 "url_prefix": None,
-                "critical": False
+                "critical": False,
             },
             {
                 "name": "admin_bp",
                 "import_path": "src.blueprints.admin_routes",
-                "blueprint_name": "admin_bp", 
+                "blueprint_name": "admin_bp",
                 "init_function": "init_admin_routes",
                 "url_prefix": None,
-                "critical": False
-            }
+                "critical": False,
+            },
         ]
 
         successful_blueprints = 0
         failed_blueprints = 0
-        
+
         for blueprint_config in blueprints_to_register:
             blueprint_start = time.time()
             blueprint_name = blueprint_config["name"]
-            
+
             try:
                 self.logger.info(f"Importing {blueprint_name}...")
-                
+
                 # Dynamic import with error handling
-                module = __import__(blueprint_config["import_path"], fromlist=[blueprint_config["blueprint_name"]])
+                module = __import__(
+                    blueprint_config["import_path"], fromlist=[blueprint_config["blueprint_name"]]
+                )
                 blueprint = getattr(module, blueprint_config["blueprint_name"])
-                
+
                 # Initialize blueprint if init function exists
                 if blueprint_config["init_function"]:
                     init_func = getattr(module, blueprint_config["init_function"])
                     init_func(self)
-                    self.logger.info(f"{blueprint_name} initialization function called successfully")
-                
+                    self.logger.info(
+                        f"{blueprint_name} initialization function called successfully"
+                    )
+
                 # Register blueprint
                 if blueprint_config["url_prefix"]:
-                    self.app.register_blueprint(blueprint, url_prefix=blueprint_config["url_prefix"])
+                    self.app.register_blueprint(
+                        blueprint, url_prefix=blueprint_config["url_prefix"]
+                    )
                 else:
                     self.app.register_blueprint(blueprint)
-                
+
                 blueprint_duration = time.time() - blueprint_start
-                
+
                 # Log successful registration
                 success_info = {
                     "event": "blueprint_registered",
@@ -193,18 +205,26 @@ class OrchDashboardRefactored:
                     "timestamp": datetime.now().isoformat(),
                     "duration_seconds": round(blueprint_duration, 3),
                     "url_prefix": blueprint_config["url_prefix"],
-                    "routes_added": len([rule for rule in self.app.url_map.iter_rules() if rule.endpoint.startswith(blueprint_name)])
+                    "routes_added": len(
+                        [
+                            rule
+                            for rule in self.app.url_map.iter_rules()
+                            if rule.endpoint.startswith(blueprint_name)
+                        ]
+                    ),
                 }
-                self.logger.info(f"✓ {blueprint_name} registered successfully: {json.dumps(success_info)}")
-                
+                self.logger.info(
+                    f"✓ {blueprint_name} registered successfully: {json.dumps(success_info)}"
+                )
+
                 self.blueprint_status[blueprint_name] = {
                     "status": "SUCCESS",
                     "duration": blueprint_duration,
                     "timestamp": datetime.now().isoformat(),
-                    "routes_count": success_info["routes_added"]
+                    "routes_count": success_info["routes_added"],
                 }
                 successful_blueprints += 1
-                
+
             except ImportError as e:
                 # Handle import errors
                 error_info = {
@@ -214,22 +234,24 @@ class OrchDashboardRefactored:
                     "error": str(e),
                     "error_type": "ImportError",
                     "import_path": blueprint_config["import_path"],
-                    "critical": blueprint_config["critical"]
+                    "critical": blueprint_config["critical"],
                 }
                 self.logger.error(f"✗ Failed to import {blueprint_name}: {json.dumps(error_info)}")
-                
+
                 self.blueprint_status[blueprint_name] = {
                     "status": "IMPORT_FAILED",
                     "error": str(e),
                     "timestamp": datetime.now().isoformat(),
-                    "critical": blueprint_config["critical"]
+                    "critical": blueprint_config["critical"],
                 }
                 failed_blueprints += 1
-                
+
                 # If critical blueprint fails, consider fallback
                 if blueprint_config["critical"]:
-                    self.logger.warning(f"Critical blueprint {blueprint_name} failed - considering fallback")
-                
+                    self.logger.warning(
+                        f"Critical blueprint {blueprint_name} failed - considering fallback"
+                    )
+
             except Exception as e:
                 # Handle other registration errors
                 error_info = {
@@ -239,29 +261,34 @@ class OrchDashboardRefactored:
                     "error": str(e),
                     "error_type": type(e).__name__,
                     "traceback": traceback.format_exc(),
-                    "critical": blueprint_config["critical"]
+                    "critical": blueprint_config["critical"],
                 }
-                self.logger.error(f"✗ Failed to register {blueprint_name}: {json.dumps(error_info)}")
-                
+                self.logger.error(
+                    f"✗ Failed to register {blueprint_name}: {json.dumps(error_info)}"
+                )
+
                 self.blueprint_status[blueprint_name] = {
-                    "status": "REGISTRATION_FAILED", 
+                    "status": "REGISTRATION_FAILED",
                     "error": str(e),
                     "timestamp": datetime.now().isoformat(),
-                    "critical": blueprint_config["critical"]
+                    "critical": blueprint_config["critical"],
                 }
                 failed_blueprints += 1
 
         # Check if we need fallback routes
-        critical_failures = [name for name, status in self.blueprint_status.items() 
-                           if status.get("status") != "SUCCESS" and 
-                           any(bp["name"] == name and bp["critical"] for bp in blueprints_to_register)]
-        
+        critical_failures = [
+            name
+            for name, status in self.blueprint_status.items()
+            if status.get("status") != "SUCCESS"
+            and any(bp["name"] == name and bp["critical"] for bp in blueprints_to_register)
+        ]
+
         if critical_failures:
             fallback_info = {
                 "event": "fallback_routes_activated",
                 "timestamp": datetime.now().isoformat(),
                 "failed_critical_blueprints": critical_failures,
-                "reason": "Critical blueprint failures detected"
+                "reason": "Critical blueprint failures detected",
             }
             self.logger.warning(f"Activating fallback routes: {json.dumps(fallback_info)}")
             self._setup_minimal_routes()
@@ -279,13 +306,14 @@ class OrchDashboardRefactored:
             "successful_blueprints": successful_blueprints,
             "failed_blueprints": failed_blueprints,
             "total_routes": len(list(self.app.url_map.iter_rules())),
-            "blueprint_status": self.blueprint_status
+            "blueprint_status": self.blueprint_status,
         }
         self.logger.info(f"=== BLUEPRINT REGISTRATION COMPLETED === {json.dumps(summary_info)}")
 
     def _setup_request_hooks(self):
         """Setup Flask request hooks with error handling"""
         try:
+
             @self.app.after_request
             def _after_request(response):
                 """Add security headers and CORS with error handling"""
@@ -294,32 +322,35 @@ class OrchDashboardRefactored:
                     response.headers["X-Frame-Options"] = "SAMEORIGIN"
                     response.headers["X-XSS-Protection"] = "1; mode=block"
                     response.headers["Access-Control-Allow-Origin"] = "*"
-                    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
+                    response.headers["Access-Control-Allow-Methods"] = (
+                        "GET, POST, PUT, DELETE, OPTIONS"
+                    )
                     response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
                     return response
                 except Exception as e:
                     self.logger.error(f"Error in after_request hook: {e}")
                     return response
-            
+
             hook_info = {
                 "event": "request_hooks_configured",
                 "timestamp": datetime.now().isoformat(),
-                "hooks": ["after_request"]
+                "hooks": ["after_request"],
             }
             self.logger.info(f"Request hooks configured: {json.dumps(hook_info)}")
-            
+
         except Exception as e:
             error_info = {
                 "event": "request_hooks_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             self.logger.error(f"Failed to setup request hooks: {json.dumps(error_info)}")
 
     def _setup_error_handlers(self):
         """Setup Flask error handlers with enhanced logging"""
         try:
+
             @self.app.errorhandler(404)
             def not_found(error):
                 error_info = {
@@ -327,10 +358,10 @@ class OrchDashboardRefactored:
                     "timestamp": datetime.now().isoformat(),
                     "path": request.path,
                     "method": request.method,
-                    "user_agent": request.headers.get("User-Agent", "Unknown")
+                    "user_agent": request.headers.get("User-Agent", "Unknown"),
                 }
                 self.logger.warning(f"404 error: {json.dumps(error_info)}")
-                
+
                 if request.path.startswith("/api/"):
                     return jsonify({"error": "API endpoint not found", "path": request.path}), 404
                 return render_template("orch_dashboard.html"), 404
@@ -343,80 +374,93 @@ class OrchDashboardRefactored:
                     "path": request.path,
                     "method": request.method,
                     "error": str(error),
-                    "traceback": traceback.format_exc()
+                    "traceback": traceback.format_exc(),
                 }
                 self.logger.error(f"Internal server error: {json.dumps(error_info)}")
-                
+
                 if request.path.startswith("/api/"):
-                    return jsonify({"error": "Internal server error", "timestamp": datetime.now().isoformat()}), 500
+                    return (
+                        jsonify(
+                            {
+                                "error": "Internal server error",
+                                "timestamp": datetime.now().isoformat(),
+                            }
+                        ),
+                        500,
+                    )
                 return render_template("orch_dashboard.html"), 500
 
             handler_info = {
                 "event": "error_handlers_configured",
                 "timestamp": datetime.now().isoformat(),
-                "handlers": ["404", "500"]
+                "handlers": ["404", "500"],
             }
             self.logger.info(f"Error handlers configured: {json.dumps(handler_info)}")
-            
+
         except Exception as e:
             error_info = {
                 "event": "error_handlers_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             self.logger.error(f"Failed to setup error handlers: {json.dumps(error_info)}")
 
     def _setup_minimal_routes(self):
         """Fallback minimal routes if blueprints fail"""
         fallback_start = time.time()
-        
+
         fallback_info = {
             "event": "minimal_routes_setup_start",
             "timestamp": datetime.now().isoformat(),
-            "reason": "Blueprint failures detected"
+            "reason": "Blueprint failures detected",
         }
         self.logger.warning(f"Setting up minimal fallback routes: {json.dumps(fallback_info)}")
-        
+
         try:
+
             @self.app.route("/")
             def index():
                 return render_template("orch_dashboard.html")
-            
+
             @self.app.route("/api/health")
             def api_health():
-                return jsonify({
-                    "status": "ok",
-                    "timestamp": datetime.now().isoformat(),
-                    "mode": "minimal_fallback",
-                    "blueprint_status": self.blueprint_status
-                })
-            
+                return jsonify(
+                    {
+                        "status": "ok",
+                        "timestamp": datetime.now().isoformat(),
+                        "mode": "minimal_fallback",
+                        "blueprint_status": self.blueprint_status,
+                    }
+                )
+
             @self.app.route("/api/status")
             def api_status():
-                return jsonify({
-                    "status": "degraded",
-                    "timestamp": datetime.now().isoformat(),
-                    "mode": "minimal_fallback",
-                    "message": "Running with minimal routes due to blueprint failures"
-                })
-            
+                return jsonify(
+                    {
+                        "status": "degraded",
+                        "timestamp": datetime.now().isoformat(),
+                        "mode": "minimal_fallback",
+                        "message": "Running with minimal routes due to blueprint failures",
+                    }
+                )
+
             fallback_duration = time.time() - fallback_start
             success_info = {
                 "event": "minimal_routes_setup_complete",
                 "timestamp": datetime.now().isoformat(),
                 "duration_seconds": round(fallback_duration, 3),
-                "routes_added": 3
+                "routes_added": 3,
             }
             self.logger.info(f"Minimal fallback routes configured: {json.dumps(success_info)}")
-            
+
         except Exception as e:
             error_info = {
                 "event": "minimal_routes_setup_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
                 "error_type": type(e).__name__,
-                "traceback": traceback.format_exc()
+                "traceback": traceback.format_exc(),
             }
             self.logger.error(f"Failed to setup minimal routes: {json.dumps(error_info)}")
             raise
@@ -428,15 +472,15 @@ class OrchDashboardRefactored:
             if not os.path.exists(tasks_file):
                 self.logger.warning(f"Tasks file not found: {tasks_file}")
                 return []
-            
+
             tasks = []
             with open(tasks_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # Parse table rows
             lines = content.split("\n")
             header_found = False
-            
+
             for line in lines:
                 if line.startswith("| task_id |"):
                     header_found = True
@@ -457,17 +501,17 @@ class OrchDashboardRefactored:
                             "lock_expires_at": parts[6],
                             "due": parts[7],
                             "artifact": parts[8],
-                            "notes": parts[9]
+                            "notes": parts[9],
                         }
                         tasks.append(task)
-            
+
             self.logger.info(f"Loaded {len(tasks)} tasks from {tasks_file}")
             return tasks
-            
+
         except Exception as e:
             self.logger.error(f"Error loading tasks data: {e}")
             return []
-    
+
     def _get_approvals_data(self):
         """Get approvals data from ORCH/STATE/APPROVALS.md"""
         try:
@@ -475,15 +519,15 @@ class OrchDashboardRefactored:
             if not os.path.exists(approvals_file):
                 self.logger.warning(f"Approvals file not found: {approvals_file}")
                 return []
-            
+
             approvals = []
             with open(approvals_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # Parse table rows
             lines = content.split("\n")
             header_found = False
-            
+
             for line in lines:
                 if line.startswith("| appr_id |"):
                     header_found = True
@@ -504,17 +548,17 @@ class OrchDashboardRefactored:
                             "approver_role": parts[6],
                             "ts_req": parts[7],
                             "ts_dec": parts[8],
-                            "evidence": parts[9]
+                            "evidence": parts[9],
                         }
                         approvals.append(approval)
-            
+
             self.logger.info(f"Loaded {len(approvals)} approvals from {approvals_file}")
             return approvals
-            
+
         except Exception as e:
             self.logger.error(f"Error loading approvals data: {e}")
             return []
-    
+
     def _get_milestones_data(self):
         """Get milestones data from ORCH/STATE/CURRENT_MILESTONE.md"""
         try:
@@ -522,64 +566,64 @@ class OrchDashboardRefactored:
             if not os.path.exists(milestone_file):
                 self.logger.warning(f"Milestone file not found: {milestone_file}")
                 return []
-            
+
             with open(milestone_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # Extract milestone information
             milestones = []
             lines = content.split("\n")
             current_milestone = {}
-            
+
             for line in lines:
                 if line.startswith("# "):
                     if current_milestone:
                         milestones.append(current_milestone)
                     current_milestone = {"title": line[2:].strip(), "status": "active"}
                 elif "進捗:" in line or "Progress:" in line:
-                    progress_match = re.search(r'(\d+)%', line)
+                    progress_match = re.search(r"(\d+)%", line)
                     if progress_match:
                         current_milestone["progress"] = int(progress_match.group(1))
                 elif "期限:" in line or "Due:" in line:
                     current_milestone["due"] = line.split(":", 1)[1].strip()
-            
+
             if current_milestone:
                 milestones.append(current_milestone)
-            
+
             self.logger.info(f"Loaded {len(milestones)} milestones from {milestone_file}")
             return milestones
-            
+
         except Exception as e:
             self.logger.error(f"Error loading milestones data: {e}")
             return []
-    
+
     def _get_quality_metrics(self):
         """Get quality metrics from actual data"""
         try:
             tasks = self._get_tasks_data()
             approvals = self._get_approvals_data()
-            
+
             # Calculate real metrics
             total_tasks = len(tasks)
             completed_tasks = len([t for t in tasks if t.get("status") == "DONE"])
             active_tasks = len([t for t in tasks if t.get("status") == "DOING"])
-            
+
             total_approvals = len(approvals)
             approved_count = len([a for a in approvals if a.get("status") == "approved"])
             pending_approvals = len([a for a in approvals if a.get("status") == "pending"])
-            
+
             task_completion_rate = completed_tasks / total_tasks if total_tasks > 0 else 0
             approval_rate = approved_count / total_approvals if total_approvals > 0 else 0
-            
+
             # Calculate system health score based on real data
             health_factors = [
                 task_completion_rate,
                 approval_rate,
                 1.0 if pending_approvals == 0 else max(0.5, 1.0 - (pending_approvals / 10)),
-                1.0 if active_tasks <= 3 else max(0.7, 1.0 - (active_tasks / 20))
+                1.0 if active_tasks <= 3 else max(0.7, 1.0 - (active_tasks / 20)),
             ]
             system_health_score = sum(health_factors) / len(health_factors)
-            
+
             metrics = {
                 "task_completion_rate": round(task_completion_rate, 3),
                 "approval_rate": round(approval_rate, 3),
@@ -588,12 +632,12 @@ class OrchDashboardRefactored:
                 "pending_approvals": pending_approvals,
                 "total_tasks": total_tasks,
                 "total_approvals": total_approvals,
-                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S")
+                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
             }
-            
+
             self.logger.info(f"Calculated quality metrics: {metrics}")
             return metrics
-            
+
         except Exception as e:
             self.logger.error(f"Error calculating quality metrics: {e}")
             return {
@@ -604,51 +648,53 @@ class OrchDashboardRefactored:
                 "pending_approvals": 0,
                 "total_tasks": 0,
                 "total_approvals": 0,
-                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S")
+                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
             }
-    
+
     def _get_system_health(self):
         """Get system health from actual data and system status"""
         try:
             quality_metrics = self._get_quality_metrics()
-            
+
             # Check file system health
             required_files = [
                 "ORCH/STATE/TASKS.md",
                 "ORCH/STATE/APPROVALS.md",
-                "ORCH/STATE/FLAGS.md"
+                "ORCH/STATE/FLAGS.md",
             ]
-            
+
             file_health = all(os.path.exists(f) for f in required_files)
-            
+
             # Calculate overall health
             health_score = quality_metrics.get("system_health_score", 0)
             if not file_health:
                 health_score *= 0.5  # Reduce health if files are missing
-            
-            status = "healthy" if health_score > 0.8 else "warning" if health_score > 0.5 else "critical"
-            
+
+            status = (
+                "healthy" if health_score > 0.8 else "warning" if health_score > 0.5 else "critical"
+            )
+
             health_data = {
                 "health": {
                     "health_score": round(health_score, 3),
                     "file_system_ok": file_health,
-                    "required_files_status": {f: os.path.exists(f) for f in required_files}
+                    "required_files_status": {f: os.path.exists(f) for f in required_files},
                 },
                 "status": status,
                 "metrics": quality_metrics,
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             self.logger.info(f"System health calculated: {status} (score: {health_score})")
             return health_data
-            
+
         except Exception as e:
             self.logger.error(f"Error calculating system health: {e}")
             return {
                 "health": {"health_score": 0.0, "file_system_ok": False},
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
 
     def get_system_status(self):
@@ -661,16 +707,12 @@ class OrchDashboardRefactored:
                 "version": "1.0.0-refactored",
                 "blueprint_status": self.blueprint_status,
                 "total_routes": len(list(self.app.url_map.iter_rules())),
-                "health_score": 0.95
+                "health_score": 0.95,
             }
             return status_info
         except Exception as e:
             self.logger.error(f"Failed to get system status: {str(e)}")
-            return {
-                "status": "error",
-                "timestamp": datetime.now().isoformat(),
-                "error": str(e)
-            }
+            return {"status": "error", "timestamp": datetime.now().isoformat(), "error": str(e)}
 
     def get_system_health(self):
         """Get system health for API routes"""
@@ -679,22 +721,22 @@ class OrchDashboardRefactored:
                 "health": "healthy",
                 "timestamp": datetime.now().isoformat(),
                 "checks": {
-                    "blueprints": "ok" if any(bp["status"] == "SUCCESS" for bp in self.blueprint_status.values()) else "warning",
+                    "blueprints": (
+                        "ok"
+                        if any(bp["status"] == "SUCCESS" for bp in self.blueprint_status.values())
+                        else "warning"
+                    ),
                     "routes": "ok" if len(list(self.app.url_map.iter_rules())) > 0 else "error",
                     "memory": "ok",
-                    "disk": "ok"
+                    "disk": "ok",
                 },
                 "health_score": 0.95,
-                "blueprint_status": self.blueprint_status
+                "blueprint_status": self.blueprint_status,
             }
             return health_info
         except Exception as e:
             self.logger.error(f"Failed to get system health: {str(e)}")
-            return {
-                "health": "unhealthy",
-                "timestamp": datetime.now().isoformat(),
-                "error": str(e)
-            }
+            return {"health": "unhealthy", "timestamp": datetime.now().isoformat(), "error": str(e)}
 
     def _initialize_style_manager(self):
         """Initialize the style management system"""
@@ -703,7 +745,7 @@ class OrchDashboardRefactored:
             style_info = {
                 "event": "style_manager_initialized",
                 "timestamp": datetime.now().isoformat(),
-                "status": "success"
+                "status": "success",
             }
             self.logger.info(f"Style manager initialized: {json.dumps(style_info)}")
         except Exception as e:
@@ -711,17 +753,17 @@ class OrchDashboardRefactored:
                 "event": "style_manager_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             self.logger.error(f"Style manager initialization failed: {json.dumps(error_info)}")
             # Don't raise - style manager is optional
-    
+
     def get_blueprint_status(self):
         """Get current blueprint status for monitoring"""
         return {
             "blueprint_status": self.blueprint_status,
             "total_routes": len(list(self.app.url_map.iter_rules())),
-            "timestamp": datetime.now().isoformat()
+            "timestamp": datetime.now().isoformat(),
         }
 
     def run(self, debug=False):
@@ -732,10 +774,10 @@ class OrchDashboardRefactored:
             "host": self.host,
             "port": self.port,
             "debug": debug,
-            "blueprint_status": self.blueprint_status
+            "blueprint_status": self.blueprint_status,
         }
         self.logger.info(f"Starting ORCH Dashboard (Refactored): {json.dumps(run_info)}")
-        
+
         try:
             self.app.run(host=self.host, port=self.port, debug=debug)
         except Exception as e:
@@ -744,11 +786,12 @@ class OrchDashboardRefactored:
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
                 "error_type": type(e).__name__,
-                "traceback": traceback.format_exc()
+                "traceback": traceback.format_exc(),
             }
             self.logger.error(f"Dashboard server failed to start: {json.dumps(error_info)}")
             raise
 
+
 if __name__ == "__main__":
     dashboard = OrchDashboardRefactored()
-    dashboard.run(debug=True)
\ No newline at end of file
+    dashboard.run(debug=True)
diff --git a/performance_fix.py b/performance_fix.py
index d0b7edb..d4b7ccc 100644
--- a/performance_fix.py
+++ b/performance_fix.py
@@ -3,36 +3,37 @@
 パフォーマンス問題の根本修正ツール
 """
 
-import re
 import os
+import re
 import shutil
 from datetime import datetime
 
+
 class PerformanceFixer:
     def __init__(self, dashboard_file: str):
         self.dashboard_file = dashboard_file
         self.backup_file = f"{dashboard_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
-        
+
     def create_backup(self):
         """バックアップ作成"""
         shutil.copy2(self.dashboard_file, self.backup_file)
         print(f"バックアップ作成: {self.backup_file}")
-        
+
     def fix_slow_imports(self, content: str) -> str:
         """遅いインポートの修正"""
         # 不要なインポートの削除
         unnecessary_imports = [
-            r'import matplotlib.*\n',
-            r'import seaborn.*\n',
-            r'import plotly.*\n',
-            r'from plotly.*\n',
-            r'import pandas.*\n',
-            r'from pandas.*\n'
+            r"import matplotlib.*\n",
+            r"import seaborn.*\n",
+            r"import plotly.*\n",
+            r"from plotly.*\n",
+            r"import pandas.*\n",
+            r"from pandas.*\n",
         ]
-        
+
         for pattern in unnecessary_imports:
-            content = re.sub(pattern, '', content)
-        
+            content = re.sub(pattern, "", content)
+
         # 遅延インポートの追加
         lazy_import_block = '''
 # 遅延インポート用の関数
@@ -62,33 +63,42 @@ pd = None
 plt = None
 sns = None
 '''
-        
+
         # インポートセクションの後に遅延インポートを追加
-        import_end = content.find('\nclass')
+        import_end = content.find("\nclass")
         if import_end != -1:
             content = content[:import_end] + lazy_import_block + content[import_end:]
-        
+
         return content
-    
+
     def fix_slow_initialization(self, content: str) -> str:
         """遅い初期化処理の修正"""
-        
+
         # __init__メソッドの最適化
         init_optimizations = [
             # 重い処理を遅延実行に変更
-            (r'(\s+)self\.setup_ml_components\(\)', r'\1# self.setup_ml_components()  # 遅延実行に変更'),
-            (r'(\s+)self\.initialize_monitoring\(\)', r'\1# self.initialize_monitoring()  # 遅延実行に変更'),
-            (r'(\s+)self\.load_historical_data\(\)', r'\1# self.load_historical_data()  # 遅延実行に変更'),
+            (
+                r"(\s+)self\.setup_ml_components\(\)",
+                r"\1# self.setup_ml_components()  # 遅延実行に変更",
+            ),
+            (
+                r"(\s+)self\.initialize_monitoring\(\)",
+                r"\1# self.initialize_monitoring()  # 遅延実行に変更",
+            ),
+            (
+                r"(\s+)self\.load_historical_data\(\)",
+                r"\1# self.load_historical_data()  # 遅延実行に変更",
+            ),
         ]
-        
+
         for pattern, replacement in init_optimizations:
             content = re.sub(pattern, replacement, content)
-        
+
         return content
-    
+
     def add_lazy_loading(self, content: str) -> str:
         """遅延ローディングの追加"""
-        
+
         lazy_loading_methods = '''
     def _ensure_ml_components(self):
         """ML コンポーネントの遅延初期化"""
@@ -110,36 +120,39 @@ sns = None
             self.load_historical_data()
             self._historical_data_loaded = True
 '''
-        
+
         # クラス定義の最後に遅延ローディングメソッドを追加
-        class_end = content.rfind('    def run(')
+        class_end = content.rfind("    def run(")
         if class_end != -1:
-            content = content[:class_end] + lazy_loading_methods + '\n' + content[class_end:]
-        
+            content = content[:class_end] + lazy_loading_methods + "\n" + content[class_end:]
+
         return content
-    
+
     def optimize_route_handlers(self, content: str) -> str:
         """ルートハンドラーの最適化"""
-        
+
         # 重い処理を含むルートの最適化
         route_optimizations = [
             # メインページの最適化
-            (r'(@app\.route\(\'/\'\)\s+def index\(\):.*?)return render_template', 
-             r'\1# 遅延ローディングの適用\n        self._ensure_monitoring()\n        return render_template'),
-            
+            (
+                r"(@app\.route\(\'/\'\)\s+def index\(\):.*?)return render_template",
+                r"\1# 遅延ローディングの適用\n        self._ensure_monitoring()\n        return render_template",
+            ),
             # API ステータスの最適化
-            (r'(@app\.route\(\'/api/status\'\)\s+def api_status\(\):.*?)(\s+)(.*?return jsonify)', 
-             r'\1\2# 軽量化されたステータス応答\n\2try:\n\2    status = {\n\2        "status": "running",\n\2        "timestamp": datetime.now().isoformat(),\n\2        "uptime": time.time() - self.start_time if hasattr(self, "start_time") else 0\n\2    }\n\2    \3'),
+            (
+                r"(@app\.route\(\'/api/status\'\)\s+def api_status\(\):.*?)(\s+)(.*?return jsonify)",
+                r'\1\2# 軽量化されたステータス応答\n\2try:\n\2    status = {\n\2        "status": "running",\n\2        "timestamp": datetime.now().isoformat(),\n\2        "uptime": time.time() - self.start_time if hasattr(self, "start_time") else 0\n\2    }\n\2    \3',
+            ),
         ]
-        
+
         for pattern, replacement in route_optimizations:
             content = re.sub(pattern, replacement, content, flags=re.DOTALL)
-        
+
         return content
-    
+
     def add_caching_decorators(self, content: str) -> str:
         """キャッシュデコレーターの追加"""
-        
+
         # キャッシュ設定の追加
         cache_config = '''
 # キャッシュ設定
@@ -168,89 +181,90 @@ def simple_cache(ttl=60):
         return wrapper
     return decorator
 '''
-        
+
         # インポートセクションの後にキャッシュ設定を追加
-        import_end = content.find('\nclass')
+        import_end = content.find("\nclass")
         if import_end != -1:
             content = content[:import_end] + cache_config + content[import_end:]
-        
+
         # 重いメソッドにキャッシュを適用
         cached_methods = [
-            (r'(\s+def get_system_status\(self\):)', r'\1\n    @simple_cache(ttl=30)'),
-            (r'(\s+def get_task_summary\(self\):)', r'\1\n    @simple_cache(ttl=60)'),
-            (r'(\s+def get_performance_metrics\(self\):)', r'\1\n    @simple_cache(ttl=120)'),
+            (r"(\s+def get_system_status\(self\):)", r"\1\n    @simple_cache(ttl=30)"),
+            (r"(\s+def get_task_summary\(self\):)", r"\1\n    @simple_cache(ttl=60)"),
+            (r"(\s+def get_performance_metrics\(self\):)", r"\1\n    @simple_cache(ttl=120)"),
         ]
-        
+
         for pattern, replacement in cached_methods:
             content = re.sub(pattern, replacement, content)
-        
+
         return content
-    
+
     def fix_database_queries(self, content: str) -> str:
         """データベースクエリの最適化"""
-        
+
         # 重いクエリの最適化
         query_optimizations = [
             # LIMIT句の追加
-            (r'SELECT \* FROM tasks', r'SELECT * FROM tasks LIMIT 100'),
-            (r'SELECT \* FROM approvals', r'SELECT * FROM approvals LIMIT 100'),
-            
+            (r"SELECT \* FROM tasks", r"SELECT * FROM tasks LIMIT 100"),
+            (r"SELECT \* FROM approvals", r"SELECT * FROM approvals LIMIT 100"),
             # インデックスヒントの追加
-            (r'ORDER BY created_at DESC', r'ORDER BY created_at DESC LIMIT 50'),
+            (r"ORDER BY created_at DESC", r"ORDER BY created_at DESC LIMIT 50"),
         ]
-        
+
         for pattern, replacement in query_optimizations:
             content = re.sub(pattern, replacement, content)
-        
+
         return content
-    
+
     def apply_all_fixes(self):
         """すべての修正を適用"""
         print("パフォーマンス修正を開始...")
-        
+
         # バックアップ作成
         self.create_backup()
-        
+
         # ファイル読み込み
-        with open(self.dashboard_file, 'r', encoding='utf-8') as f:
+        with open(self.dashboard_file, "r", encoding="utf-8") as f:
             content = f.read()
-        
+
         print("1. 遅いインポートの修正...")
         content = self.fix_slow_imports(content)
-        
+
         print("2. 初期化処理の最適化...")
         content = self.fix_slow_initialization(content)
-        
+
         print("3. 遅延ローディングの追加...")
         content = self.add_lazy_loading(content)
-        
+
         print("4. ルートハンドラーの最適化...")
         content = self.optimize_route_handlers(content)
-        
+
         print("5. キャッシュの追加...")
         content = self.add_caching_decorators(content)
-        
+
         print("6. データベースクエリの最適化...")
         content = self.fix_database_queries(content)
-        
+
         # 修正されたファイルを保存
-        with open(self.dashboard_file, 'w', encoding='utf-8') as f:
+        with open(self.dashboard_file, "w", encoding="utf-8") as f:
             f.write(content)
-        
+
         print(f"パフォーマンス修正完了: {self.dashboard_file}")
         print(f"バックアップ: {self.backup_file}")
 
+
 def main():
     dashboard_file = "orch_dashboard.py"
-    
+
     if not os.path.exists(dashboard_file):
         print(f"エラー: {dashboard_file} が見つかりません")
         return
-    
+
     fixer = PerformanceFixer(dashboard_file)
     fixer.apply_all_fixes()
-    
+
     print("\n修正完了！ダッシュボードを再起動してください。")
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/scripts/ops/check_port.py b/scripts/ops/check_port.py
index 5dd96be..4ced1d9 100644
--- a/scripts/ops/check_port.py
+++ b/scripts/ops/check_port.py
@@ -1,6 +1,6 @@
 import socket
-import sys
 import subprocess
+import sys
 
 
 def is_port_in_use(port: int) -> bool:
@@ -22,7 +22,7 @@ def show_netstat(port: int) -> None:
             "-NoLogo",
             "-NoProfile",
             "-Command",
-            f"netstat -ano | Select-String -Pattern ':{port}\\s'"
+            f"netstat -ano | Select-String -Pattern ':{port}\\s'",
         ]
         out = subprocess.check_output(cmd, text=True)
         print(out)
@@ -42,4 +42,4 @@ def main():
 
 
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/scripts/ops/gen_root_cause_card.py b/scripts/ops/gen_root_cause_card.py
index bcb8726..d32bbcb 100644
--- a/scripts/ops/gen_root_cause_card.py
+++ b/scripts/ops/gen_root_cause_card.py
@@ -14,8 +14,8 @@ Intended to be called from CI after tests. Safe to run locally.
 from __future__ import annotations
 
 import os
-import sys
 import subprocess
+import sys
 from datetime import datetime
 from pathlib import Path
 from typing import Tuple
@@ -72,6 +72,15 @@ def main() -> int:
     summary = get_git_summary()
     unified = get_unified_diff()
 
+    # Front-matter fields
+    code, sha_in, _ = run(["git", "rev-parse", "origin/main"])
+    if code != 0:
+        sha_in = "unknown"
+    code, sha_out, _ = run(["git", "rev-parse", "HEAD"])
+    if code != 0:
+        sha_out = "unknown"
+    task_id = os.environ.get("TASK_ID", "ui-audit-p0")
+
     # UI-Audit pointers: these paths should match CI artifacts and local reports
     ui_artifacts = [
         "artifacts/ui_audit/",  # CI uploaded artifacts
@@ -81,6 +90,19 @@ def main() -> int:
     ]
 
     content = f"""
+---
+task_id: {task_id}
+sha_in: {sha_in}
+sha_out: {sha_out}
+metrics:
+  lighthouse: pending_CI
+  lcp: pending_CI
+  cls: pending_CI
+  linkinator_404: pending_CI
+  playwright_tests: pending_CI
+rollback_cmd: "git revert {sha_out}"
+---
+
 Accountability Card (Root Cause & Rollback)
 
 - Branch: {branch}
diff --git a/scripts/profile_app.py b/scripts/profile_app.py
index 798aaca..2fee162 100644
--- a/scripts/profile_app.py
+++ b/scripts/profile_app.py
@@ -3,12 +3,12 @@
 アプリケーションパフォーマンスプロファイリングスクリプト
 """
 
-import sys
-import os
-import time
 import cProfile
-import pstats
 import io
+import os
+import pstats
+import sys
+import time
 from pathlib import Path
 
 # プロジェクトルートをパスに追加
@@ -17,62 +17,63 @@ sys.path.insert(0, str(project_root))
 
 from src.performance_profiler import PerformanceProfiler, ResourceMonitor
 
+
 def profile_dashboard():
     """ダッシュボードアプリケーションをプロファイリング"""
     print("=== ダッシュボードアプリケーションプロファイリング ===")
-    
+
     # プロファイラーを初期化
     profiler = PerformanceProfiler()
-    
+
     # リソースモニターを開始
     monitor = ResourceMonitor()
     monitor.start_monitoring()
-    
+
     try:
         # ダッシュボードアプリケーションをインポート
         import orch_dashboard
-        
+
         # プロファイリング開始
         profiler.start_profiling()
-        
+
         # 短時間実行してプロファイリング
         print("プロファイリング中... (10秒)")
         time.sleep(10)
-        
+
         # プロファイリング終了
         profile_stats = profiler.stop_profiling()
         memory_stats = profiler.get_memory_stats()
-        
+
         # 結果を保存
         results_dir = project_root / "data" / "profiling"
         results_dir.mkdir(parents=True, exist_ok=True)
-        
+
         # プロファイル結果を保存
         with open(results_dir / "dashboard_profile.txt", "w", encoding="utf-8") as f:
             f.write("=== CPU プロファイリング結果 ===\n")
             f.write(f"総実行時間: {profile_stats['total_time']:.4f}秒\n")
             f.write(f"関数呼び出し数: {profile_stats['function_calls']}\n")
             f.write(f"プリミティブ呼び出し数: {profile_stats['primitive_calls']}\n\n")
-            
+
             f.write("=== トップ関数 (累積時間順) ===\n")
-            for func_info in profile_stats['top_functions']:
+            for func_info in profile_stats["top_functions"]:
                 f.write(f"{func_info}\n")
-            
+
             f.write("\n=== メモリ使用量統計 ===\n")
             f.write(f"現在のメモリ使用量: {memory_stats['current_memory']:.2f} MB\n")
             f.write(f"ピークメモリ使用量: {memory_stats['peak_memory']:.2f} MB\n")
-            
+
             f.write("\n=== トップメモリ使用箇所 ===\n")
-            for mem_info in memory_stats['top_memory']:
+            for mem_info in memory_stats["top_memory"]:
                 f.write(f"{mem_info}\n")
-        
+
         print(f"プロファイリング結果を保存: {results_dir / 'dashboard_profile.txt'}")
-        
+
     except Exception as e:
         print(f"プロファイリングエラー: {e}")
     finally:
         monitor.stop_monitoring()
-        
+
         # リソース使用量レポート
         resource_stats = monitor.get_stats()
         print("\n=== リソース使用量統計 ===")
@@ -80,49 +81,51 @@ def profile_dashboard():
         print(f"平均メモリ使用率: {resource_stats['avg_memory']:.1f}%")
         print(f"ピークメモリ使用量: {resource_stats['peak_memory']:.1f} MB")
 
+
 def analyze_slow_endpoints():
     """遅いエンドポイントを分析"""
     print("\n=== エンドポイント応答時間分析 ===")
-    
-    import requests
+
     import statistics
-    
+
+    import requests
+
     endpoints = [
         "http://localhost:5000/",
         "http://localhost:5000/api/status",
         "http://localhost:5000/security",
         "http://localhost:5000/api/security/users",
     ]
-    
+
     results = {}
-    
+
     for endpoint in endpoints:
         print(f"分析中: {endpoint}")
         times = []
-        
+
         for i in range(20):
             try:
                 start_time = time.time()
                 response = requests.get(endpoint, timeout=5)
                 end_time = time.time()
-                
+
                 if response.status_code == 200:
                     times.append(end_time - start_time)
                 else:
                     print(f"  エラー応答: {response.status_code}")
-                    
+
             except Exception as e:
                 print(f"  リクエストエラー: {e}")
-        
+
         if times:
             results[endpoint] = {
-                'avg': statistics.mean(times),
-                'median': statistics.median(times),
-                'p95': statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times),
-                'min': min(times),
-                'max': max(times)
+                "avg": statistics.mean(times),
+                "median": statistics.median(times),
+                "p95": statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times),
+                "min": min(times),
+                "max": max(times),
             }
-    
+
     # 結果を表示
     print("\n=== エンドポイント応答時間結果 ===")
     for endpoint, stats in results.items():
@@ -132,13 +135,13 @@ def analyze_slow_endpoints():
         print(f"  P95: {stats['p95']*1000:.1f}ms")
         print(f"  最小: {stats['min']*1000:.1f}ms")
         print(f"  最大: {stats['max']*1000:.1f}ms")
-    
+
     # 遅いエンドポイントを特定
     slow_endpoints = []
     for endpoint, stats in results.items():
-        if stats['p95'] > 0.5:  # 500ms以上
-            slow_endpoints.append((endpoint, stats['p95']))
-    
+        if stats["p95"] > 0.5:  # 500ms以上
+            slow_endpoints.append((endpoint, stats["p95"]))
+
     if slow_endpoints:
         print("\n=== 最適化が必要なエンドポイント ===")
         for endpoint, p95_time in sorted(slow_endpoints, key=lambda x: x[1], reverse=True):
@@ -146,29 +149,32 @@ def analyze_slow_endpoints():
     else:
         print("\n全エンドポイントが良好なパフォーマンスです。")
 
+
 def main():
     """メイン実行関数"""
     print("アプリケーションパフォーマンス分析を開始...")
-    
+
     # ダッシュボードが実行中かチェック
     try:
         import requests
+
         response = requests.get("http://localhost:5000/api/status", timeout=2)
         if response.status_code == 200:
             print("ダッシュボードが実行中です。分析を開始します。")
-            
+
             # エンドポイント分析
             analyze_slow_endpoints()
-            
+
             # プロファイリング（注意：これは実際のアプリケーションには影響しません）
             print("\n注意: 詳細なプロファイリングには別途設定が必要です。")
-            
+
         else:
             print("ダッシュボードが応答しません。先にダッシュボードを起動してください。")
-            
+
     except Exception as e:
         print(f"ダッシュボード接続エラー: {e}")
         print("先にダッシュボードを起動してください: python orch_dashboard.py")
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/src/advanced_optimizer.py b/src/advanced_optimizer.py
index 142b7fd..bac1ae857 100644
--- a/src/advanced_optimizer.py
+++ b/src/advanced_optimizer.py
@@ -3,39 +3,42 @@
 高度なパフォーマンス最適化ツール
 """
 
-import os
-import sys
-import time
 import json
 import logging
+import os
+import sys
 import threading
-from pathlib import Path
-from typing import Dict, List, Any, Optional
-from datetime import datetime
+import time
 from concurrent.futures import ThreadPoolExecutor
+from datetime import datetime
+from pathlib import Path
+from typing import Any, Dict, List, Optional
 
 # プロジェクトルートをパスに追加
 project_root = Path(__file__).parent.parent
 sys.path.insert(0, str(project_root))
 
+
 class AdvancedOptimizer:
     """高度な最適化クラス"""
-    
+
     def __init__(self):
         self.logger = logging.getLogger(__name__)
         self.optimizations_applied = []
-        
+
     def optimize_dashboard_routes(self, dashboard_file: str) -> bool:
         """ダッシュボードルートの最適化"""
         try:
-            with open(dashboard_file, 'r', encoding='utf-8') as f:
+            with open(dashboard_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # バックアップ作成
-            backup_file = f"{dashboard_file}.backup_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
-            with open(backup_file, 'w', encoding='utf-8') as f:
+            backup_file = (
+                f"{dashboard_file}.backup_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
+            )
+            with open(backup_file, "w", encoding="utf-8") as f:
                 f.write(content)
-            
+
             # 最適化されたルート実装
             optimized_routes = '''
         @self.app.route('/api/status')
@@ -73,51 +76,54 @@ class AdvancedOptimizer:
                 self.logger.error(f"Dashboard error: {e}")
                 return f"Dashboard Error: {e}", 500
 '''
-            
+
             # 既存のルート定義を最適化版に置換
-            lines = content.split('\n')
+            lines = content.split("\n")
             new_lines = []
             skip_until_next_route = False
-            
+
             for i, line in enumerate(lines):
-                if '@self.app.route(\'/api/status\')' in line:
+                if "@self.app.route('/api/status')" in line:
                     # 既存のapi/statusルートをスキップして最適化版を挿入
                     new_lines.append(optimized_routes)
                     skip_until_next_route = True
                     continue
-                elif '@self.app.route(\'/\')' in line and 'dashboard' in lines[i+1:i+5]:
+                elif "@self.app.route('/')" in line and "dashboard" in lines[i + 1 : i + 5]:
                     # 既存のメインダッシュボードルートをスキップ
                     skip_until_next_route = True
                     continue
-                elif skip_until_next_route and (line.strip().startswith('@self.app.route') or 
-                                               line.strip().startswith('def ') and 'self' not in line):
+                elif skip_until_next_route and (
+                    line.strip().startswith("@self.app.route")
+                    or line.strip().startswith("def ")
+                    and "self" not in line
+                ):
                     # 次のルートまたは関数に到達したらスキップ終了
                     skip_until_next_route = False
                     new_lines.append(line)
                 elif not skip_until_next_route:
                     new_lines.append(line)
-            
+
             # 最適化されたファイルを保存
-            with open(dashboard_file, 'w', encoding='utf-8') as f:
-                f.write('\n'.join(new_lines))
-            
+            with open(dashboard_file, "w", encoding="utf-8") as f:
+                f.write("\n".join(new_lines))
+
             self.logger.info(f"ルート最適化を適用: {dashboard_file}")
             self.logger.info(f"バックアップ: {backup_file}")
-            
+
             return True
-            
+
         except Exception as e:
             self.logger.error(f"ルート最適化エラー: {e}")
             return False
-    
+
     def add_performance_middleware(self, dashboard_file: str) -> bool:
         """パフォーマンス監視ミドルウェアの追加"""
         try:
-            with open(dashboard_file, 'r', encoding='utf-8') as f:
+            with open(dashboard_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # ミドルウェアコードの追加
-            middleware_code = '''
+            middleware_code = """
         # パフォーマンス監視ミドルウェア
         @self.app.before_request
         def before_request():
@@ -130,40 +136,39 @@ class AdvancedOptimizer:
                 if duration > 1.0:  # 1秒以上の場合ログ出力
                     self.logger.warning(f"Slow request: {request.path} took {duration:.2f}s")
             return response
-'''
-            
+"""
+
             # インポート追加
-            if 'from flask import g' not in content:
-                content = content.replace('from flask import', 'from flask import g,')
-            
-            if 'import time' not in content:
-                content = 'import time\n' + content
-            
+            if "from flask import g" not in content:
+                content = content.replace("from flask import", "from flask import g,")
+
+            if "import time" not in content:
+                content = "import time\n" + content
+
             # ミドルウェアを_setup_routesメソッドの最初に追加
             content = content.replace(
-                'def _setup_routes(self):',
-                f'def _setup_routes(self):{middleware_code}'
+                "def _setup_routes(self):", f"def _setup_routes(self):{middleware_code}"
             )
-            
+
             # ファイル保存
-            with open(dashboard_file, 'w', encoding='utf-8') as f:
+            with open(dashboard_file, "w", encoding="utf-8") as f:
                 f.write(content)
-            
+
             self.logger.info("パフォーマンス監視ミドルウェアを追加")
             return True
-            
+
         except Exception as e:
             self.logger.error(f"ミドルウェア追加エラー: {e}")
             return False
-    
+
     def optimize_template_rendering(self) -> Dict[str, Any]:
         """テンプレートレンダリング最適化"""
         template_dir = Path("templates")
         if not template_dir.exists():
             template_dir.mkdir(parents=True)
-        
+
         # 軽量なダッシュボードテンプレート
-        dashboard_template = '''<!DOCTYPE html>
+        dashboard_template = """<!DOCTYPE html>
 <html lang="ja">
 <head>
     <meta charset="UTF-8">
@@ -199,100 +204,94 @@ class AdvancedOptimizer:
         </div>
     </div>
 </body>
-</html>'''
-        
+</html>"""
+
         # テンプレートファイル作成
         template_file = template_dir / "dashboard.html"
-        with open(template_file, 'w', encoding='utf-8') as f:
+        with open(template_file, "w", encoding="utf-8") as f:
             f.write(dashboard_template)
-        
-        return {
-            "template_created": str(template_file),
-            "optimization": "lightweight_template"
-        }
-    
+
+        return {"template_created": str(template_file), "optimization": "lightweight_template"}
+
     def apply_all_optimizations(self, dashboard_file: str = "orch_dashboard.py") -> Dict[str, Any]:
         """全ての最適化を適用"""
         results = {
             "timestamp": datetime.now().isoformat(),
             "optimizations": [],
             "success": True,
-            "errors": []
+            "errors": [],
         }
-        
+
         try:
             # 1. テンプレート最適化
             template_result = self.optimize_template_rendering()
-            results["optimizations"].append({
-                "type": "template_optimization",
-                "result": template_result,
-                "success": True
-            })
-            
+            results["optimizations"].append(
+                {"type": "template_optimization", "result": template_result, "success": True}
+            )
+
             # 2. ルート最適化
             route_success = self.optimize_dashboard_routes(dashboard_file)
-            results["optimizations"].append({
-                "type": "route_optimization", 
-                "success": route_success
-            })
-            
+            results["optimizations"].append(
+                {"type": "route_optimization", "success": route_success}
+            )
+
             # 3. ミドルウェア追加
             middleware_success = self.add_performance_middleware(dashboard_file)
-            results["optimizations"].append({
-                "type": "middleware_optimization",
-                "success": middleware_success
-            })
-            
+            results["optimizations"].append(
+                {"type": "middleware_optimization", "success": middleware_success}
+            )
+
             # 成功判定
             results["success"] = all(opt.get("success", False) for opt in results["optimizations"])
-            
+
         except Exception as e:
             results["success"] = False
             results["errors"].append(str(e))
             self.logger.error(f"最適化適用エラー: {e}")
-        
+
         return results
 
+
 def main():
     """メイン実行関数"""
     optimizer = AdvancedOptimizer()
-    
+
     # ログ設定
-    logging.basicConfig(
-        level=logging.INFO,
-        format='%(asctime)s - %(levelname)s - %(message)s'
-    )
-    
+    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
+
     print("=== 高度なパフォーマンス最適化 ===")
-    
+
     # 全最適化を適用
     results = optimizer.apply_all_optimizations()
-    
+
     # 結果保存
     results_dir = Path("data/optimization")
     results_dir.mkdir(parents=True, exist_ok=True)
-    
-    results_file = results_dir / f"advanced_optimization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
-    with open(results_file, 'w', encoding='utf-8') as f:
+
+    results_file = (
+        results_dir / f"advanced_optimization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
+    )
+    with open(results_file, "w", encoding="utf-8") as f:
         json.dump(results, f, indent=2, ensure_ascii=False)
-    
+
     print(f"最適化結果: {results_file}")
-    
+
     # サマリー表示
     print(f"\n=== 最適化サマリー ===")
     print(f"全体成功: {'✓' if results['success'] else '✗'}")
     print(f"適用数: {len(results['optimizations'])}")
-    
-    for opt in results['optimizations']:
-        status = '✓' if opt['success'] else '✗'
+
+    for opt in results["optimizations"]:
+        status = "✓" if opt["success"] else "✗"
         print(f"{status} {opt['type']}")
-    
-    if results['errors']:
+
+    if results["errors"]:
         print(f"\nエラー:")
-        for error in results['errors']:
+        for error in results["errors"]:
             print(f"- {error}")
-    
+
     print(f"\n次のステップ: ダッシュボードを再起動してください")
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/src/alert_enhancer.py b/src/alert_enhancer.py
index dc0b33e..f78e457 100644
--- a/src/alert_enhancer.py
+++ b/src/alert_enhancer.py
@@ -5,19 +5,21 @@
 
 import json
 import logging
+import smtplib
 import time
 from datetime import datetime, timedelta
-from typing import Dict, List, Optional, Any
-from pathlib import Path
+from email.mime.multipart import MIMEMultipart
+from email.mime.text import MIMEText
 from enum import Enum
-import smtplib
+from pathlib import Path
+from typing import Any, Dict, List, Optional
+
 import requests
-from email.mime.text import MIMEText
-from email.mime.multipart import MIMEMultipart
 
 
 class AlertSeverity(Enum):
     """アラート重要度"""
+
     LOW = "low"
     MEDIUM = "medium"
     HIGH = "high"
@@ -26,6 +28,7 @@ class AlertSeverity(Enum):
 
 class AlertCategory(Enum):
     """アラートカテゴリ"""
+
     PERFORMANCE = "performance"
     QUALITY = "quality"
     SECURITY = "security"
@@ -35,6 +38,7 @@ class AlertCategory(Enum):
 
 class NotificationChannel(Enum):
     """通知チャンネル"""
+
     EMAIL = "email"
     WEBHOOK = "webhook"
     DASHBOARD = "dashboard"
@@ -44,14 +48,14 @@ class NotificationChannel(Enum):
 
 class AlertEnhancer:
     """強化されたアラート管理システム"""
-    
+
     def __init__(self, config_path: str = "config/alert_config.json"):
         self.config_path = Path(config_path)
         self.config = self._load_config()
         self.logger = self._setup_logging()
         self.alert_history = []
         self.suppressed_alerts = {}
-        
+
     def _load_config(self) -> Dict:
         """設定ファイル読み込み"""
         default_config = {
@@ -60,7 +64,7 @@ class AlertEnhancer:
                 "memory_usage": {"medium": 75, "high": 90, "critical": 98},
                 "disk_usage": {"medium": 80, "high": 90, "critical": 95},
                 "error_rate": {"medium": 0.05, "high": 0.1, "critical": 0.2},
-                "response_time": {"medium": 1.0, "high": 3.0, "critical": 5.0}
+                "response_time": {"medium": 1.0, "high": 3.0, "critical": 5.0},
             },
             "notification_channels": {
                 "email": {
@@ -69,88 +73,90 @@ class AlertEnhancer:
                     "smtp_port": 587,
                     "username": "alerts@example.com",
                     "password": "CHANGEME",
-                    "recipients": ["admin@example.com"]
+                    "recipients": ["admin@example.com"],
                 },
                 "webhook": {
                     "enabled": True,
                     "url": "https://hooks.slack.com/services/CHANGEME",
-                    "timeout": 10
+                    "timeout": 10,
                 },
-                "dashboard": {
-                    "enabled": True,
-                    "endpoint": "http://localhost:5000/api/alerts"
-                }
+                "dashboard": {"enabled": True, "endpoint": "http://localhost:5000/api/alerts"},
             },
             "alert_rules": {
                 "suppression_window": 300,  # 5分
-                "escalation_delay": 900,    # 15分
+                "escalation_delay": 900,  # 15分
                 "max_alerts_per_hour": 50,
-                "cooldown_period": 60       # 1分
+                "cooldown_period": 60,  # 1分
             },
             "business_hours": {
                 "start": "09:00",
                 "end": "18:00",
                 "timezone": "Asia/Tokyo",
-                "weekdays_only": True
-            }
+                "weekdays_only": True,
+            },
         }
-        
+
         if self.config_path.exists():
             try:
-                with open(self.config_path, 'r', encoding='utf-8') as f:
+                with open(self.config_path, "r", encoding="utf-8") as f:
                     loaded_config = json.load(f)
                     # デフォルト設定とマージ
                     default_config.update(loaded_config)
             except Exception as e:
                 logging.warning(f"設定ファイル読み込みエラー: {e}")
-        
+
         return default_config
-    
+
     def _setup_logging(self) -> logging.Logger:
         """ログ設定"""
         logger = logging.getLogger("AlertEnhancer")
         logger.setLevel(logging.INFO)
-        
+
         if not logger.handlers:
             handler = logging.StreamHandler()
-            formatter = logging.Formatter(
-                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
-            )
+            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
             handler.setFormatter(formatter)
             logger.addHandler(handler)
-        
+
         return logger
-    
+
     def classify_alert(self, alert: Dict) -> Dict:
         """アラート分類と重要度判定"""
         alert_type = alert.get("type", "unknown")
         metric = alert.get("metric", "")
         value = alert.get("value", 0)
-        
+
         # カテゴリ判定
         category = self._determine_category(alert_type, metric)
-        
+
         # 重要度判定
         severity = self._determine_severity(metric, value, alert.get("severity"))
-        
+
         # 拡張情報追加
         enhanced_alert = alert.copy()
-        enhanced_alert.update({
-            "category": category.value,
-            "severity": severity.value,
-            "timestamp": datetime.now().isoformat(),
-            "alert_id": f"{alert_type}_{int(time.time())}",
-            "business_impact": self._assess_business_impact(category, severity),
-            "recommended_action": self._get_recommended_action(alert_type, severity)
-        })
-        
+        enhanced_alert.update(
+            {
+                "category": category.value,
+                "severity": severity.value,
+                "timestamp": datetime.now().isoformat(),
+                "alert_id": f"{alert_type}_{int(time.time())}",
+                "business_impact": self._assess_business_impact(category, severity),
+                "recommended_action": self._get_recommended_action(alert_type, severity),
+            }
+        )
+
         return enhanced_alert
-    
+
     def _determine_category(self, alert_type: str, metric: str) -> AlertCategory:
         """アラートカテゴリ判定"""
-        if any(keyword in alert_type.lower() for keyword in ["cpu", "memory", "disk", "network", "performance"]):
+        if any(
+            keyword in alert_type.lower()
+            for keyword in ["cpu", "memory", "disk", "network", "performance"]
+        ):
             return AlertCategory.PERFORMANCE
-        elif any(keyword in alert_type.lower() for keyword in ["coverage", "complexity", "quality"]):
+        elif any(
+            keyword in alert_type.lower() for keyword in ["coverage", "complexity", "quality"]
+        ):
             return AlertCategory.QUALITY
         elif any(keyword in alert_type.lower() for keyword in ["security", "auth", "permission"]):
             return AlertCategory.SECURITY
@@ -158,26 +164,28 @@ class AlertEnhancer:
             return AlertCategory.SYSTEM
         else:
             return AlertCategory.BUSINESS
-    
-    def _determine_severity(self, metric: str, value: float, current_severity: str = None) -> AlertSeverity:
+
+    def _determine_severity(
+        self, metric: str, value: float, current_severity: str = None
+    ) -> AlertSeverity:
         """重要度判定"""
         if current_severity:
             try:
                 return AlertSeverity(current_severity.lower())
             except ValueError:
                 pass
-        
+
         thresholds = self.config["severity_thresholds"].get(metric, {})
-        
-        if value >= thresholds.get("critical", float('inf')):
+
+        if value >= thresholds.get("critical", float("inf")):
             return AlertSeverity.CRITICAL
-        elif value >= thresholds.get("high", float('inf')):
+        elif value >= thresholds.get("high", float("inf")):
             return AlertSeverity.HIGH
-        elif value >= thresholds.get("medium", float('inf')):
+        elif value >= thresholds.get("medium", float("inf")):
             return AlertSeverity.MEDIUM
         else:
             return AlertSeverity.LOW
-    
+
     def _assess_business_impact(self, category: AlertCategory, severity: AlertSeverity) -> str:
         """ビジネス影響度評価"""
         impact_matrix = {
@@ -185,11 +193,11 @@ class AlertEnhancer:
             (AlertCategory.PERFORMANCE, AlertSeverity.HIGH): "ユーザー体験の大幅な劣化",
             (AlertCategory.QUALITY, AlertSeverity.CRITICAL): "品質基準の重大な違反",
             (AlertCategory.SECURITY, AlertSeverity.CRITICAL): "セキュリティ侵害の可能性",
-            (AlertCategory.SYSTEM, AlertSeverity.CRITICAL): "システム障害の可能性"
+            (AlertCategory.SYSTEM, AlertSeverity.CRITICAL): "システム障害の可能性",
         }
-        
+
         return impact_matrix.get((category, severity), "軽微な影響")
-    
+
     def _get_recommended_action(self, alert_type: str, severity: AlertSeverity) -> str:
         """推奨アクション"""
         actions = {
@@ -197,56 +205,55 @@ class AlertEnhancer:
             "performance_memory_high": "メモリリークの確認とガベージコレクションの実行",
             "performance_disk_high": "不要ファイルの削除とディスク容量の拡張",
             "quality_coverage_low": "テストカバレッジの向上とテストケースの追加",
-            "security_auth_failed": "認証ログの確認と不正アクセスの調査"
+            "security_auth_failed": "認証ログの確認と不正アクセスの調査",
         }
-        
+
         base_action = actions.get(alert_type, "詳細な調査と適切な対応")
-        
+
         if severity == AlertSeverity.CRITICAL:
             return f"緊急対応: {base_action}"
         elif severity == AlertSeverity.HIGH:
             return f"優先対応: {base_action}"
         else:
             return base_action
-    
+
     def should_suppress_alert(self, alert: Dict) -> bool:
         """アラート抑制判定"""
         alert_key = f"{alert.get('type')}_{alert.get('metric')}"
         current_time = time.time()
-        
+
         # 抑制ウィンドウ内の同じアラートをチェック
         if alert_key in self.suppressed_alerts:
             last_sent = self.suppressed_alerts[alert_key]
             suppression_window = self.config["alert_rules"]["suppression_window"]
-            
+
             if current_time - last_sent < suppression_window:
                 return True
-        
+
         # 時間あたりのアラート数制限
         recent_alerts = [
-            a for a in self.alert_history 
-            if current_time - a.get("timestamp_unix", 0) < 3600
+            a for a in self.alert_history if current_time - a.get("timestamp_unix", 0) < 3600
         ]
-        
+
         max_alerts = self.config["alert_rules"]["max_alerts_per_hour"]
         if len(recent_alerts) >= max_alerts:
             return True
-        
+
         return False
-    
+
     def send_enhanced_alert(self, alert: Dict) -> bool:
         """強化されたアラート送信"""
         # アラート分類
         enhanced_alert = self.classify_alert(alert)
-        
+
         # 抑制チェック
         if self.should_suppress_alert(enhanced_alert):
             self.logger.info(f"アラート抑制: {enhanced_alert.get('alert_id')}")
             return False
-        
+
         # 通知チャンネル決定
         channels = self._select_notification_channels(enhanced_alert)
-        
+
         success = True
         for channel in channels:
             try:
@@ -256,51 +263,51 @@ class AlertEnhancer:
                     self._send_webhook_alert(enhanced_alert)
                 elif channel == NotificationChannel.DASHBOARD:
                     self._send_dashboard_alert(enhanced_alert)
-                
+
                 self.logger.info(f"アラート送信成功: {channel.value}")
             except Exception as e:
                 self.logger.error(f"アラート送信失敗 ({channel.value}): {e}")
                 success = False
-        
+
         # 履歴記録
         enhanced_alert["timestamp_unix"] = time.time()
         self.alert_history.append(enhanced_alert)
-        
+
         # 抑制記録更新
         alert_key = f"{enhanced_alert.get('type')}_{enhanced_alert.get('metric')}"
         self.suppressed_alerts[alert_key] = time.time()
-        
+
         return success
-    
+
     def _select_notification_channels(self, alert: Dict) -> List[NotificationChannel]:
         """通知チャンネル選択"""
         severity = AlertSeverity(alert.get("severity", "low"))
         channels = []
-        
+
         # 重要度に応じたチャンネル選択
         if severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
             channels.extend([NotificationChannel.EMAIL, NotificationChannel.WEBHOOK])
-        
+
         if severity != AlertSeverity.LOW:
             channels.append(NotificationChannel.DASHBOARD)
-        
+
         # 設定で有効なチャンネルのみ
         enabled_channels = []
         for channel in channels:
             if self.config["notification_channels"].get(channel.value, {}).get("enabled", False):
                 enabled_channels.append(channel)
-        
+
         return enabled_channels
-    
+
     def _send_email_alert(self, alert: Dict) -> None:
         """メールアラート送信"""
         email_config = self.config["notification_channels"]["email"]
-        
+
         msg = MIMEMultipart()
-        msg['From'] = email_config["username"]
-        msg['To'] = ", ".join(email_config["recipients"])
-        msg['Subject'] = f"[{alert['severity'].upper()}] {alert['message']}"
-        
+        msg["From"] = email_config["username"]
+        msg["To"] = ", ".join(email_config["recipients"])
+        msg["Subject"] = f"[{alert['severity'].upper()}] {alert['message']}"
+
         body = f"""
 アラート詳細:
 - ID: {alert['alert_id']}
@@ -313,99 +320,103 @@ class AlertEnhancer:
 
 詳細な調査を行ってください。
         """
-        
-        msg.attach(MIMEText(body, 'plain', 'utf-8'))
-        
+
+        msg.attach(MIMEText(body, "plain", "utf-8"))
+
         with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
             server.starttls()
             server.login(email_config["username"], email_config["password"])
             server.send_message(msg)
-    
+
     def _send_webhook_alert(self, alert: Dict) -> None:
         """Webhookアラート送信"""
         webhook_config = self.config["notification_channels"]["webhook"]
-        
+
         payload = {
             "text": f"[{alert['severity'].upper()}] {alert['message']}",
-            "attachments": [{
-                "color": self._get_alert_color(alert['severity']),
-                "fields": [
-                    {"title": "カテゴリ", "value": alert['category'], "short": True},
-                    {"title": "重要度", "value": alert['severity'], "short": True},
-                    {"title": "ビジネス影響", "value": alert['business_impact'], "short": False},
-                    {"title": "推奨アクション", "value": alert['recommended_action'], "short": False}
-                ],
-                "timestamp": alert['timestamp']
-            }]
+            "attachments": [
+                {
+                    "color": self._get_alert_color(alert["severity"]),
+                    "fields": [
+                        {"title": "カテゴリ", "value": alert["category"], "short": True},
+                        {"title": "重要度", "value": alert["severity"], "short": True},
+                        {
+                            "title": "ビジネス影響",
+                            "value": alert["business_impact"],
+                            "short": False,
+                        },
+                        {
+                            "title": "推奨アクション",
+                            "value": alert["recommended_action"],
+                            "short": False,
+                        },
+                    ],
+                    "timestamp": alert["timestamp"],
+                }
+            ],
         }
-        
+
         response = requests.post(
-            webhook_config["url"],
-            json=payload,
-            timeout=webhook_config.get("timeout", 10)
+            webhook_config["url"], json=payload, timeout=webhook_config.get("timeout", 10)
         )
         response.raise_for_status()
-    
+
     def _send_dashboard_alert(self, alert: Dict) -> None:
         """ダッシュボードアラート送信"""
         dashboard_config = self.config["notification_channels"]["dashboard"]
-        
-        response = requests.post(
-            dashboard_config["endpoint"],
-            json=alert,
-            timeout=10
-        )
+
+        response = requests.post(dashboard_config["endpoint"], json=alert, timeout=10)
         response.raise_for_status()
-    
+
     def _get_alert_color(self, severity: str) -> str:
         """アラート色取得"""
         colors = {
-            "low": "#36a64f",      # 緑
-            "medium": "#ff9500",   # オレンジ
-            "high": "#ff0000",     # 赤
-            "critical": "#8b0000"  # 暗赤
+            "low": "#36a64f",  # 緑
+            "medium": "#ff9500",  # オレンジ
+            "high": "#ff0000",  # 赤
+            "critical": "#8b0000",  # 暗赤
         }
         return colors.get(severity, "#808080")
-    
+
     def get_alert_statistics(self) -> Dict[str, Any]:
         """アラート統計情報を取得"""
         try:
             now = datetime.now()
             last_24h = now - timedelta(hours=24)
-            
+
             # 過去24時間のアラートを集計
             recent_alerts = [
-                alert for alert in self.alert_history 
-                if datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')) > last_24h
+                alert
+                for alert in self.alert_history
+                if datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")) > last_24h
             ]
-            
+
             # 重要度別集計
             by_severity = {}
             for alert in recent_alerts:
-                severity = alert.get('severity', 'unknown')
+                severity = alert.get("severity", "unknown")
                 by_severity[severity] = by_severity.get(severity, 0) + 1
-            
+
             # カテゴリ別集計
             by_category = {}
             for alert in recent_alerts:
-                category = alert.get('category', 'unknown')
+                category = alert.get("category", "unknown")
                 by_category[category] = by_category.get(category, 0) + 1
-            
+
             # 抑制されたアラート数
-            suppressed_count = len([
-                alert for alert in recent_alerts 
-                if alert.get('suppressed', False)
-            ])
-            
+            suppressed_count = len(
+                [alert for alert in recent_alerts if alert.get("suppressed", False)]
+            )
+
             return {
                 "total_alerts_24h": len(recent_alerts),
                 "by_severity": by_severity,
                 "by_category": by_category,
                 "suppressed_count": suppressed_count,
                 "average_per_hour": len(recent_alerts) / 24.0,
-                "timestamp": now.isoformat()
+                "timestamp": now.isoformat(),
             }
-            
+
         except Exception as e:
             self.logger.error(f"アラート統計取得エラー: {e}")
             return {
@@ -414,5 +425,5 @@ class AlertEnhancer:
                 "by_category": {},
                 "suppressed_count": 0,
                 "average_per_hour": 0.0,
-                "timestamp": datetime.now().isoformat()
-            }
\ No newline at end of file
+                "timestamp": datetime.now().isoformat(),
+            }
diff --git a/src/app_optimizer.py b/src/app_optimizer.py
index 66890f5..aea0492 100644
--- a/src/app_optimizer.py
+++ b/src/app_optimizer.py
@@ -3,97 +3,107 @@
 アプリケーションパフォーマンス最適化ツール
 """
 
+import json
+import logging
 import os
 import sys
 import time
-import json
-import logging
-from pathlib import Path
-from typing import Dict, List, Any
 from datetime import datetime
+from pathlib import Path
+from typing import Any, Dict, List
 
 # プロジェクトルートをパスに追加
 project_root = Path(__file__).parent.parent
 sys.path.insert(0, str(project_root))
 
+
 class AppOptimizer:
     """アプリケーション最適化クラス"""
-    
+
     def __init__(self):
         self.logger = logging.getLogger(__name__)
         self.optimizations = []
-        
+
     def optimize_imports(self, file_path: str) -> Dict[str, Any]:
         """インポート最適化"""
         try:
-            with open(file_path, 'r', encoding='utf-8') as f:
+            with open(file_path, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # 遅延インポートの提案
             suggestions = []
-            
+
             # 重いライブラリの検出
             heavy_imports = [
-                'pandas', 'numpy', 'matplotlib', 'seaborn', 'sklearn',
-                'tensorflow', 'torch', 'cv2', 'PIL'
+                "pandas",
+                "numpy",
+                "matplotlib",
+                "seaborn",
+                "sklearn",
+                "tensorflow",
+                "torch",
+                "cv2",
+                "PIL",
             ]
-            
+
             for lib in heavy_imports:
-                if f'import {lib}' in content or f'from {lib}' in content:
-                    suggestions.append({
-                        'type': 'lazy_import',
-                        'library': lib,
-                        'suggestion': f'{lib}を関数内で遅延インポートすることを推奨'
-                    })
-            
+                if f"import {lib}" in content or f"from {lib}" in content:
+                    suggestions.append(
+                        {
+                            "type": "lazy_import",
+                            "library": lib,
+                            "suggestion": f"{lib}を関数内で遅延インポートすることを推奨",
+                        }
+                    )
+
             return {
-                'file': file_path,
-                'suggestions': suggestions,
-                'heavy_imports_count': len(suggestions)
+                "file": file_path,
+                "suggestions": suggestions,
+                "heavy_imports_count": len(suggestions),
             }
-            
+
         except Exception as e:
             self.logger.error(f"インポート分析エラー: {e}")
-            return {'file': file_path, 'error': str(e)}
-    
+            return {"file": file_path, "error": str(e)}
+
     def optimize_database_queries(self) -> List[Dict[str, Any]]:
         """データベースクエリ最適化提案"""
         optimizations = [
             {
-                'type': 'connection_pooling',
-                'description': 'データベース接続プールの実装',
-                'impact': 'high',
-                'implementation': 'SQLAlchemy connection poolingの使用'
+                "type": "connection_pooling",
+                "description": "データベース接続プールの実装",
+                "impact": "high",
+                "implementation": "SQLAlchemy connection poolingの使用",
             },
             {
-                'type': 'query_caching',
-                'description': 'クエリ結果のキャッシュ',
-                'impact': 'medium',
-                'implementation': 'Redis/Memcachedによるクエリキャッシュ'
+                "type": "query_caching",
+                "description": "クエリ結果のキャッシュ",
+                "impact": "medium",
+                "implementation": "Redis/Memcachedによるクエリキャッシュ",
             },
             {
-                'type': 'index_optimization',
-                'description': 'データベースインデックスの最適化',
-                'impact': 'high',
-                'implementation': '頻繁にクエリされるカラムにインデックス追加'
+                "type": "index_optimization",
+                "description": "データベースインデックスの最適化",
+                "impact": "high",
+                "implementation": "頻繁にクエリされるカラムにインデックス追加",
             },
             {
-                'type': 'batch_operations',
-                'description': 'バッチ操作の実装',
-                'impact': 'medium',
-                'implementation': '複数のINSERT/UPDATEをバッチで実行'
-            }
+                "type": "batch_operations",
+                "description": "バッチ操作の実装",
+                "impact": "medium",
+                "implementation": "複数のINSERT/UPDATEをバッチで実行",
+            },
         ]
         return optimizations
-    
+
     def optimize_flask_app(self) -> List[Dict[str, Any]]:
         """Flaskアプリケーション最適化提案"""
         optimizations = [
             {
-                'type': 'response_caching',
-                'description': 'レスポンスキャッシュの実装',
-                'impact': 'high',
-                'code': '''
+                "type": "response_caching",
+                "description": "レスポンスキャッシュの実装",
+                "impact": "high",
+                "code": """
 from flask_caching import Cache
 
 cache = Cache()
@@ -103,29 +113,29 @@ cache.init_app(app, config={'CACHE_TYPE': 'simple'})
 @cache.cached(timeout=60)  # 60秒キャッシュ
 def api_status():
     # 既存のコード
-'''
+""",
             },
             {
-                'type': 'gzip_compression',
-                'description': 'Gzip圧縮の有効化',
-                'impact': 'medium',
-                'code': '''
+                "type": "gzip_compression",
+                "description": "Gzip圧縮の有効化",
+                "impact": "medium",
+                "code": """
 from flask_compress import Compress
 
 Compress(app)
-'''
+""",
             },
             {
-                'type': 'static_file_optimization',
-                'description': '静的ファイルの最適化',
-                'impact': 'medium',
-                'implementation': 'CDN使用、ファイル圧縮、キャッシュヘッダー設定'
+                "type": "static_file_optimization",
+                "description": "静的ファイルの最適化",
+                "impact": "medium",
+                "implementation": "CDN使用、ファイル圧縮、キャッシュヘッダー設定",
             },
             {
-                'type': 'async_processing',
-                'description': '非同期処理の実装',
-                'impact': 'high',
-                'code': '''
+                "type": "async_processing",
+                "description": "非同期処理の実装",
+                "impact": "high",
+                "code": """
 from concurrent.futures import ThreadPoolExecutor
 import asyncio
 
@@ -135,192 +145,196 @@ executor = ThreadPoolExecutor(max_workers=4)
 def heavy_task():
     future = executor.submit(process_heavy_task)
     return jsonify({'task_id': 'async_task_id'})
-'''
-            }
+""",
+            },
         ]
         return optimizations
-    
+
     def optimize_memory_usage(self) -> List[Dict[str, Any]]:
         """メモリ使用量最適化提案"""
         optimizations = [
             {
-                'type': 'object_pooling',
-                'description': 'オブジェクトプールの実装',
-                'impact': 'medium',
-                'implementation': '頻繁に作成/破棄されるオブジェクトのプール化'
+                "type": "object_pooling",
+                "description": "オブジェクトプールの実装",
+                "impact": "medium",
+                "implementation": "頻繁に作成/破棄されるオブジェクトのプール化",
             },
             {
-                'type': 'garbage_collection',
-                'description': 'ガベージコレクション最適化',
-                'impact': 'low',
-                'code': '''
+                "type": "garbage_collection",
+                "description": "ガベージコレクション最適化",
+                "impact": "low",
+                "code": """
 import gc
 
 # 定期的なガベージコレクション
 gc.collect()
 gc.set_threshold(700, 10, 10)  # デフォルトより頻繁に実行
-'''
+""",
             },
             {
-                'type': 'memory_profiling',
-                'description': 'メモリプロファイリングの実装',
-                'impact': 'low',
-                'code': '''
+                "type": "memory_profiling",
+                "description": "メモリプロファイリングの実装",
+                "impact": "low",
+                "code": """
 import tracemalloc
 
 tracemalloc.start()
 # アプリケーション実行
 current, peak = tracemalloc.get_traced_memory()
 tracemalloc.stop()
-'''
-            }
+""",
+            },
         ]
         return optimizations
-    
+
     def apply_flask_optimizations(self, dashboard_file: str):
         """Flaskアプリケーションに最適化を適用"""
         try:
-            with open(dashboard_file, 'r', encoding='utf-8') as f:
+            with open(dashboard_file, "r", encoding="utf-8") as f:
                 content = f.read()
-            
+
             # キャッシュの追加
-            if 'flask_caching' not in content:
+            if "flask_caching" not in content:
                 cache_import = "from flask_caching import Cache\n"
-                
+
                 # インポート部分を見つけて追加
-                lines = content.split('\n')
+                lines = content.split("\n")
                 import_end = 0
                 for i, line in enumerate(lines):
-                    if line.startswith('from ') or line.startswith('import '):
+                    if line.startswith("from ") or line.startswith("import "):
                         import_end = i
-                
+
                 lines.insert(import_end + 1, cache_import)
-                
+
                 # キャッシュ初期化を追加
                 for i, line in enumerate(lines):
-                    if 'self.app = Flask(__name__)' in line:
-                        lines.insert(i + 1, '        self.cache = Cache()')
-                        lines.insert(i + 2, '        self.cache.init_app(self.app, config={"CACHE_TYPE": "simple"})')
+                    if "self.app = Flask(__name__)" in line:
+                        lines.insert(i + 1, "        self.cache = Cache()")
+                        lines.insert(
+                            i + 2,
+                            '        self.cache.init_app(self.app, config={"CACHE_TYPE": "simple"})',
+                        )
                         break
-                
-                content = '\n'.join(lines)
-            
+
+                content = "\n".join(lines)
+
             # 圧縮の追加
-            if 'flask_compress' not in content:
+            if "flask_compress" not in content:
                 compress_import = "from flask_compress import Compress\n"
-                lines = content.split('\n')
-                
+                lines = content.split("\n")
+
                 # インポート追加
                 for i, line in enumerate(lines):
-                    if line.startswith('from flask_caching'):
+                    if line.startswith("from flask_caching"):
                         lines.insert(i + 1, compress_import)
                         break
-                
+
                 # 圧縮初期化を追加
                 for i, line in enumerate(lines):
-                    if 'self.cache.init_app' in line:
-                        lines.insert(i + 1, '        Compress(self.app)')
+                    if "self.cache.init_app" in line:
+                        lines.insert(i + 1, "        Compress(self.app)")
                         break
-                
-                content = '\n'.join(lines)
-            
+
+                content = "\n".join(lines)
+
             # バックアップを作成
             backup_file = f"{dashboard_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
-            with open(backup_file, 'w', encoding='utf-8') as f:
-                f.write(open(dashboard_file, 'r', encoding='utf-8').read())
-            
+            with open(backup_file, "w", encoding="utf-8") as f:
+                f.write(open(dashboard_file, "r", encoding="utf-8").read())
+
             # 最適化されたファイルを保存
-            with open(dashboard_file, 'w', encoding='utf-8') as f:
+            with open(dashboard_file, "w", encoding="utf-8") as f:
                 f.write(content)
-            
+
             self.logger.info(f"最適化を適用しました: {dashboard_file}")
             self.logger.info(f"バックアップ: {backup_file}")
-            
+
             return True
-            
+
         except Exception as e:
             self.logger.error(f"最適化適用エラー: {e}")
             return False
-    
+
     def generate_optimization_report(self) -> Dict[str, Any]:
         """最適化レポートの生成"""
         report = {
-            'timestamp': datetime.now().isoformat(),
-            'flask_optimizations': self.optimize_flask_app(),
-            'database_optimizations': self.optimize_database_queries(),
-            'memory_optimizations': self.optimize_memory_usage(),
-            'summary': {
-                'total_suggestions': 0,
-                'high_impact': 0,
-                'medium_impact': 0,
-                'low_impact': 0
-            }
+            "timestamp": datetime.now().isoformat(),
+            "flask_optimizations": self.optimize_flask_app(),
+            "database_optimizations": self.optimize_database_queries(),
+            "memory_optimizations": self.optimize_memory_usage(),
+            "summary": {
+                "total_suggestions": 0,
+                "high_impact": 0,
+                "medium_impact": 0,
+                "low_impact": 0,
+            },
         }
-        
+
         # 影響度別の集計
         all_optimizations = (
-            report['flask_optimizations'] + 
-            report['database_optimizations'] + 
-            report['memory_optimizations']
+            report["flask_optimizations"]
+            + report["database_optimizations"]
+            + report["memory_optimizations"]
         )
-        
+
         for opt in all_optimizations:
-            impact = opt.get('impact', 'low')
-            report['summary']['total_suggestions'] += 1
-            report['summary'][f'{impact}_impact'] += 1
-        
+            impact = opt.get("impact", "low")
+            report["summary"]["total_suggestions"] += 1
+            report["summary"][f"{impact}_impact"] += 1
+
         return report
 
+
 def main():
     """メイン実行関数"""
     optimizer = AppOptimizer()
-    
+
     # ログ設定
-    logging.basicConfig(
-        level=logging.INFO,
-        format='%(asctime)s - %(levelname)s - %(message)s'
-    )
-    
+    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
+
     print("=== アプリケーション最適化分析 ===")
-    
+
     # 最適化レポート生成
     report = optimizer.generate_optimization_report()
-    
+
     # レポート保存
     report_dir = Path("data/optimization")
     report_dir.mkdir(parents=True, exist_ok=True)
-    
-    report_file = report_dir / f"optimization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
-    with open(report_file, 'w', encoding='utf-8') as f:
+
+    report_file = (
+        report_dir / f"optimization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
+    )
+    with open(report_file, "w", encoding="utf-8") as f:
         json.dump(report, f, indent=2, ensure_ascii=False)
-    
+
     print(f"最適化レポートを生成: {report_file}")
-    
+
     # サマリー表示
-    summary = report['summary']
+    summary = report["summary"]
     print(f"\n=== 最適化提案サマリー ===")
     print(f"総提案数: {summary['total_suggestions']}")
     print(f"高影響: {summary['high_impact']}")
     print(f"中影響: {summary['medium_impact']}")
     print(f"低影響: {summary['low_impact']}")
-    
+
     # 高影響の提案を表示
     print(f"\n=== 高影響の最適化提案 ===")
-    for category in ['flask_optimizations', 'database_optimizations', 'memory_optimizations']:
+    for category in ["flask_optimizations", "database_optimizations", "memory_optimizations"]:
         for opt in report[category]:
-            if opt.get('impact') == 'high':
+            if opt.get("impact") == "high":
                 print(f"- {opt['description']}")
-    
+
     # Flaskアプリケーションの最適化を適用するか確認
     dashboard_file = "orch_dashboard.py"
     if Path(dashboard_file).exists():
         apply = input(f"\n{dashboard_file}に最適化を適用しますか？ (y/N): ")
-        if apply.lower() == 'y':
+        if apply.lower() == "y":
             success = optimizer.apply_flask_optimizations(dashboard_file)
             if success:
                 print("最適化が適用されました。アプリケーションを再起動してください。")
             else:
                 print("最適化の適用に失敗しました。")
 
+
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/src/auto_retrain_scheduler.py b/src/auto_retrain_scheduler.py
index 57dc1f9..214262b 100644
--- a/src/auto_retrain_scheduler.py
+++ b/src/auto_retrain_scheduler.py
@@ -22,7 +22,7 @@ class AutoRetrainScheduler:
         self.logger = logging.getLogger(__name__)
         self.is_running = False
         self.task: Optional[asyncio.Task] = None
-        
+
         # デフォルト設定
         self.default_config = {
             "retrain_interval_hours": 6,
@@ -30,16 +30,16 @@ class AutoRetrainScheduler:
             "feature_importance_threshold": 0.1,
             "performance_threshold": 0.8,
             "max_retries": 3,
-            "retry_delay_minutes": 30
+            "retry_delay_minutes": 30,
         }
-        
+
         self.load_config()
 
     def load_config(self) -> dict:
         """設定ファイル読み込み"""
         try:
             if self.config_path.exists():
-                with open(self.config_path, 'r', encoding='utf-8') as f:
+                with open(self.config_path, "r", encoding="utf-8") as f:
                     config = json.load(f)
                     self.config = config.get("ai_prediction", self.default_config)
             else:
@@ -48,7 +48,7 @@ class AutoRetrainScheduler:
         except Exception as e:
             self.logger.error(f"Failed to load config: {e}")
             self.config = self.default_config
-        
+
         return self.config
 
     def check_training_data_availability(self) -> Dict[str, bool]:
@@ -57,9 +57,9 @@ class AutoRetrainScheduler:
             "quality_data_available": False,
             "resource_data_available": False,
             "quality_sample_count": 0,
-            "resource_sample_count": 0
+            "resource_sample_count": 0,
         }
-        
+
         try:
             # 品質データチェック
             db_path = Path("data/quality_metrics.db")
@@ -69,15 +69,15 @@ class AutoRetrainScheduler:
                     count = cursor.fetchone()[0]
                     results["quality_sample_count"] = count
                     results["quality_data_available"] = count >= self.config["min_training_samples"]
-            
+
             # リソースデータチェック（仮想的なチェック）
             # 実際の実装では適切なデータソースを確認
             results["resource_sample_count"] = 150  # ダミー値
             results["resource_data_available"] = True
-            
+
         except Exception as e:
             self.logger.error(f"Failed to check training data: {e}")
-        
+
         return results
 
     async def retrain_models(self) -> Dict[str, any]:
@@ -86,43 +86,47 @@ class AutoRetrainScheduler:
             "timestamp": datetime.now().isoformat(),
             "quality_model": {"success": False, "metrics": {}},
             "resource_model": {"success": False, "metrics": {}},
-            "errors": []
+            "errors": [],
         }
-        
+
         try:
             # 品質予測モデル再訓練
             self.logger.info("Starting quality model retraining...")
             quality_predictor = QualityPredictor()
-            
+
             try:
                 quality_metrics = quality_predictor.train_model()
                 results["quality_model"]["success"] = True
                 results["quality_model"]["metrics"] = quality_metrics
-                self.logger.info(f"Quality model retrained successfully: accuracy={quality_metrics.get('accuracy', 'N/A')}")
+                self.logger.info(
+                    f"Quality model retrained successfully: accuracy={quality_metrics.get('accuracy', 'N/A')}"
+                )
             except Exception as e:
                 error_msg = f"Quality model retraining failed: {e}"
                 self.logger.error(error_msg)
                 results["errors"].append(error_msg)
-            
+
             # リソース需要予測モデル再訓練
             self.logger.info("Starting resource model retraining...")
             resource_predictor = ResourceDemandPredictor()
-            
+
             try:
                 resource_metrics = resource_predictor.train_model()
                 results["resource_model"]["success"] = True
                 results["resource_model"]["metrics"] = resource_metrics
-                self.logger.info(f"Resource model retrained successfully: R²={resource_metrics.get('r2_score', 'N/A')}")
+                self.logger.info(
+                    f"Resource model retrained successfully: R²={resource_metrics.get('r2_score', 'N/A')}"
+                )
             except Exception as e:
                 error_msg = f"Resource model retraining failed: {e}"
                 self.logger.error(error_msg)
                 results["errors"].append(error_msg)
-            
+
         except Exception as e:
             error_msg = f"Unexpected error during retraining: {e}"
             self.logger.error(error_msg)
             results["errors"].append(error_msg)
-        
+
         return results
 
     def save_retrain_log(self, results: Dict[str, any]) -> None:
@@ -130,55 +134,56 @@ class AutoRetrainScheduler:
         try:
             log_dir = Path("data/logs/retrain")
             log_dir.mkdir(parents=True, exist_ok=True)
-            
+
             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
             log_file = log_dir / f"retrain_log_{timestamp}.json"
-            
-            with open(log_file, 'w', encoding='utf-8') as f:
+
+            with open(log_file, "w", encoding="utf-8") as f:
                 json.dump(results, f, indent=2, ensure_ascii=False)
-            
+
             self.logger.info(f"Retrain log saved: {log_file}")
-            
+
         except Exception as e:
             self.logger.error(f"Failed to save retrain log: {e}")
 
     async def schedule_loop(self) -> None:
         """スケジュール実行ループ"""
         self.logger.info("Auto retrain scheduler started")
-        
+
         while self.is_running:
             try:
                 # データ可用性チェック
                 data_status = self.check_training_data_availability()
                 self.logger.info(f"Training data status: {data_status}")
-                
+
                 if data_status["quality_data_available"] or data_status["resource_data_available"]:
                     # 再訓練実行
                     results = await self.retrain_models()
-                    
+
                     # ログ保存
                     self.save_retrain_log(results)
-                    
+
                     # 成功/失敗の判定
-                    success_count = sum([
-                        results["quality_model"]["success"],
-                        results["resource_model"]["success"]
-                    ])
-                    
+                    success_count = sum(
+                        [results["quality_model"]["success"], results["resource_model"]["success"]]
+                    )
+
                     if success_count > 0:
-                        self.logger.info(f"Retraining completed: {success_count}/2 models successful")
+                        self.logger.info(
+                            f"Retraining completed: {success_count}/2 models successful"
+                        )
                     else:
                         self.logger.warning("All model retraining failed")
                 else:
                     self.logger.info("Insufficient training data, skipping retraining")
-                
+
                 # 次回実行まで待機
                 interval_hours = self.config["retrain_interval_hours"]
                 wait_seconds = interval_hours * 3600
                 self.logger.info(f"Next retraining in {interval_hours} hours")
-                
+
                 await asyncio.sleep(wait_seconds)
-                
+
             except asyncio.CancelledError:
                 self.logger.info("Retrain scheduler cancelled")
                 break
@@ -192,7 +197,7 @@ class AutoRetrainScheduler:
         if self.is_running:
             self.logger.warning("Scheduler is already running")
             return
-        
+
         self.is_running = True
         self.task = asyncio.create_task(self.schedule_loop())
         self.logger.info("Auto retrain scheduler started")
@@ -201,7 +206,7 @@ class AutoRetrainScheduler:
         """スケジューラー停止"""
         if not self.is_running:
             return
-        
+
         self.is_running = False
         if self.task:
             self.task.cancel()
@@ -209,7 +214,7 @@ class AutoRetrainScheduler:
                 await self.task
             except asyncio.CancelledError:
                 pass
-        
+
         self.logger.info("Auto retrain scheduler stopped")
 
     def get_status(self) -> Dict[str, any]:
@@ -218,8 +223,12 @@ class AutoRetrainScheduler:
             "is_running": self.is_running,
             "config": self.config,
             "next_run_estimate": (
-                datetime.now() + timedelta(hours=self.config["retrain_interval_hours"])
-            ).isoformat() if self.is_running else None
+                (
+                    datetime.now() + timedelta(hours=self.config["retrain_interval_hours"])
+                ).isoformat()
+                if self.is_running
+                else None
+            ),
         }
 
 
@@ -230,8 +239,9 @@ scheduler = AutoRetrainScheduler()
 async def main():
     """テスト実行"""
     import logging
+
     logging.basicConfig(level=logging.INFO)
-    
+
     try:
         await scheduler.start()
         # テスト用に短時間実行
@@ -241,4 +251,4 @@ async def main():
 
 
 if __name__ == "__main__":
-    asyncio.run(main())
\ No newline at end of file
+    asyncio.run(main())
diff --git a/src/blueprints/__init__.py b/src/blueprints/__init__.py
index 8ecebd3..8c58e25 100644
--- a/src/blueprints/__init__.py
+++ b/src/blueprints/__init__.py
@@ -1,9 +1,9 @@
 # Blueprint modules for ORCH Dashboard
 # Modular route organization for maintainability and testing
 
-from .ui_routes import ui_bp
+from .admin_routes import admin_bp
 from .api_routes import api_bp
 from .sse_routes import sse_bp
-from .admin_routes import admin_bp
+from .ui_routes import ui_bp
 
-__all__ = ['ui_bp', 'api_bp', 'sse_bp', 'admin_bp']
\ No newline at end of file
+__all__ = ["ui_bp", "api_bp", "sse_bp", "admin_bp"]
diff --git a/src/blueprints/admin_routes.py b/src/blueprints/admin_routes.py
index 8a1114d..b95e491 100644
--- a/src/blueprints/admin_routes.py
+++ b/src/blueprints/admin_routes.py
@@ -3,34 +3,40 @@ Admin Routes Blueprint for ORCH Dashboard
 Handles administrative endpoints with enhanced error handling and monitoring
 """
 
-import logging
 import json
-import traceback
-import time
-import psutil
+import logging
 import platform
+import time
+import traceback
 from datetime import datetime
-from flask import Blueprint, jsonify, request, Response
-from typing import Optional, Dict, Any
+from typing import Any, Dict, Optional
+
+import psutil
+from flask import Blueprint, Response, jsonify, request
 
 # Configure structured logging
 logger = logging.getLogger(__name__)
 
+
 class AdminInitializationError(Exception):
     """Custom exception for Admin initialization failures"""
+
     pass
 
+
 class AdminRouteError(Exception):
     """Custom exception for Admin route failures"""
+
     pass
 
+
 # Create Blueprint with error handling
 try:
-    admin_bp = Blueprint('admin', __name__)
+    admin_bp = Blueprint("admin", __name__)
     blueprint_info = {
         "event": "admin_blueprint_created",
         "timestamp": datetime.now().isoformat(),
-        "blueprint_name": "admin"
+        "blueprint_name": "admin",
     }
     logger.info(f"Admin Blueprint created: {json.dumps(blueprint_info)}")
 except Exception as e:
@@ -38,62 +44,65 @@ except Exception as e:
         "event": "admin_blueprint_creation_failed",
         "timestamp": datetime.now().isoformat(),
         "error": str(e),
-        "error_type": type(e).__name__
+        "error_type": type(e).__name__,
     }
     logger.error(f"Failed to create Admin Blueprint: {json.dumps(error_info)}")
     raise
 
+
 def init_admin_routes(dashboard_instance):
     """Initialize Admin routes with enhanced error handling and monitoring"""
     init_start = time.time()
-    
+
     try:
         # Log initialization start
         init_info = {
             "event": "admin_routes_init_start",
             "timestamp": datetime.now().isoformat(),
-            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None
+            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
         }
         logger.info(f"Admin routes initialization starting: {json.dumps(init_info)}")
-        
+
         # Validate dashboard instance
         if dashboard_instance is None:
             raise ValueError("Dashboard instance is required for Admin initialization")
-        
+
         # Validate dashboard instance type and required methods
-        required_methods = ['get_system_status', 'get_system_health']
-        optional_methods = ['get_quality_metrics', 'get_work_progress']
+        required_methods = ["get_system_status", "get_system_health"]
+        optional_methods = ["get_quality_metrics", "get_work_progress"]
         missing_required = []
         missing_optional = []
-        
+
         for method in required_methods:
             if not hasattr(dashboard_instance, method):
                 missing_required.append(method)
-        
+
         for method in optional_methods:
             if not hasattr(dashboard_instance, method):
                 missing_optional.append(method)
-        
+
         if missing_required:
             validation_error = {
                 "event": "admin_dashboard_instance_validation_failed",
                 "timestamp": datetime.now().isoformat(),
                 "missing_required_methods": missing_required,
                 "missing_optional_methods": missing_optional,
-                "instance_type": type(dashboard_instance).__name__
+                "instance_type": type(dashboard_instance).__name__,
             }
             logger.error(f"Dashboard instance validation failed: {json.dumps(validation_error)}")
             raise ValueError(f"Dashboard instance missing required methods: {missing_required}")
-        
+
         if missing_optional:
             optional_warning = {
                 "event": "admin_dashboard_instance_optional_methods_missing",
                 "timestamp": datetime.now().isoformat(),
                 "missing_optional_methods": missing_optional,
-                "instance_type": type(dashboard_instance).__name__
+                "instance_type": type(dashboard_instance).__name__,
             }
-            logger.warning(f"Dashboard instance missing optional methods: {json.dumps(optional_warning)}")
-        
+            logger.warning(
+                f"Dashboard instance missing optional methods: {json.dumps(optional_warning)}"
+            )
+
         # Store dashboard instance reference with error handling
         try:
             admin_bp.dashboard_instance = dashboard_instance
@@ -102,29 +111,38 @@ def init_admin_routes(dashboard_instance):
                 "timestamp": datetime.now().isoformat(),
                 "instance_type": type(dashboard_instance).__name__,
                 "instance_id": id(dashboard_instance),
-                "available_methods": [method for method in dir(dashboard_instance) if not method.startswith('_')],
-                "required_methods_available": all(hasattr(dashboard_instance, method) for method in required_methods),
-                "optional_methods_available": [method for method in optional_methods if hasattr(dashboard_instance, method)]
+                "available_methods": [
+                    method for method in dir(dashboard_instance) if not method.startswith("_")
+                ],
+                "required_methods_available": all(
+                    hasattr(dashboard_instance, method) for method in required_methods
+                ),
+                "optional_methods_available": [
+                    method for method in optional_methods if hasattr(dashboard_instance, method)
+                ],
             }
-            logger.info(f"Dashboard instance injected into Admin Blueprint: {json.dumps(instance_info)}")
+            logger.info(
+                f"Dashboard instance injected into Admin Blueprint: {json.dumps(instance_info)}"
+            )
         except Exception as e:
             error_info = {
                 "event": "admin_dashboard_instance_injection_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
             raise
-        
+
         # Initialize Prometheus metrics if available
         try:
             import prometheus_client
+
             prometheus_available = True
             prometheus_info = {
                 "event": "admin_prometheus_available",
                 "timestamp": datetime.now().isoformat(),
-                "prometheus_version": getattr(prometheus_client, '__version__', 'unknown')
+                "prometheus_version": getattr(prometheus_client, "__version__", "unknown"),
             }
             logger.info(f"Prometheus client available: {json.dumps(prometheus_info)}")
         except ImportError as e:
@@ -132,12 +150,12 @@ def init_admin_routes(dashboard_instance):
             prometheus_warning = {
                 "event": "admin_prometheus_unavailable",
                 "timestamp": datetime.now().isoformat(),
-                "error": str(e)
+                "error": str(e),
             }
             logger.warning(f"Prometheus client not available: {json.dumps(prometheus_warning)}")
-        
+
         admin_bp.prometheus_available = prometheus_available
-        
+
         # Log successful initialization
         init_duration = time.time() - init_start
         success_info = {
@@ -145,10 +163,10 @@ def init_admin_routes(dashboard_instance):
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(init_duration, 3),
             "dashboard_instance_validated": True,
-            "prometheus_available": prometheus_available
+            "prometheus_available": prometheus_available,
         }
         logger.info(f"Admin routes initialized successfully: {json.dumps(success_info)}")
-        
+
     except Exception as e:
         # Log initialization failure
         init_duration = time.time() - init_start
@@ -158,17 +176,18 @@ def init_admin_routes(dashboard_instance):
             "duration_seconds": round(init_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"Admin routes initialization failed: {json.dumps(error_info)}")
         raise AdminInitializationError(f"Failed to initialize Admin routes: {e}") from e
 
-@admin_bp.route('/metrics')
+
+@admin_bp.route("/metrics")
 def get_metrics():
     """Get Prometheus metrics with enhanced error handling"""
     request_start = time.time()
     request_id = f"metrics_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
@@ -176,33 +195,33 @@ def get_metrics():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "remote_addr": request.remote_addr,
-            "user_agent": request.headers.get("User-Agent", "Unknown")
+            "user_agent": request.headers.get("User-Agent", "Unknown"),
         }
         logger.info(f"Admin metrics request started: {json.dumps(request_info)}")
-        
+
         # Check if Prometheus is available
-        if not getattr(admin_bp, 'prometheus_available', False):
+        if not getattr(admin_bp, "prometheus_available", False):
             raise AdminRouteError("Prometheus metrics not available")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(admin_bp, 'dashboard_instance') or admin_bp.dashboard_instance is None:
+        if not hasattr(admin_bp, "dashboard_instance") or admin_bp.dashboard_instance is None:
             raise AdminRouteError("Dashboard instance not available")
-        
+
         try:
             import prometheus_client
-            
+
             # Generate metrics with error handling
             try:
                 metrics_output = prometheus_client.generate_latest()
-                
+
                 metrics_info = {
                     "event": "admin_prometheus_metrics_generated",
                     "request_id": request_id,
                     "timestamp": datetime.now().isoformat(),
-                    "metrics_size_bytes": len(metrics_output)
+                    "metrics_size_bytes": len(metrics_output),
                 }
                 logger.info(f"Prometheus metrics generated: {json.dumps(metrics_info)}")
-                
+
                 # Log successful response
                 request_duration = time.time() - request_start
                 success_info = {
@@ -210,12 +229,12 @@ def get_metrics():
                     "request_id": request_id,
                     "timestamp": datetime.now().isoformat(),
                     "duration_seconds": round(request_duration, 3),
-                    "metrics_size_bytes": len(metrics_output)
+                    "metrics_size_bytes": len(metrics_output),
                 }
                 logger.info(f"Admin metrics request completed: {json.dumps(success_info)}")
-                
-                return Response(metrics_output, mimetype='text/plain')
-                
+
+                return Response(metrics_output, mimetype="text/plain")
+
             except Exception as e:
                 # Fallback metrics if generation fails
                 fallback_info = {
@@ -223,10 +242,12 @@ def get_metrics():
                     "request_id": request_id,
                     "timestamp": datetime.now().isoformat(),
                     "error": str(e),
-                    "error_type": type(e).__name__
+                    "error_type": type(e).__name__,
                 }
-                logger.warning(f"Using fallback metrics due to generation error: {json.dumps(fallback_info)}")
-                
+                logger.warning(
+                    f"Using fallback metrics due to generation error: {json.dumps(fallback_info)}"
+                )
+
                 fallback_metrics = f"""# HELP admin_request_total Total admin requests
 # TYPE admin_request_total counter
 admin_request_total{{endpoint="metrics",status="fallback"}} 1
@@ -239,11 +260,11 @@ admin_request_duration_seconds_count{{endpoint="metrics"}} 1
 # TYPE admin_error_total counter
 admin_error_total{{endpoint="metrics",error_type="{type(e).__name__}"}} 1
 """
-                return Response(fallback_metrics, mimetype='text/plain')
-                
+                return Response(fallback_metrics, mimetype="text/plain")
+
         except ImportError as e:
             raise AdminRouteError(f"Prometheus client import failed: {e}")
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -254,23 +275,29 @@ admin_error_total{{endpoint="metrics",error_type="{type(e).__name__}"}} 1
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"Admin metrics request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve metrics",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@admin_bp.route('/system-info')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve metrics",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@admin_bp.route("/system-info")
 def get_system_info():
     """Get comprehensive system information with enhanced monitoring"""
     request_start = time.time()
     request_id = f"sysinfo_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
@@ -278,17 +305,17 @@ def get_system_info():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "remote_addr": request.remote_addr,
-            "user_agent": request.headers.get("User-Agent", "Unknown")
+            "user_agent": request.headers.get("User-Agent", "Unknown"),
         }
         logger.info(f"Admin system info request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(admin_bp, 'dashboard_instance') or admin_bp.dashboard_instance is None:
+        if not hasattr(admin_bp, "dashboard_instance") or admin_bp.dashboard_instance is None:
             raise AdminRouteError("Dashboard instance not available")
-        
+
         # Collect comprehensive system information
         system_info = {}
-        
+
         # Platform information
         try:
             system_info["platform"] = {
@@ -299,123 +326,129 @@ def get_system_info():
                 "processor": platform.processor(),
                 "python_version": platform.python_version(),
                 "python_implementation": platform.python_implementation(),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             platform_info = {
                 "event": "admin_platform_info_collected",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "platform_system": platform.system()
+                "platform_system": platform.system(),
             }
             logger.info(f"Platform information collected: {json.dumps(platform_info)}")
-            
+
         except Exception as e:
             system_info["platform"] = {
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             platform_error_info = {
                 "event": "admin_platform_info_error",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
-            logger.error(f"Platform information collection failed: {json.dumps(platform_error_info)}")
-        
+            logger.error(
+                f"Platform information collection failed: {json.dumps(platform_error_info)}"
+            )
+
         # System resources
         try:
             cpu_percent = psutil.cpu_percent(interval=0.1)
             memory = psutil.virtual_memory()
-            disk = psutil.disk_usage('/')
-            
+            disk = psutil.disk_usage("/")
+
             system_info["resources"] = {
                 "cpu": {
                     "count": psutil.cpu_count(),
                     "count_logical": psutil.cpu_count(logical=True),
                     "percent": round(cpu_percent, 2),
-                    "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
+                    "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                 },
                 "memory": {
                     "total_gb": round(memory.total / (1024**3), 2),
                     "available_gb": round(memory.available / (1024**3), 2),
                     "used_gb": round(memory.used / (1024**3), 2),
-                    "percent_used": round(memory.percent, 2)
+                    "percent_used": round(memory.percent, 2),
                 },
                 "disk": {
                     "total_gb": round(disk.total / (1024**3), 2),
                     "free_gb": round(disk.free / (1024**3), 2),
                     "used_gb": round(disk.used / (1024**3), 2),
-                    "percent_used": round((disk.used / disk.total) * 100, 2)
+                    "percent_used": round((disk.used / disk.total) * 100, 2),
                 },
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             resources_info = {
                 "event": "admin_resources_info_collected",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "cpu_percent": cpu_percent,
-                "memory_percent": memory.percent
+                "memory_percent": memory.percent,
             }
             logger.info(f"System resources collected: {json.dumps(resources_info)}")
-            
+
         except Exception as e:
             system_info["resources"] = {
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             resources_error_info = {
                 "event": "admin_resources_info_error",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"System resources collection failed: {json.dumps(resources_error_info)}")
-        
+
         # Dashboard status
         try:
             dashboard_status = admin_bp.dashboard_instance.get_system_status()
             system_info["dashboard"] = dashboard_status
-            
+
             dashboard_status_info = {
                 "event": "admin_dashboard_status_collected",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "status": dashboard_status.get("status", "unknown") if isinstance(dashboard_status, dict) else "non_dict_response"
+                "status": (
+                    dashboard_status.get("status", "unknown")
+                    if isinstance(dashboard_status, dict)
+                    else "non_dict_response"
+                ),
             }
             logger.info(f"Dashboard status collected: {json.dumps(dashboard_status_info)}")
-            
+
         except Exception as e:
             system_info["dashboard"] = {
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             dashboard_error_info = {
                 "event": "admin_dashboard_status_error",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Dashboard status collection failed: {json.dumps(dashboard_error_info)}")
-        
+
         # Compile final response
         response_data = {
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "system_info": system_info,
-            "response_time_ms": round((time.time() - request_start) * 1000, 3)
+            "response_time_ms": round((time.time() - request_start) * 1000, 3),
         }
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
@@ -423,12 +456,12 @@ def get_system_info():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(request_duration, 3),
-            "info_sections": list(system_info.keys())
+            "info_sections": list(system_info.keys()),
         }
         logger.info(f"Admin system info request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(response_data)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -439,58 +472,67 @@ def get_system_info():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"Admin system info request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve system information",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@admin_bp.route('/health')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve system information",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@admin_bp.route("/health")
 def admin_health_check():
     """Simple Admin health check endpoint"""
     try:
         health_start = time.time()
-        
+
         # Basic health check
         health_data = {
             "status": "healthy",
             "timestamp": datetime.now().isoformat(),
             "admin_version": "1.0.0",
-            "dashboard_instance_available": hasattr(admin_bp, 'dashboard_instance') and admin_bp.dashboard_instance is not None,
-            "prometheus_available": getattr(admin_bp, 'prometheus_available', False),
-            "response_time_ms": round((time.time() - health_start) * 1000, 3)
+            "dashboard_instance_available": hasattr(admin_bp, "dashboard_instance")
+            and admin_bp.dashboard_instance is not None,
+            "prometheus_available": getattr(admin_bp, "prometheus_available", False),
+            "response_time_ms": round((time.time() - health_start) * 1000, 3),
         }
-        
+
         # Log health check
         health_info = {
             "event": "admin_health_check",
             "timestamp": datetime.now().isoformat(),
-            "status": "healthy"
+            "status": "healthy",
         }
         logger.info(f"Admin health check completed: {json.dumps(health_info)}")
-        
+
         return jsonify(health_data)
-        
+
     except Exception as e:
         # Log health check failure
         error_info = {
             "event": "admin_health_check_failed",
             "timestamp": datetime.now().isoformat(),
             "error": str(e),
-            "error_type": type(e).__name__
+            "error_type": type(e).__name__,
         }
         logger.error(f"Admin health check failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "status": "unhealthy",
-            "error": str(e),
-            "timestamp": datetime.now().isoformat()
-        }), 500
+
+        return (
+            jsonify(
+                {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}
+            ),
+            500,
+        )
+
 
 @admin_bp.errorhandler(AdminRouteError)
 def handle_admin_route_error(error):
@@ -499,15 +541,21 @@ def handle_admin_route_error(error):
         "event": "admin_route_error_handled",
         "timestamp": datetime.now().isoformat(),
         "error": str(error),
-        "error_type": type(error).__name__
+        "error_type": type(error).__name__,
     }
     logger.error(f"Admin route error handled: {json.dumps(error_info)}")
-    
-    return jsonify({
-        "error": "Admin route error",
-        "message": str(error),
-        "timestamp": datetime.now().isoformat()
-    }), 500
+
+    return (
+        jsonify(
+            {
+                "error": "Admin route error",
+                "message": str(error),
+                "timestamp": datetime.now().isoformat(),
+            }
+        ),
+        500,
+    )
+
 
 @admin_bp.errorhandler(Exception)
 def handle_general_error(error):
@@ -517,14 +565,20 @@ def handle_general_error(error):
         "timestamp": datetime.now().isoformat(),
         "error": str(error),
         "error_type": type(error).__name__,
-        "traceback": traceback.format_exc()
+        "traceback": traceback.format_exc(),
     }
     logger.error(f"Admin general error handled: {json.dumps(error_info)}")
-    
-    return jsonify({
-        "error": "Internal server error",
-        "message": "An unexpected error occurred",
-        "timestamp": datetime.now().isoformat()
-    }), 500
-
-__all__ = ['admin_bp', 'init_admin_routes']
\ No newline at end of file
+
+    return (
+        jsonify(
+            {
+                "error": "Internal server error",
+                "message": "An unexpected error occurred",
+                "timestamp": datetime.now().isoformat(),
+            }
+        ),
+        500,
+    )
+
+
+__all__ = ["admin_bp", "init_admin_routes"]
diff --git a/src/blueprints/api_routes.py b/src/blueprints/api_routes.py
index 3f7fd28..2ae2169 100644
--- a/src/blueprints/api_routes.py
+++ b/src/blueprints/api_routes.py
@@ -3,34 +3,40 @@ API Routes Blueprint for ORCH Dashboard
 Handles all API endpoints with enhanced error handling and monitoring
 """
 
-import logging
 import json
-import traceback
-import time
-import psutil
+import logging
 import platform
+import time
+import traceback
 from datetime import datetime
+from typing import Any, Dict, Optional
+
+import psutil
 from flask import Blueprint, jsonify, request
-from typing import Optional, Dict, Any
 
 # Configure structured logging
 logger = logging.getLogger(__name__)
 
+
 class APIInitializationError(Exception):
     """Custom exception for API initialization failures"""
+
     pass
 
+
 class APIRouteError(Exception):
     """Custom exception for API route failures"""
+
     pass
 
+
 # Create Blueprint with error handling
 try:
-    api_bp = Blueprint('api', __name__)
+    api_bp = Blueprint("api", __name__)
     blueprint_info = {
         "event": "api_blueprint_created",
         "timestamp": datetime.now().isoformat(),
-        "blueprint_name": "api"
+        "blueprint_name": "api",
     }
     logger.info(f"API Blueprint created: {json.dumps(blueprint_info)}")
 except Exception as e:
@@ -38,46 +44,47 @@ except Exception as e:
         "event": "api_blueprint_creation_failed",
         "timestamp": datetime.now().isoformat(),
         "error": str(e),
-        "error_type": type(e).__name__
+        "error_type": type(e).__name__,
     }
     logger.error(f"Failed to create API Blueprint: {json.dumps(error_info)}")
     raise
 
+
 def init_api_routes(dashboard_instance):
     """Initialize API routes with enhanced error handling and monitoring"""
     init_start = time.time()
-    
+
     try:
         # Log initialization start
         init_info = {
             "event": "api_routes_init_start",
             "timestamp": datetime.now().isoformat(),
-            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None
+            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
         }
         logger.info(f"API routes initialization starting: {json.dumps(init_info)}")
-        
+
         # Validate dashboard instance
         if dashboard_instance is None:
             raise ValueError("Dashboard instance is required for API initialization")
-        
+
         # Validate dashboard instance type and required methods
-        required_methods = ['get_system_status', 'get_system_health']
+        required_methods = ["get_system_status", "get_system_health"]
         missing_methods = []
-        
+
         for method in required_methods:
             if not hasattr(dashboard_instance, method):
                 missing_methods.append(method)
-        
+
         if missing_methods:
             validation_error = {
                 "event": "api_dashboard_instance_validation_failed",
                 "timestamp": datetime.now().isoformat(),
                 "missing_methods": missing_methods,
-                "instance_type": type(dashboard_instance).__name__
+                "instance_type": type(dashboard_instance).__name__,
             }
             logger.error(f"Dashboard instance validation failed: {json.dumps(validation_error)}")
             raise ValueError(f"Dashboard instance missing required methods: {missing_methods}")
-        
+
         # Store dashboard instance reference with error handling
         try:
             api_bp.dashboard_instance = dashboard_instance
@@ -86,29 +93,33 @@ def init_api_routes(dashboard_instance):
                 "timestamp": datetime.now().isoformat(),
                 "instance_type": type(dashboard_instance).__name__,
                 "instance_id": id(dashboard_instance),
-                "available_methods": [method for method in dir(dashboard_instance) if not method.startswith('_')]
+                "available_methods": [
+                    method for method in dir(dashboard_instance) if not method.startswith("_")
+                ],
             }
-            logger.info(f"Dashboard instance injected into API Blueprint: {json.dumps(instance_info)}")
+            logger.info(
+                f"Dashboard instance injected into API Blueprint: {json.dumps(instance_info)}"
+            )
         except Exception as e:
             error_info = {
                 "event": "api_dashboard_instance_injection_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
             raise
-        
+
         # Log successful initialization
         init_duration = time.time() - init_start
         success_info = {
             "event": "api_routes_init_complete",
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(init_duration, 3),
-            "dashboard_instance_validated": True
+            "dashboard_instance_validated": True,
         }
         logger.info(f"API routes initialized successfully: {json.dumps(success_info)}")
-        
+
     except Exception as e:
         # Log initialization failure
         init_duration = time.time() - init_start
@@ -118,17 +129,18 @@ def init_api_routes(dashboard_instance):
             "duration_seconds": round(init_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API routes initialization failed: {json.dumps(error_info)}")
         raise APIInitializationError(f"Failed to initialize API routes: {e}") from e
 
-@api_bp.route('/status')
+
+@api_bp.route("/status")
 def get_status():
     """Get system status with comprehensive error handling"""
     request_start = time.time()
     request_id = f"status_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
@@ -136,14 +148,14 @@ def get_status():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "remote_addr": request.remote_addr,
-            "user_agent": request.headers.get("User-Agent", "Unknown")
+            "user_agent": request.headers.get("User-Agent", "Unknown"),
         }
         logger.info(f"API status request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(api_bp, 'dashboard_instance') or api_bp.dashboard_instance is None:
+        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
             raise APIRouteError("Dashboard instance not available")
-        
+
         # Get status from dashboard instance with error handling
         try:
             dashboard_status = api_bp.dashboard_instance.get_system_status()
@@ -151,7 +163,11 @@ def get_status():
                 "event": "api_dashboard_status_retrieved",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "status_keys": list(dashboard_status.keys()) if isinstance(dashboard_status, dict) else "non_dict_response"
+                "status_keys": (
+                    list(dashboard_status.keys())
+                    if isinstance(dashboard_status, dict)
+                    else "non_dict_response"
+                ),
             }
             logger.info(f"Dashboard status retrieved: {json.dumps(status_retrieval_info)}")
         except Exception as e:
@@ -161,17 +177,19 @@ def get_status():
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
-            logger.warning(f"Using fallback status due to dashboard error: {json.dumps(fallback_info)}")
-            
+            logger.warning(
+                f"Using fallback status due to dashboard error: {json.dumps(fallback_info)}"
+            )
+
             dashboard_status = {
                 "status": "degraded",
                 "message": "Dashboard status method failed",
                 "error": str(e),
-                "fallback": True
+                "fallback": True,
             }
-        
+
         # Enhance status with additional system information
         try:
             enhanced_status = {
@@ -179,14 +197,14 @@ def get_status():
                 "api_info": {
                     "request_id": request_id,
                     "timestamp": datetime.now().isoformat(),
-                    "response_time_ms": round((time.time() - request_start) * 1000, 3)
+                    "response_time_ms": round((time.time() - request_start) * 1000, 3),
                 },
                 "system_info": {
                     "platform": platform.system(),
                     "python_version": platform.python_version(),
                     "cpu_count": psutil.cpu_count(),
-                    "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2)
-                }
+                    "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
+                },
             }
         except Exception as e:
             # Log enhancement failure but continue with basic status
@@ -195,11 +213,11 @@ def get_status():
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.warning(f"Status enhancement failed: {json.dumps(enhancement_error)}")
             enhanced_status = dashboard_status
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
@@ -207,12 +225,12 @@ def get_status():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(request_duration, 3),
-            "status_type": enhanced_status.get("status", "unknown")
+            "status_type": enhanced_status.get("status", "unknown"),
         }
         logger.info(f"API status request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(enhanced_status)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -223,23 +241,29 @@ def get_status():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API status request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve system status",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@api_bp.route('/system-health')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve system status",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@api_bp.route("/system-health")
 def get_system_health():
     """Get comprehensive system health with enhanced monitoring"""
     request_start = time.time()
     request_id = f"health_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
@@ -247,107 +271,111 @@ def get_system_health():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "remote_addr": request.remote_addr,
-            "user_agent": request.headers.get("User-Agent", "Unknown")
+            "user_agent": request.headers.get("User-Agent", "Unknown"),
         }
         logger.info(f"API health request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(api_bp, 'dashboard_instance') or api_bp.dashboard_instance is None:
+        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
             raise APIRouteError("Dashboard instance not available")
-        
+
         # Collect comprehensive health metrics
         health_metrics = {}
-        
+
         # Get dashboard health
         try:
             dashboard_health = api_bp.dashboard_instance.get_system_health()
             health_metrics["dashboard"] = dashboard_health
-            
+
             dashboard_health_info = {
                 "event": "api_dashboard_health_retrieved",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "health_status": dashboard_health.get("status", "unknown") if isinstance(dashboard_health, dict) else "non_dict_response"
+                "health_status": (
+                    dashboard_health.get("status", "unknown")
+                    if isinstance(dashboard_health, dict)
+                    else "non_dict_response"
+                ),
             }
             logger.info(f"Dashboard health retrieved: {json.dumps(dashboard_health_info)}")
         except Exception as e:
             health_metrics["dashboard"] = {
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             dashboard_error_info = {
                 "event": "api_dashboard_health_error",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Dashboard health retrieval failed: {json.dumps(dashboard_error_info)}")
-        
+
         # Get system metrics
         try:
             cpu_percent = psutil.cpu_percent(interval=0.1)
             memory = psutil.virtual_memory()
-            disk = psutil.disk_usage('/')
-            
+            disk = psutil.disk_usage("/")
+
             health_metrics["system"] = {
                 "cpu_percent": round(cpu_percent, 2),
                 "memory": {
                     "total_gb": round(memory.total / (1024**3), 2),
                     "available_gb": round(memory.available / (1024**3), 2),
-                    "percent_used": round(memory.percent, 2)
+                    "percent_used": round(memory.percent, 2),
                 },
                 "disk": {
                     "total_gb": round(disk.total / (1024**3), 2),
                     "free_gb": round(disk.free / (1024**3), 2),
-                    "percent_used": round((disk.used / disk.total) * 100, 2)
+                    "percent_used": round((disk.used / disk.total) * 100, 2),
                 },
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             system_metrics_info = {
                 "event": "api_system_metrics_collected",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "cpu_percent": cpu_percent,
-                "memory_percent": memory.percent
+                "memory_percent": memory.percent,
             }
             logger.info(f"System metrics collected: {json.dumps(system_metrics_info)}")
-            
+
         except Exception as e:
             health_metrics["system"] = {
                 "status": "error",
                 "error": str(e),
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
-            
+
             system_error_info = {
                 "event": "api_system_metrics_error",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"System metrics collection failed: {json.dumps(system_error_info)}")
-        
+
         # Determine overall health status
         overall_status = "healthy"
         if health_metrics.get("dashboard", {}).get("status") == "error":
             overall_status = "degraded"
         if health_metrics.get("system", {}).get("status") == "error":
             overall_status = "critical" if overall_status == "degraded" else "degraded"
-        
+
         # Compile final health response
         health_response = {
             "overall_status": overall_status,
             "timestamp": datetime.now().isoformat(),
             "request_id": request_id,
             "metrics": health_metrics,
-            "response_time_ms": round((time.time() - request_start) * 1000, 3)
+            "response_time_ms": round((time.time() - request_start) * 1000, 3),
         }
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
@@ -355,12 +383,12 @@ def get_system_health():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(request_duration, 3),
-            "overall_status": overall_status
+            "overall_status": overall_status,
         }
         logger.info(f"API health request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(health_response)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -371,60 +399,66 @@ def get_system_health():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API health request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve system health",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@api_bp.route('/tasks')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve system health",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@api_bp.route("/tasks")
 def get_tasks():
     """Get tasks data from ORCH/STATE/TASKS.md"""
     request_start = time.time()
     request_id = f"tasks_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
             "event": "api_tasks_request_start",
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
-            "remote_addr": request.remote_addr
+            "remote_addr": request.remote_addr,
         }
         logger.info(f"API tasks request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(api_bp, 'dashboard_instance') or api_bp.dashboard_instance is None:
+        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
             raise APIRouteError("Dashboard instance not available")
-        
+
         # Get tasks data from dashboard instance
         try:
             tasks_data = api_bp.dashboard_instance._get_tasks_data()
-            
+
             tasks_info = {
                 "event": "api_tasks_data_retrieved",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0
+                "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0,
             }
             logger.info(f"Tasks data retrieved: {json.dumps(tasks_info)}")
         except Exception as e:
             raise APIRouteError(f"Failed to retrieve tasks data: {e}")
-        
+
         # Prepare response
         response_data = {
             "tasks": tasks_data,
             "count": len(tasks_data) if isinstance(tasks_data, list) else 0,
             "timestamp": datetime.now().isoformat(),
             "request_id": request_id,
-            "response_time_ms": round((time.time() - request_start) * 1000, 3)
+            "response_time_ms": round((time.time() - request_start) * 1000, 3),
         }
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
@@ -432,12 +466,12 @@ def get_tasks():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(request_duration, 3),
-            "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0
+            "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0,
         }
         logger.info(f"API tasks request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(response_data)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -448,60 +482,66 @@ def get_tasks():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API tasks request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve tasks",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@api_bp.route('/approvals')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve tasks",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@api_bp.route("/approvals")
 def get_approvals():
     """Get approvals data from ORCH/STATE/APPROVALS.md"""
     request_start = time.time()
     request_id = f"approvals_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
             "event": "api_approvals_request_start",
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
-            "remote_addr": request.remote_addr
+            "remote_addr": request.remote_addr,
         }
         logger.info(f"API approvals request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(api_bp, 'dashboard_instance') or api_bp.dashboard_instance is None:
+        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
             raise APIRouteError("Dashboard instance not available")
-        
+
         # Get approvals data from dashboard instance
         try:
             approvals_data = api_bp.dashboard_instance._get_approvals_data()
-            
+
             approvals_info = {
                 "event": "api_approvals_data_retrieved",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0
+                "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0,
             }
             logger.info(f"Approvals data retrieved: {json.dumps(approvals_info)}")
         except Exception as e:
             raise APIRouteError(f"Failed to retrieve approvals data: {e}")
-        
+
         # Prepare response
         response_data = {
             "approvals": approvals_data,
             "count": len(approvals_data) if isinstance(approvals_data, list) else 0,
             "timestamp": datetime.now().isoformat(),
             "request_id": request_id,
-            "response_time_ms": round((time.time() - request_start) * 1000, 3)
+            "response_time_ms": round((time.time() - request_start) * 1000, 3),
         }
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
@@ -509,12 +549,12 @@ def get_approvals():
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(request_duration, 3),
-            "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0
+            "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0,
         }
         logger.info(f"API approvals request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(response_data)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -525,71 +565,81 @@ def get_approvals():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API approvals request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve approvals",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@api_bp.route('/metrics')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve approvals",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@api_bp.route("/metrics")
 def get_metrics():
     """Get quality metrics from actual data"""
     request_start = time.time()
     request_id = f"metrics_{int(time.time() * 1000)}"
-    
+
     try:
         # Log request start
         request_info = {
             "event": "api_metrics_request_start",
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
-            "remote_addr": request.remote_addr
+            "remote_addr": request.remote_addr,
         }
         logger.info(f"API metrics request started: {json.dumps(request_info)}")
-        
+
         # Check if dashboard instance is available
-        if not hasattr(api_bp, 'dashboard_instance') or api_bp.dashboard_instance is None:
+        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
             raise APIRouteError("Dashboard instance not available")
-        
+
         # Get metrics data from dashboard instance
         try:
             metrics_data = api_bp.dashboard_instance._get_quality_metrics()
-            
+
             metrics_info = {
                 "event": "api_metrics_data_retrieved",
                 "request_id": request_id,
                 "timestamp": datetime.now().isoformat(),
-                "metrics_keys": list(metrics_data.keys()) if isinstance(metrics_data, dict) else "non_dict_response"
+                "metrics_keys": (
+                    list(metrics_data.keys())
+                    if isinstance(metrics_data, dict)
+                    else "non_dict_response"
+                ),
             }
             logger.info(f"Metrics data retrieved: {json.dumps(metrics_info)}")
         except Exception as e:
             raise APIRouteError(f"Failed to retrieve metrics data: {e}")
-        
+
         # Prepare response
         response_data = {
             "metrics": metrics_data,
             "timestamp": datetime.now().isoformat(),
             "request_id": request_id,
-            "response_time_ms": round((time.time() - request_start) * 1000, 3)
+            "response_time_ms": round((time.time() - request_start) * 1000, 3),
         }
-        
+
         # Log successful response
         request_duration = time.time() - request_start
         success_info = {
             "event": "api_metrics_request_complete",
             "request_id": request_id,
             "timestamp": datetime.now().isoformat(),
-            "duration_seconds": round(request_duration, 3)
+            "duration_seconds": round(request_duration, 3),
         }
         logger.info(f"API metrics request completed: {json.dumps(success_info)}")
-        
+
         return jsonify(response_data)
-        
+
     except Exception as e:
         # Log request failure
         request_duration = time.time() - request_start
@@ -600,57 +650,66 @@ def get_metrics():
             "duration_seconds": round(request_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"API metrics request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": "Failed to retrieve metrics",
-            "request_id": request_id,
-            "timestamp": datetime.now().isoformat(),
-            "details": str(e)
-        }), 500
 
-@api_bp.route('/health')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to retrieve metrics",
+                    "request_id": request_id,
+                    "timestamp": datetime.now().isoformat(),
+                    "details": str(e),
+                }
+            ),
+            500,
+        )
+
+
+@api_bp.route("/health")
 def api_health_check():
     """Simple API health check endpoint"""
     try:
         health_start = time.time()
-        
+
         # Basic health check
         health_data = {
             "status": "healthy",
             "timestamp": datetime.now().isoformat(),
             "api_version": "1.0.0",
-            "dashboard_instance_available": hasattr(api_bp, 'dashboard_instance') and api_bp.dashboard_instance is not None,
-            "response_time_ms": round((time.time() - health_start) * 1000, 3)
+            "dashboard_instance_available": hasattr(api_bp, "dashboard_instance")
+            and api_bp.dashboard_instance is not None,
+            "response_time_ms": round((time.time() - health_start) * 1000, 3),
         }
-        
+
         # Log health check
         health_info = {
             "event": "api_health_check",
             "timestamp": datetime.now().isoformat(),
-            "status": "healthy"
+            "status": "healthy",
         }
         logger.info(f"API health check completed: {json.dumps(health_info)}")
-        
+
         return jsonify(health_data)
-        
+
     except Exception as e:
         # Log health check failure
         error_info = {
             "event": "api_health_check_failed",
             "timestamp": datetime.now().isoformat(),
             "error": str(e),
-            "error_type": type(e).__name__
+            "error_type": type(e).__name__,
         }
         logger.error(f"API health check failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "status": "unhealthy",
-            "error": str(e),
-            "timestamp": datetime.now().isoformat()
-        }), 500
+
+        return (
+            jsonify(
+                {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}
+            ),
+            500,
+        )
+
 
 @api_bp.errorhandler(APIRouteError)
 def handle_api_route_error(error):
@@ -659,15 +718,21 @@ def handle_api_route_error(error):
         "event": "api_route_error_handled",
         "timestamp": datetime.now().isoformat(),
         "error": str(error),
-        "error_type": type(error).__name__
+        "error_type": type(error).__name__,
     }
     logger.error(f"API route error handled: {json.dumps(error_info)}")
-    
-    return jsonify({
-        "error": "API route error",
-        "message": str(error),
-        "timestamp": datetime.now().isoformat()
-    }), 500
+
+    return (
+        jsonify(
+            {
+                "error": "API route error",
+                "message": str(error),
+                "timestamp": datetime.now().isoformat(),
+            }
+        ),
+        500,
+    )
+
 
 @api_bp.errorhandler(Exception)
 def handle_general_error(error):
@@ -677,14 +742,20 @@ def handle_general_error(error):
         "timestamp": datetime.now().isoformat(),
         "error": str(error),
         "error_type": type(error).__name__,
-        "traceback": traceback.format_exc()
+        "traceback": traceback.format_exc(),
     }
     logger.error(f"API general error handled: {json.dumps(error_info)}")
-    
-    return jsonify({
-        "error": "Internal server error",
-        "message": "An unexpected error occurred",
-        "timestamp": datetime.now().isoformat()
-    }), 500
-
-__all__ = ['api_bp', 'init_api_routes']
\ No newline at end of file
+
+    return (
+        jsonify(
+            {
+                "error": "Internal server error",
+                "message": "An unexpected error occurred",
+                "timestamp": datetime.now().isoformat(),
+            }
+        ),
+        500,
+    )
+
+
+__all__ = ["api_bp", "init_api_routes"]
diff --git a/src/blueprints/sse_routes.py b/src/blueprints/sse_routes.py
index d3d4ba0..343148f 100644
--- a/src/blueprints/sse_routes.py
+++ b/src/blueprints/sse_routes.py
@@ -3,25 +3,29 @@ SSE (Server-Sent Events) Blueprint for ORCH Dashboard
 Handles real-time communication with enhanced error handling and monitoring
 """
 
-import logging
 import json
-import traceback
-import time
+import logging
 import threading
+import time
+import traceback
 from datetime import datetime
-from flask import Blueprint, Response, request, jsonify
 from typing import Dict, List, Optional
 
+from flask import Blueprint, Response, jsonify, request
+
 # Configure structured logging
 logger = logging.getLogger(__name__)
 
+
 class SSEConnectionError(Exception):
     """Custom exception for SSE connection failures"""
+
     pass
 
+
 class SSEManager:
     """Enhanced SSE Manager with comprehensive error handling and monitoring"""
-    
+
     def __init__(self):
         self.clients: Dict[str, dict] = {}
         self.connection_stats = {
@@ -29,18 +33,18 @@ class SSEManager:
             "active_connections": 0,
             "failed_connections": 0,
             "total_messages_sent": 0,
-            "last_activity": None
+            "last_activity": None,
         }
         self.lock = threading.Lock()
-        
+
         # Log SSE Manager initialization
         init_info = {
             "event": "sse_manager_initialized",
             "timestamp": datetime.now().isoformat(),
-            "initial_stats": self.connection_stats
+            "initial_stats": self.connection_stats,
         }
         logger.info(f"SSE Manager initialized: {json.dumps(init_info)}")
-    
+
     def add_client(self, client_id: str, request_info: dict = None) -> bool:
         """Add a client with enhanced error handling and monitoring"""
         try:
@@ -52,10 +56,10 @@ class SSEManager:
                         "client_id": client_id,
                         "timestamp": datetime.now().isoformat(),
                         "previous_connection": self.clients[client_id].get("connected_at"),
-                        "request_info": request_info
+                        "request_info": request_info,
                     }
                     logger.warning(f"Client reconnection detected: {json.dumps(existing_info)}")
-                
+
                 # Create client record with comprehensive metadata
                 client_record = {
                     "connected_at": datetime.now().isoformat(),
@@ -63,25 +67,25 @@ class SSEManager:
                     "message_count": 0,
                     "user_agent": request_info.get("user_agent") if request_info else "Unknown",
                     "remote_addr": request_info.get("remote_addr") if request_info else "Unknown",
-                    "connection_id": f"{client_id}_{int(time.time())}"
+                    "connection_id": f"{client_id}_{int(time.time())}",
                 }
-                
+
                 self.clients[client_id] = client_record
                 self.connection_stats["total_connections"] += 1
                 self.connection_stats["active_connections"] = len(self.clients)
                 self.connection_stats["last_activity"] = datetime.now().isoformat()
-                
+
                 # Log successful client addition
                 success_info = {
                     "event": "sse_client_added",
                     "client_id": client_id,
                     "timestamp": datetime.now().isoformat(),
                     "connection_stats": self.connection_stats,
-                    "client_record": client_record
+                    "client_record": client_record,
                 }
                 logger.info(f"SSE client added successfully: {json.dumps(success_info)}")
                 return True
-                
+
         except Exception as e:
             # Log client addition failure
             error_info = {
@@ -91,23 +95,23 @@ class SSEManager:
                 "error": str(e),
                 "error_type": type(e).__name__,
                 "traceback": traceback.format_exc(),
-                "request_info": request_info
+                "request_info": request_info,
             }
             logger.error(f"Failed to add SSE client: {json.dumps(error_info)}")
             self.connection_stats["failed_connections"] += 1
             return False
-    
+
     def remove_client(self, client_id: str, reason: str = "normal_disconnect") -> bool:
         """Remove a client with enhanced logging and cleanup"""
         try:
             with self.lock:
                 if client_id in self.clients:
                     client_record = self.clients[client_id]
-                    
+
                     # Calculate connection duration
                     connected_at = datetime.fromisoformat(client_record["connected_at"])
                     duration = (datetime.now() - connected_at).total_seconds()
-                    
+
                     # Log client removal with statistics
                     removal_info = {
                         "event": "sse_client_removed",
@@ -116,13 +120,13 @@ class SSEManager:
                         "reason": reason,
                         "connection_duration_seconds": round(duration, 3),
                         "messages_sent": client_record.get("message_count", 0),
-                        "connection_stats_before": dict(self.connection_stats)
+                        "connection_stats_before": dict(self.connection_stats),
                     }
-                    
+
                     del self.clients[client_id]
                     self.connection_stats["active_connections"] = len(self.clients)
                     self.connection_stats["last_activity"] = datetime.now().isoformat()
-                    
+
                     removal_info["connection_stats_after"] = dict(self.connection_stats)
                     logger.info(f"SSE client removed: {json.dumps(removal_info)}")
                     return True
@@ -133,11 +137,13 @@ class SSEManager:
                         "client_id": client_id,
                         "timestamp": datetime.now().isoformat(),
                         "reason": reason,
-                        "active_clients": list(self.clients.keys())
+                        "active_clients": list(self.clients.keys()),
                     }
-                    logger.warning(f"Attempted to remove non-existent SSE client: {json.dumps(warning_info)}")
+                    logger.warning(
+                        f"Attempted to remove non-existent SSE client: {json.dumps(warning_info)}"
+                    )
                     return False
-                    
+
         except Exception as e:
             # Log client removal failure
             error_info = {
@@ -147,39 +153,34 @@ class SSEManager:
                 "error": str(e),
                 "error_type": type(e).__name__,
                 "traceback": traceback.format_exc(),
-                "reason": reason
+                "reason": reason,
             }
             logger.error(f"Failed to remove SSE client: {json.dumps(error_info)}")
             return False
-    
+
     def broadcast_message(self, message: dict, target_clients: Optional[List[str]] = None) -> dict:
         """Broadcast message with comprehensive error handling and delivery tracking"""
         broadcast_start = time.time()
-        delivery_stats = {
-            "attempted": 0,
-            "successful": 0,
-            "failed": 0,
-            "failed_clients": []
-        }
-        
+        delivery_stats = {"attempted": 0, "successful": 0, "failed": 0, "failed_clients": []}
+
         try:
             with self.lock:
                 # Determine target clients
                 if target_clients is None:
                     target_clients = list(self.clients.keys())
-                
+
                 delivery_stats["attempted"] = len(target_clients)
-                
+
                 # Log broadcast start
                 broadcast_info = {
                     "event": "sse_broadcast_start",
                     "timestamp": datetime.now().isoformat(),
                     "message_type": message.get("type", "unknown"),
                     "target_clients": target_clients,
-                    "total_active_clients": len(self.clients)
+                    "total_active_clients": len(self.clients),
                 }
                 logger.info(f"SSE broadcast starting: {json.dumps(broadcast_info)}")
-                
+
                 # Broadcast to each target client
                 for client_id in target_clients:
                     try:
@@ -190,23 +191,24 @@ class SSEManager:
                             delivery_stats["successful"] += 1
                         else:
                             delivery_stats["failed"] += 1
-                            delivery_stats["failed_clients"].append({
-                                "client_id": client_id,
-                                "reason": "client_not_found"
-                            })
-                            
+                            delivery_stats["failed_clients"].append(
+                                {"client_id": client_id, "reason": "client_not_found"}
+                            )
+
                     except Exception as e:
                         delivery_stats["failed"] += 1
-                        delivery_stats["failed_clients"].append({
-                            "client_id": client_id,
-                            "reason": str(e),
-                            "error_type": type(e).__name__
-                        })
-                
+                        delivery_stats["failed_clients"].append(
+                            {
+                                "client_id": client_id,
+                                "reason": str(e),
+                                "error_type": type(e).__name__,
+                            }
+                        )
+
                 # Update global statistics
                 self.connection_stats["total_messages_sent"] += delivery_stats["successful"]
                 self.connection_stats["last_activity"] = datetime.now().isoformat()
-                
+
                 # Log broadcast completion
                 broadcast_duration = time.time() - broadcast_start
                 completion_info = {
@@ -215,16 +217,16 @@ class SSEManager:
                     "duration_seconds": round(broadcast_duration, 3),
                     "delivery_stats": delivery_stats,
                     "message_type": message.get("type", "unknown"),
-                    "updated_connection_stats": dict(self.connection_stats)
+                    "updated_connection_stats": dict(self.connection_stats),
                 }
                 logger.info(f"SSE broadcast completed: {json.dumps(completion_info)}")
-                
+
                 return {
                     "success": True,
                     "delivery_stats": delivery_stats,
-                    "duration_seconds": round(broadcast_duration, 3)
+                    "duration_seconds": round(broadcast_duration, 3),
                 }
-                
+
         except Exception as e:
             # Log broadcast failure
             error_info = {
@@ -234,16 +236,12 @@ class SSEManager:
                 "error_type": type(e).__name__,
                 "traceback": traceback.format_exc(),
                 "message_type": message.get("type", "unknown"),
-                "delivery_stats": delivery_stats
+                "delivery_stats": delivery_stats,
             }
             logger.error(f"SSE broadcast failed: {json.dumps(error_info)}")
-            
-            return {
-                "success": False,
-                "error": str(e),
-                "delivery_stats": delivery_stats
-            }
-    
+
+            return {"success": False, "error": str(e), "delivery_stats": delivery_stats}
+
     def get_connection_stats(self) -> dict:
         """Get comprehensive connection statistics"""
         try:
@@ -256,71 +254,73 @@ class SSEManager:
                             "last_activity": client_data["last_activity"],
                             "message_count": client_data["message_count"],
                             "connection_duration_seconds": round(
-                                (datetime.now() - datetime.fromisoformat(client_data["connected_at"])).total_seconds(), 3
-                            )
+                                (
+                                    datetime.now()
+                                    - datetime.fromisoformat(client_data["connected_at"])
+                                ).total_seconds(),
+                                3,
+                            ),
                         }
                         for client_id, client_data in self.clients.items()
                     },
-                    "timestamp": datetime.now().isoformat()
+                    "timestamp": datetime.now().isoformat(),
                 }
                 return stats
-                
+
         except Exception as e:
             error_info = {
                 "event": "sse_stats_retrieval_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Failed to retrieve SSE stats: {json.dumps(error_info)}")
             return {"error": str(e), "timestamp": datetime.now().isoformat()}
-    
+
     def cleanup_stale_connections(self, max_idle_seconds: int = 300) -> dict:
         """Clean up stale connections with detailed logging"""
         cleanup_start = time.time()
-        cleanup_stats = {
-            "checked": 0,
-            "removed": 0,
-            "stale_clients": []
-        }
-        
+        cleanup_stats = {"checked": 0, "removed": 0, "stale_clients": []}
+
         try:
             with self.lock:
                 current_time = datetime.now()
                 clients_to_remove = []
-                
+
                 for client_id, client_data in self.clients.items():
                     cleanup_stats["checked"] += 1
                     last_activity = datetime.fromisoformat(client_data["last_activity"])
                     idle_seconds = (current_time - last_activity).total_seconds()
-                    
+
                     if idle_seconds > max_idle_seconds:
                         clients_to_remove.append(client_id)
-                        cleanup_stats["stale_clients"].append({
-                            "client_id": client_id,
-                            "idle_seconds": round(idle_seconds, 3),
-                            "last_activity": client_data["last_activity"]
-                        })
-                
+                        cleanup_stats["stale_clients"].append(
+                            {
+                                "client_id": client_id,
+                                "idle_seconds": round(idle_seconds, 3),
+                                "last_activity": client_data["last_activity"],
+                            }
+                        )
+
                 # Remove stale clients
                 for client_id in clients_to_remove:
                     if self.remove_client(client_id, "stale_connection_cleanup"):
                         cleanup_stats["removed"] += 1
-                
+
                 cleanup_duration = time.time() - cleanup_start
-                
+
                 # Log cleanup results
                 cleanup_info = {
                     "event": "sse_stale_cleanup_complete",
                     "timestamp": datetime.now().isoformat(),
                     "duration_seconds": round(cleanup_duration, 3),
                     "max_idle_seconds": max_idle_seconds,
-                    "cleanup_stats": cleanup_stats
+                    "cleanup_stats": cleanup_stats,
                 }
                 logger.info(f"SSE stale connection cleanup completed: {json.dumps(cleanup_info)}")
-                
+
                 return cleanup_stats
-                
+
         except Exception as e:
             error_info = {
                 "event": "sse_stale_cleanup_failed",
@@ -328,18 +328,19 @@ class SSEManager:
                 "error": str(e),
                 "error_type": type(e).__name__,
                 "traceback": traceback.format_exc(),
-                "cleanup_stats": cleanup_stats
+                "cleanup_stats": cleanup_stats,
             }
             logger.error(f"SSE stale connection cleanup failed: {json.dumps(error_info)}")
             return {"error": str(e), "cleanup_stats": cleanup_stats}
 
+
 # Global SSE manager instance with initialization error handling
 try:
     sse_manager = SSEManager()
     manager_init_info = {
         "event": "global_sse_manager_created",
         "timestamp": datetime.now().isoformat(),
-        "manager_id": id(sse_manager)
+        "manager_id": id(sse_manager),
     }
     logger.info(f"Global SSE manager created successfully: {json.dumps(manager_init_info)}")
 except Exception as e:
@@ -348,18 +349,18 @@ except Exception as e:
         "timestamp": datetime.now().isoformat(),
         "error": str(e),
         "error_type": type(e).__name__,
-        "traceback": traceback.format_exc()
+        "traceback": traceback.format_exc(),
     }
     logger.error(f"Failed to create global SSE manager: {json.dumps(error_info)}")
     raise SSEConnectionError(f"Failed to initialize SSE manager: {e}") from e
 
 # Create Blueprint with error handling
 try:
-    sse_bp = Blueprint('sse', __name__)
+    sse_bp = Blueprint("sse", __name__)
     blueprint_info = {
         "event": "sse_blueprint_created",
         "timestamp": datetime.now().isoformat(),
-        "blueprint_name": "sse"
+        "blueprint_name": "sse",
     }
     logger.info(f"SSE Blueprint created: {json.dumps(blueprint_info)}")
 except Exception as e:
@@ -367,28 +368,29 @@ except Exception as e:
         "event": "sse_blueprint_creation_failed",
         "timestamp": datetime.now().isoformat(),
         "error": str(e),
-        "error_type": type(e).__name__
+        "error_type": type(e).__name__,
     }
     logger.error(f"Failed to create SSE Blueprint: {json.dumps(error_info)}")
     raise
 
+
 def init_sse_routes(dashboard_instance):
     """Initialize SSE routes with enhanced error handling and monitoring"""
     init_start = time.time()
-    
+
     try:
         # Log initialization start
         init_info = {
             "event": "sse_routes_init_start",
             "timestamp": datetime.now().isoformat(),
-            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None
+            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
         }
         logger.info(f"SSE routes initialization starting: {json.dumps(init_info)}")
-        
+
         # Validate dashboard instance
         if dashboard_instance is None:
             raise ValueError("Dashboard instance is required for SSE initialization")
-        
+
         # Store dashboard instance reference with error handling
         try:
             sse_bp.dashboard_instance = dashboard_instance
@@ -396,29 +398,31 @@ def init_sse_routes(dashboard_instance):
                 "event": "sse_dashboard_instance_injected",
                 "timestamp": datetime.now().isoformat(),
                 "instance_type": type(dashboard_instance).__name__,
-                "instance_id": id(dashboard_instance)
+                "instance_id": id(dashboard_instance),
             }
-            logger.info(f"Dashboard instance injected into SSE Blueprint: {json.dumps(instance_info)}")
+            logger.info(
+                f"Dashboard instance injected into SSE Blueprint: {json.dumps(instance_info)}"
+            )
         except Exception as e:
             error_info = {
                 "event": "sse_dashboard_instance_injection_failed",
                 "timestamp": datetime.now().isoformat(),
                 "error": str(e),
-                "error_type": type(e).__name__
+                "error_type": type(e).__name__,
             }
             logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
             raise
-        
+
         # Log successful initialization
         init_duration = time.time() - init_start
         success_info = {
             "event": "sse_routes_init_complete",
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(init_duration, 3),
-            "manager_stats": sse_manager.get_connection_stats()
+            "manager_stats": sse_manager.get_connection_stats(),
         }
         logger.info(f"SSE routes initialized successfully: {json.dumps(success_info)}")
-        
+
     except Exception as e:
         # Log initialization failure
         init_duration = time.time() - init_start
@@ -428,17 +432,18 @@ def init_sse_routes(dashboard_instance):
             "duration_seconds": round(init_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"SSE routes initialization failed: {json.dumps(error_info)}")
         raise SSEConnectionError(f"Failed to initialize SSE routes: {e}") from e
 
-@sse_bp.route('/events')
+
+@sse_bp.route("/events")
 def events():
     """SSE endpoint with comprehensive error handling and monitoring"""
     connection_start = time.time()
     client_id = f"client_{int(time.time() * 1000)}_{request.remote_addr}"
-    
+
     try:
         # Log connection attempt
         connection_info = {
@@ -447,21 +452,21 @@ def events():
             "timestamp": datetime.now().isoformat(),
             "remote_addr": request.remote_addr,
             "user_agent": request.headers.get("User-Agent", "Unknown"),
-            "headers": dict(request.headers)
+            "headers": dict(request.headers),
         }
         logger.info(f"SSE connection attempt: {json.dumps(connection_info)}")
-        
+
         # Prepare request info for client registration
         request_info = {
             "remote_addr": request.remote_addr,
             "user_agent": request.headers.get("User-Agent", "Unknown"),
-            "timestamp": datetime.now().isoformat()
+            "timestamp": datetime.now().isoformat(),
         }
-        
+
         # Add client to SSE manager
         if not sse_manager.add_client(client_id, request_info):
             raise SSEConnectionError("Failed to register SSE client")
-        
+
         def generate():
             """Generate SSE events with error handling"""
             try:
@@ -470,35 +475,35 @@ def events():
                     "type": "connection_established",
                     "client_id": client_id,
                     "timestamp": datetime.now().isoformat(),
-                    "server_info": "ORCH Dashboard SSE"
+                    "server_info": "ORCH Dashboard SSE",
                 }
                 yield f"data: {json.dumps(initial_message)}\n\n"
-                
+
                 # Send periodic heartbeat and data
                 while True:
                     try:
                         # Check if client still exists
                         if client_id not in sse_manager.clients:
                             break
-                        
+
                         # Send heartbeat
                         heartbeat_message = {
                             "type": "heartbeat",
                             "timestamp": datetime.now().isoformat(),
                             "client_id": client_id,
-                            "connection_stats": sse_manager.get_connection_stats()
+                            "connection_stats": sse_manager.get_connection_stats(),
                         }
                         yield f"data: {json.dumps(heartbeat_message)}\n\n"
-                        
+
                         time.sleep(30)  # 30-second heartbeat interval
-                        
+
                     except GeneratorExit:
                         # Client disconnected
                         disconnect_info = {
                             "event": "sse_client_generator_exit",
                             "client_id": client_id,
                             "timestamp": datetime.now().isoformat(),
-                            "reason": "generator_exit"
+                            "reason": "generator_exit",
                         }
                         logger.info(f"SSE client generator exit: {json.dumps(disconnect_info)}")
                         break
@@ -509,11 +514,11 @@ def events():
                             "client_id": client_id,
                             "timestamp": datetime.now().isoformat(),
                             "error": str(e),
-                            "error_type": type(e).__name__
+                            "error_type": type(e).__name__,
                         }
                         logger.error(f"SSE generation error: {json.dumps(error_info)}")
                         break
-                        
+
             except Exception as e:
                 # Log generator failure
                 error_info = {
@@ -522,19 +527,19 @@ def events():
                     "timestamp": datetime.now().isoformat(),
                     "error": str(e),
                     "error_type": type(e).__name__,
-                    "traceback": traceback.format_exc()
+                    "traceback": traceback.format_exc(),
                 }
                 logger.error(f"SSE generator failed: {json.dumps(error_info)}")
             finally:
                 # Clean up client connection
                 sse_manager.remove_client(client_id, "generator_cleanup")
-        
+
         # Create SSE response
-        response = Response(generate(), mimetype='text/event-stream')
-        response.headers['Cache-Control'] = 'no-cache'
-        response.headers['Connection'] = 'keep-alive'
-        response.headers['Access-Control-Allow-Origin'] = '*'
-        
+        response = Response(generate(), mimetype="text/event-stream")
+        response.headers["Cache-Control"] = "no-cache"
+        response.headers["Connection"] = "keep-alive"
+        response.headers["Access-Control-Allow-Origin"] = "*"
+
         # Log successful connection establishment
         connection_duration = time.time() - connection_start
         success_info = {
@@ -542,12 +547,12 @@ def events():
             "client_id": client_id,
             "timestamp": datetime.now().isoformat(),
             "setup_duration_seconds": round(connection_duration, 3),
-            "response_headers": dict(response.headers)
+            "response_headers": dict(response.headers),
         }
         logger.info(f"SSE connection established: {json.dumps(success_info)}")
-        
+
         return response
-        
+
     except Exception as e:
         # Log connection failure
         connection_duration = time.time() - connection_start
@@ -558,55 +563,63 @@ def events():
             "setup_duration_seconds": round(connection_duration, 3),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"SSE connection failed: {json.dumps(error_info)}")
-        
+
         # Clean up any partial client registration
         sse_manager.remove_client(client_id, "connection_failure")
-        
-        return jsonify({
-            "error": "Failed to establish SSE connection",
-            "client_id": client_id,
-            "timestamp": datetime.now().isoformat()
-        }), 500
 
-@sse_bp.route('/events/health')
+        return (
+            jsonify(
+                {
+                    "error": "Failed to establish SSE connection",
+                    "client_id": client_id,
+                    "timestamp": datetime.now().isoformat(),
+                }
+            ),
+            500,
+        )
+
+
+@sse_bp.route("/events/health")
 def events_health():
     """SSE health check endpoint with comprehensive monitoring"""
     try:
         health_start = time.time()
-        
+
         # Get comprehensive health information
         connection_stats = sse_manager.get_connection_stats()
-        
+
         # Perform stale connection cleanup
         cleanup_stats = sse_manager.cleanup_stale_connections()
-        
+
         health_duration = time.time() - health_start
-        
+
         health_data = {
             "status": "healthy",
             "timestamp": datetime.now().isoformat(),
             "sse_manager": {
                 "connection_stats": connection_stats,
                 "cleanup_stats": cleanup_stats,
-                "manager_id": id(sse_manager)
+                "manager_id": id(sse_manager),
             },
-            "health_check_duration_seconds": round(health_duration, 3)
+            "health_check_duration_seconds": round(health_duration, 3),
         }
-        
+
         # Log health check
         health_info = {
             "event": "sse_health_check",
             "timestamp": datetime.now().isoformat(),
             "duration_seconds": round(health_duration, 3),
-            "active_connections": connection_stats.get("connection_stats", {}).get("active_connections", 0)
+            "active_connections": connection_stats.get("connection_stats", {}).get(
+                "active_connections", 0
+            ),
         }
         logger.info(f"SSE health check completed: {json.dumps(health_info)}")
-        
+
         return jsonify(health_data)
-        
+
     except Exception as e:
         # Log health check failure
         error_info = {
@@ -614,41 +627,40 @@ def events_health():
             "timestamp": datetime.now().isoformat(),
             "error": str(e),
             "error_type": type(e).__name__,
-            "traceback": traceback.format_exc()
+            "traceback": traceback.format_exc(),
         }
         logger.error(f"SSE health check failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "status": "unhealthy",
-            "error": str(e),
-            "timestamp": datetime.now().isoformat()
-        }), 500
 
-@sse_bp.route('/events/stats')
+        return (
+            jsonify(
+                {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}
+            ),
+            500,
+        )
+
+
+@sse_bp.route("/events/stats")
 def events_stats():
     """Get detailed SSE statistics"""
     try:
         stats = sse_manager.get_connection_stats()
-        
+
         stats_info = {
             "event": "sse_stats_requested",
             "timestamp": datetime.now().isoformat(),
-            "active_connections": stats.get("connection_stats", {}).get("active_connections", 0)
+            "active_connections": stats.get("connection_stats", {}).get("active_connections", 0),
         }
         logger.info(f"SSE stats requested: {json.dumps(stats_info)}")
-        
+
         return jsonify(stats)
-        
+
     except Exception as e:
         error_info = {
             "event": "sse_stats_request_failed",
             "timestamp": datetime.now().isoformat(),
             "error": str(e),
-            "error_type": type(e).__name__
+            "error_type": type(e).__name__,
         }
         logger.error(f"SSE stats request failed: {json.dumps(error_info)}")
-        
-        return jsonify({
-            "error": str(e),
-            "timestamp": datetime.now().isoformat()
-        }), 500
\ No newline at end of file
+
+        return jsonify({"error": str(e), "timestamp": datetime.now().isoformat()}), 500
diff --git a/src/blueprints/ui_routes.py b/src/blueprints/ui_routes.py
index 636307e..8c3891c 100644
--- a/src/blueprints/ui_routes.py
+++ b/src/blueprints/ui_routes.py
@@ -3,12 +3,14 @@ UI Routes Blueprint
 Handles all user interface routes for the ORCH Dashboard
 """
 
-from flask import Blueprint, render_template
 import logging
 
-ui_bp = Blueprint('ui', __name__)
+from flask import Blueprint, render_template
+
+ui_bp = Blueprint("ui", __name__)
 logger = logging.getLogger(__name__)
 
+
 @ui_bp.route("/")
 @ui_bp.route("/dashboard")
 def dashboard():
@@ -16,68 +18,79 @@ def dashboard():
     logger.info("Serving main dashboard page")
     return render_template("dashboard.html", title="ORCH統合管理システム")
 
+
 @ui_bp.route("/tasks")
 def tasks_page():
     """Tasks management page"""
     logger.info("Serving tasks management page")
     return render_template("tasks.html", title="タスク管理")
 
+
 @ui_bp.route("/approvals")
 def approvals_page():
     """Approvals management page"""
     logger.info("Serving approvals management page")
     return render_template("approvals.html", title="承認管理")
 
+
 @ui_bp.route("/ml")
 def ml_page():
     """Machine Learning page"""
     logger.info("Serving ML page")
     return render_template("dashboard.html", title="機械学習")
 
+
 @ui_bp.route("/ps1")
 def ps1_page():
     """PowerShell scripts page"""
     logger.info("Serving PS1 page")
     return render_template("dashboard.html", title="PowerShellスクリプト")
 
+
 @ui_bp.route("/results")
 def results_page():
     """Results page"""
     logger.info("Serving results page")
     return render_template("dashboard.html", title="実行結果")
 
+
 @ui_bp.route("/tasks/new")
 def new_task_page():
     """New task creation page"""
     logger.info("Serving new task page")
     return render_template("dashboard.html", title="新規タスク作成")
 
+
 @ui_bp.route("/realtime")
 def realtime_page():
     """Real-time monitoring page"""
     logger.info("Serving realtime page")
     return render_template("dashboard.html", title="リアルタイム監視")
 
+
 @ui_bp.route("/agents")
 def agents_page():
     """Agents management page"""
     logger.info("Serving agents page")
     return render_template("agents.html", title="エージェント管理")
 
+
 @ui_bp.route("/console")
 def console_page():
     """Console page"""
     logger.info("Serving console page")
     return render_template("dashboard.html", title="コンソール")
 
+
 @ui_bp.route("/monitoring")
 def monitoring_page():
     """Monitoring page"""
     logger.info("Serving monitoring page")
     return render_template("dashboard.html", title="監視")
 
+
 @ui_bp.route("/security")
 def security_page():
     """Security page"""
     logger.info("Serving security page")
-    return render_template("dashboard.html", title="セキュリティ")
\ No newline at end of file
+    return render_template("dashboard.html", title="セキュリティ")
diff --git a/src/dashboard.py b/src/dashboard.py
index 0f4f558..69ad4bb 100644
--- a/src/dashboard.py
+++ b/src/dashboard.py
@@ -17,84 +17,95 @@ from src.ai_prediction import QualityPredictor
 # 静的ファイルのパスを正しく設定
 current_dir = os.path.dirname(os.path.abspath(__file__))
 project_root = os.path.dirname(current_dir)
-static_folder = os.path.join(project_root, 'static')
-template_folder = os.path.join(project_root, 'templates')
+static_folder = os.path.join(project_root, "static")
+template_folder = os.path.join(project_root, "templates")
 
 app = Flask(__name__, static_folder=static_folder, template_folder=template_folder)
 
-@app.route('/healthz', methods=['GET'])
+
+@app.route("/healthz", methods=["GET"])
 def healthz():
     """ヘルスチェック: サーバが稼働しているか確認"""
     return jsonify({"status": "ok", "time": datetime.now().isoformat()}), 200
 
+
 # Style Manager統合
 try:
     from src.style_manager import StyleManager
+
     # Style Managerのルートを統合
     style_manager = StyleManager()
-    
-    @app.route('/api/pages', methods=['GET'])
+
+    @app.route("/api/pages", methods=["GET"])
     def get_available_pages():
         """利用可能なページ一覧を取得"""
         pages = [
-            {"url": "/dashboard", "name": "ダッシュボード", "description": "メインダッシュボード画面"},
+            {
+                "url": "/dashboard",
+                "name": "ダッシュボード",
+                "description": "メインダッシュボード画面",
+            },
             {"url": "/tasks", "name": "タスク管理", "description": "タスク一覧と管理画面"},
             {"url": "/agents", "name": "エージェント", "description": "AI エージェント管理画面"},
-            {"url": "/style-manager", "name": "スタイル管理", "description": "UIスタイル管理画面"}
+            {"url": "/style-manager", "name": "スタイル管理", "description": "UIスタイル管理画面"},
         ]
         return jsonify(pages)
-    
-    @app.route('/api/styles', methods=['GET'])
+
+    @app.route("/api/styles", methods=["GET"])
     def get_styles():
         """現在のスタイル設定を取得"""
         return jsonify(style_manager.styles)
-    
-    @app.route('/api/styles', methods=['POST'])
+
+    @app.route("/api/styles", methods=["POST"])
     def update_styles():
         """スタイル設定を更新"""
         try:
             data = request.get_json()
             if not data:
                 return jsonify({"error": "データが必要です"}), 400
-            
-            if 'key' in data and 'value' in data:
+
+            if "key" in data and "value" in data:
                 # 単一更新
-                success = style_manager.update_style(data['key'], data['value'])
-            elif 'styles' in data:
+                success = style_manager.update_style(data["key"], data["value"])
+            elif "styles" in data:
                 # 一括更新
-                success = style_manager.update_multiple_styles(data['styles'])
+                success = style_manager.update_multiple_styles(data["styles"])
             else:
                 return jsonify({"error": "無効なデータ形式"}), 400
-            
+
             if success:
-                return jsonify({
-                    "success": True, 
-                    "styles": style_manager.styles,
-                    "message": "スタイルが更新されました"
-                })
+                return jsonify(
+                    {
+                        "success": True,
+                        "styles": style_manager.styles,
+                        "message": "スタイルが更新されました",
+                    }
+                )
             else:
                 return jsonify({"error": "スタイル更新に失敗しました"}), 500
-                
+
         except Exception as e:
             return jsonify({"error": f"エラー: {str(e)}"}), 500
-    
-    @app.route('/api/styles/reset', methods=['POST'])
+
+    @app.route("/api/styles/reset", methods=["POST"])
     def reset_styles():
         """スタイルをデフォルトにリセット"""
         try:
             success = style_manager.reset_to_defaults()
             if success:
-                return jsonify({
-                    "success": True,
-                    "styles": style_manager.styles,
-                    "message": "デフォルトスタイルにリセットしました"
-                })
+                return jsonify(
+                    {
+                        "success": True,
+                        "styles": style_manager.styles,
+                        "message": "デフォルトスタイルにリセットしました",
+                    }
+                )
             else:
                 return jsonify({"error": "リセットに失敗しました"}), 500
         except Exception as e:
             return jsonify({"error": f"エラー: {str(e)}"}), 500
-    
-    @app.route('/api/styles/patch', methods=['POST'])
+
+    @app.route("/api/styles/patch", methods=["POST"])
     def create_style_patch():
         """スタイルパッチを作成"""
         try:
@@ -103,13 +114,13 @@ try:
             patch = {
                 "timestamp": datetime.now().isoformat(),
                 "changes": data,
-                "type": "style_update"
+                "type": "style_update",
             }
             return jsonify(patch)
         except Exception as e:
             return jsonify({"error": f"パッチ作成エラー: {str(e)}"}), 500
-    
-    @app.route('/style-manager')
+
+    @app.route("/style-manager")
     def style_manager_page():
         """スタイル管理画面 - 完全版を使用"""
         # 完全なスタイル管理テンプレート
@@ -607,11 +618,12 @@ try:
 </html>
 """
         return render_template_string(template)
-    
-    @app.route('/metrics')
+
+    @app.route("/metrics")
     def metrics_page():
         """メトリクス表示ページ"""
-        return render_template_string("""
+        return render_template_string(
+            """
         <!DOCTYPE html>
         <html>
         <head>
@@ -653,31 +665,37 @@ try:
             </div>
         </body>
         </html>
-        """)
-    
+        """
+        )
+
 except ImportError:
     print("[WARN] Style Manager統合に失敗しました。基本機能のみ利用可能です。")
-    
+
     # Style Manager統合に失敗した場合の基本ルート
-    @app.route('/api/pages', methods=['GET'])
+    @app.route("/api/pages", methods=["GET"])
     def get_available_pages_fallback():
         """利用可能なページ一覧を取得（フォールバック）"""
         pages = [
-            {"url": "/dashboard", "name": "ダッシュボード", "description": "メインダッシュボード画面"},
-            {"url": "/tasks", "name": "タスク管理", "description": "タスク一覧と管理画面"}
+            {
+                "url": "/dashboard",
+                "name": "ダッシュボード",
+                "description": "メインダッシュボード画面",
+            },
+            {"url": "/tasks", "name": "タスク管理", "description": "タスク一覧と管理画面"},
         ]
         return jsonify(pages)
-    
-    @app.route('/style-manager')
+
+    @app.route("/style-manager")
     def style_manager_page_fallback():
         """スタイル管理画面（フォールバック）"""
         return "<h1>Style Manager</h1><p>Style Manager機能は現在利用できません。</p>"
-    
-    @app.route('/metrics')
+
+    @app.route("/metrics")
     def metrics_page_fallback():
         """メトリクス表示ページ（フォールバック）"""
         return "<h1>Metrics</h1><p>メトリクス機能は現在利用できません。</p>"
 
+
 # 予測器のシングルトンを用意し、リクエスト毎の再初期化とDB初期化のオーバーヘッドを回避
 PREDICTOR_SINGLETON = None
 
@@ -811,6 +829,7 @@ def dashboard():
     """メインダッシュボード"""
     return dashboard_main()
 
+
 @app.route("/tasks")
 def tasks():
     """タスク管理ページ"""
@@ -896,6 +915,7 @@ def tasks():
     """
     return render_template_string(template)
 
+
 def dashboard_main():
     """メインダッシュボード"""
     dashboard_obj = QualityDashboard()
diff --git a/src/database_optimizer.py b/src/database_optimizer.py
index a7a4e47..176f664 100644
--- a/src/database_optimizer.py
+++ b/src/database_optimizer.py
@@ -6,40 +6,41 @@ SQLクエリのパフォーマンス分析と最適化提案を行います。
 """
 
 import json
+import logging
 import os
 import re
 import sqlite3
 import time
 from collections import defaultdict
 from datetime import datetime, timezone
-from typing import Dict, List, Any, Optional, Tuple
-import logging
+from typing import Any, Dict, List, Optional, Tuple
+
 
 class QueryAnalyzer:
     """SQLクエリ分析クラス"""
-    
+
     def __init__(self, db_path: Optional[str] = None):
         self.db_path = db_path or "C:/Users/User/Trae/ORCH-Next/data/app.db"
         self.query_log = []
         self.slow_query_threshold = 0.1  # 100ms
-        
+
         # ログ設定
         logging.basicConfig(level=logging.INFO)
         self.logger = logging.getLogger(__name__)
-        
+
         # クエリパターン
         self.query_patterns = {
-            'select': re.compile(r'SELECT\s+(.+?)\s+FROM\s+(\w+)', re.IGNORECASE),
-            'insert': re.compile(r'INSERT\s+INTO\s+(\w+)', re.IGNORECASE),
-            'update': re.compile(r'UPDATE\s+(\w+)', re.IGNORECASE),
-            'delete': re.compile(r'DELETE\s+FROM\s+(\w+)', re.IGNORECASE),
-            'join': re.compile(r'JOIN\s+(\w+)', re.IGNORECASE),
-            'where': re.compile(r'WHERE\s+(.+?)(?:\s+ORDER|\s+GROUP|\s+LIMIT|$)', re.IGNORECASE),
-            'order_by': re.compile(r'ORDER\s+BY\s+(.+?)(?:\s+LIMIT|$)', re.IGNORECASE),
-            'group_by': re.compile(r'GROUP\s+BY\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)', re.IGNORECASE),
-            'limit': re.compile(r'LIMIT\s+(\d+)', re.IGNORECASE)
+            "select": re.compile(r"SELECT\s+(.+?)\s+FROM\s+(\w+)", re.IGNORECASE),
+            "insert": re.compile(r"INSERT\s+INTO\s+(\w+)", re.IGNORECASE),
+            "update": re.compile(r"UPDATE\s+(\w+)", re.IGNORECASE),
+            "delete": re.compile(r"DELETE\s+FROM\s+(\w+)", re.IGNORECASE),
+            "join": re.compile(r"JOIN\s+(\w+)", re.IGNORECASE),
+            "where": re.compile(r"WHERE\s+(.+?)(?:\s+ORDER|\s+GROUP|\s+LIMIT|$)", re.IGNORECASE),
+            "order_by": re.compile(r"ORDER\s+BY\s+(.+?)(?:\s+LIMIT|$)", re.IGNORECASE),
+            "group_by": re.compile(r"GROUP\s+BY\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)", re.IGNORECASE),
+            "limit": re.compile(r"LIMIT\s+(\d+)", re.IGNORECASE),
         }
-        
+
     def analyze_query(self, query: str, execution_time: float = None) -> Dict[str, Any]:
         """クエリを分析"""
         analysis = {
@@ -52,9 +53,9 @@ class QueryAnalyzer:
             "conditions": self._extract_conditions(query),
             "joins": self._extract_joins(query),
             "complexity_score": self._calculate_complexity(query),
-            "optimization_suggestions": self._get_optimization_suggestions(query)
+            "optimization_suggestions": self._get_optimization_suggestions(query),
         }
-        
+
         # スロークエリの場合は警告
         if execution_time and execution_time > self.slow_query_threshold:
             analysis["is_slow"] = True
@@ -63,222 +64,222 @@ class QueryAnalyzer:
         else:
             analysis["is_slow"] = False
             analysis["performance_impact"] = "low"
-            
+
         self.query_log.append(analysis)
         return analysis
-        
+
     def _get_query_type(self, query: str) -> str:
         """クエリタイプを取得"""
         query_upper = query.upper().strip()
-        if query_upper.startswith('SELECT'):
-            return 'SELECT'
-        elif query_upper.startswith('INSERT'):
-            return 'INSERT'
-        elif query_upper.startswith('UPDATE'):
-            return 'UPDATE'
-        elif query_upper.startswith('DELETE'):
-            return 'DELETE'
-        elif query_upper.startswith('CREATE'):
-            return 'CREATE'
-        elif query_upper.startswith('DROP'):
-            return 'DROP'
+        if query_upper.startswith("SELECT"):
+            return "SELECT"
+        elif query_upper.startswith("INSERT"):
+            return "INSERT"
+        elif query_upper.startswith("UPDATE"):
+            return "UPDATE"
+        elif query_upper.startswith("DELETE"):
+            return "DELETE"
+        elif query_upper.startswith("CREATE"):
+            return "CREATE"
+        elif query_upper.startswith("DROP"):
+            return "DROP"
         else:
-            return 'OTHER'
-            
+            return "OTHER"
+
     def _extract_tables(self, query: str) -> List[str]:
         """テーブル名を抽出"""
         tables = set()
-        
+
         # FROM句のテーブル
-        from_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
+        from_match = re.search(r"FROM\s+(\w+)", query, re.IGNORECASE)
         if from_match:
             tables.add(from_match.group(1))
-            
+
         # JOIN句のテーブル
-        join_matches = self.query_patterns['join'].findall(query)
+        join_matches = self.query_patterns["join"].findall(query)
         tables.update(join_matches)
-        
+
         # INSERT/UPDATE/DELETE のテーブル
-        for pattern_name in ['insert', 'update', 'delete']:
+        for pattern_name in ["insert", "update", "delete"]:
             match = self.query_patterns[pattern_name].search(query)
             if match:
                 tables.add(match.group(1))
-                
+
         return list(tables)
-        
+
     def _extract_columns(self, query: str) -> List[str]:
         """カラム名を抽出"""
         columns = []
-        
+
         # SELECT句のカラム
-        select_match = self.query_patterns['select'].search(query)
+        select_match = self.query_patterns["select"].search(query)
         if select_match:
             select_part = select_match.group(1)
-            if select_part.strip() != '*':
+            if select_part.strip() != "*":
                 # カンマで分割してカラム名を抽出
-                cols = [col.strip() for col in select_part.split(',')]
+                cols = [col.strip() for col in select_part.split(",")]
                 columns.extend(cols)
-                
+
         return columns
-        
+
     def _extract_conditions(self, query: str) -> List[str]:
         """WHERE条件を抽出"""
         conditions = []
-        
-        where_match = self.query_patterns['where'].search(query)
+
+        where_match = self.query_patterns["where"].search(query)
         if where_match:
             where_clause = where_match.group(1)
             # AND/ORで分割
-            parts = re.split(r'\s+(?:AND|OR)\s+', where_clause, flags=re.IGNORECASE)
+            parts = re.split(r"\s+(?:AND|OR)\s+", where_clause, flags=re.IGNORECASE)
             conditions.extend([part.strip() for part in parts])
-            
+
         return conditions
-        
+
     def _extract_joins(self, query: str) -> List[str]:
         """JOIN情報を抽出"""
         joins = []
-        
+
         # JOIN句を検索
-        join_pattern = re.compile(r'((?:INNER|LEFT|RIGHT|FULL)?\s*JOIN\s+\w+\s+ON\s+[^)]+)', re.IGNORECASE)
+        join_pattern = re.compile(
+            r"((?:INNER|LEFT|RIGHT|FULL)?\s*JOIN\s+\w+\s+ON\s+[^)]+)", re.IGNORECASE
+        )
         join_matches = join_pattern.findall(query)
         joins.extend(join_matches)
-        
+
         return joins
-        
+
     def _calculate_complexity(self, query: str) -> int:
         """クエリの複雑度を計算"""
         score = 0
-        
+
         # 基本スコア
         score += 1
-        
+
         # テーブル数
         tables = self._extract_tables(query)
         score += len(tables) * 2
-        
+
         # JOIN数
         joins = self._extract_joins(query)
         score += len(joins) * 3
-        
+
         # サブクエリ
-        subquery_count = query.upper().count('SELECT') - 1
+        subquery_count = query.upper().count("SELECT") - 1
         score += subquery_count * 5
-        
+
         # 集約関数
-        aggregates = ['COUNT', 'SUM', 'AVG', 'MAX', 'MIN']
+        aggregates = ["COUNT", "SUM", "AVG", "MAX", "MIN"]
         for agg in aggregates:
             score += query.upper().count(agg) * 2
-            
+
         # GROUP BY
-        if 'GROUP BY' in query.upper():
+        if "GROUP BY" in query.upper():
             score += 3
-            
+
         # ORDER BY
-        if 'ORDER BY' in query.upper():
+        if "ORDER BY" in query.upper():
             score += 2
-            
+
         # HAVING
-        if 'HAVING' in query.upper():
+        if "HAVING" in query.upper():
             score += 4
-            
+
         return score
-        
+
     def _get_optimization_suggestions(self, query: str) -> List[str]:
         """最適化提案を生成"""
         suggestions = []
-        
+
         # SELECT * の使用チェック
-        if re.search(r'SELECT\s+\*', query, re.IGNORECASE):
+        if re.search(r"SELECT\s+\*", query, re.IGNORECASE):
             suggestions.append("SELECT * の代わりに必要なカラムのみを指定してください")
-            
+
         # インデックスが必要そうなWHERE条件
         conditions = self._extract_conditions(query)
         for condition in conditions:
-            if '=' in condition or 'LIKE' in condition.upper():
+            if "=" in condition or "LIKE" in condition.upper():
                 column = condition.split()[0]
                 suggestions.append(f"カラム '{column}' にインデックスを検討してください")
-                
+
         # LIMIT句がないSELECT
-        if query.upper().startswith('SELECT') and 'LIMIT' not in query.upper():
+        if query.upper().startswith("SELECT") and "LIMIT" not in query.upper():
             suggestions.append("大量データの場合はLIMIT句の使用を検討してください")
-            
+
         # ORDER BY without INDEX
-        order_match = self.query_patterns['order_by'].search(query)
+        order_match = self.query_patterns["order_by"].search(query)
         if order_match:
             order_columns = order_match.group(1)
-            suggestions.append(f"ORDER BY カラム '{order_columns}' にインデックスを検討してください")
-            
+            suggestions.append(
+                f"ORDER BY カラム '{order_columns}' にインデックスを検討してください"
+            )
+
         # 複数テーブルJOINでのWHERE条件
         tables = self._extract_tables(query)
         joins = self._extract_joins(query)
         if len(tables) > 1 and len(joins) > 0:
             suggestions.append("JOIN条件とWHERE条件の最適化を検討してください")
-            
+
         # サブクエリの最適化
-        if query.upper().count('SELECT') > 1:
+        if query.upper().count("SELECT") > 1:
             suggestions.append("サブクエリをJOINに書き換えることで性能向上の可能性があります")
-            
+
         return suggestions
 
+
 class DatabaseOptimizer:
     """データベース最適化クラス"""
-    
+
     def __init__(self, db_path: Optional[str] = None):
         self.db_path = db_path or "C:/Users/User/Trae/ORCH-Next/data/app.db"
         self.analyzer = QueryAnalyzer(db_path)
-        
+
         # ログ設定
         logging.basicConfig(level=logging.INFO)
         self.logger = logging.getLogger(__name__)
-        
+
     def execute_with_analysis(self, query: str, params: Tuple = ()) -> Tuple[Any, Dict[str, Any]]:
         """クエリを実行して分析"""
         start_time = time.time()
-        
+
         try:
             with sqlite3.connect(self.db_path) as conn:
                 cursor = conn.cursor()
                 result = cursor.execute(query, params).fetchall()
-                
+
             execution_time = time.time() - start_time
             analysis = self.analyzer.analyze_query(query, execution_time)
-            
+
             return result, analysis
-            
+
         except Exception as e:
             execution_time = time.time() - start_time
             analysis = self.analyzer.analyze_query(query, execution_time)
             analysis["error"] = str(e)
-            
+
             self.logger.error(f"クエリ実行エラー: {e}")
             raise
-            
+
     def analyze_database_schema(self) -> Dict[str, Any]:
         """データベーススキーマを分析"""
-        schema_info = {
-            "tables": {},
-            "indexes": {},
-            "statistics": {},
-            "recommendations": []
-        }
-        
+        schema_info = {"tables": {}, "indexes": {}, "statistics": {}, "recommendations": []}
+
         try:
             with sqlite3.connect(self.db_path) as conn:
                 cursor = conn.cursor()
-                
+
                 # テーブル一覧
                 cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                 tables = [row[0] for row in cursor.fetchall()]
-                
+
                 for table in tables:
                     # テーブル情報
                     cursor.execute(f"PRAGMA table_info({table})")
                     columns = cursor.fetchall()
-                    
+
                     # レコード数
                     cursor.execute(f"SELECT COUNT(*) FROM {table}")
                     row_count = cursor.fetchone()[0]
-                    
+
                     schema_info["tables"][table] = {
                         "columns": [
                             {
@@ -286,133 +287,136 @@ class DatabaseOptimizer:
                                 "type": col[2],
                                 "not_null": bool(col[3]),
                                 "default": col[4],
-                                "primary_key": bool(col[5])
+                                "primary_key": bool(col[5]),
                             }
                             for col in columns
                         ],
-                        "row_count": row_count
+                        "row_count": row_count,
                     }
-                    
+
                 # インデックス一覧
                 cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
                 indexes = cursor.fetchall()
-                
+
                 for index in indexes:
-                    if index[0] and not index[0].startswith('sqlite_'):
-                        schema_info["indexes"][index[0]] = {
-                            "table": index[1],
-                            "sql": index[2]
-                        }
-                        
+                    if index[0] and not index[0].startswith("sqlite_"):
+                        schema_info["indexes"][index[0]] = {"table": index[1], "sql": index[2]}
+
                 # 統計情報
                 schema_info["statistics"] = {
                     "total_tables": len(tables),
                     "total_indexes": len(schema_info["indexes"]),
-                    "total_rows": sum(info["row_count"] for info in schema_info["tables"].values())
+                    "total_rows": sum(info["row_count"] for info in schema_info["tables"].values()),
                 }
-                
+
                 # 推奨事項
                 schema_info["recommendations"] = self._generate_schema_recommendations(schema_info)
-                
+
         except Exception as e:
             self.logger.error(f"スキーマ分析エラー: {e}")
             schema_info["error"] = str(e)
-            
+
         return schema_info
-        
+
     def _generate_schema_recommendations(self, schema_info: Dict[str, Any]) -> List[str]:
         """スキーマ最適化推奨事項を生成"""
         recommendations = []
-        
+
         for table_name, table_info in schema_info["tables"].items():
             # 主キーがないテーブル
             has_primary_key = any(col["primary_key"] for col in table_info["columns"])
             if not has_primary_key:
                 recommendations.append(f"テーブル '{table_name}' に主キーの追加を検討してください")
-                
+
             # 大量データテーブルのインデックス
             if table_info["row_count"] > 10000:
-                recommendations.append(f"テーブル '{table_name}' ({table_info['row_count']} 行) のインデックス最適化を検討してください")
-                
+                recommendations.append(
+                    f"テーブル '{table_name}' ({table_info['row_count']} 行) のインデックス最適化を検討してください"
+                )
+
         # インデックスが少ない場合
         if schema_info["statistics"]["total_indexes"] < schema_info["statistics"]["total_tables"]:
-            recommendations.append("インデックス数が少ない可能性があります。クエリパフォーマンスを確認してください")
-            
+            recommendations.append(
+                "インデックス数が少ない可能性があります。クエリパフォーマンスを確認してください"
+            )
+
         return recommendations
-        
+
     def generate_performance_report(self) -> Dict[str, Any]:
         """パフォーマンスレポートを生成"""
         query_stats = defaultdict(list)
         slow_queries = []
-        
+
         # クエリログを分析
         for log_entry in self.analyzer.query_log:
             query_type = log_entry["type"]
             query_stats[query_type].append(log_entry)
-            
+
             if log_entry.get("is_slow", False):
                 slow_queries.append(log_entry)
-                
+
         # 統計計算
         report = {
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "summary": {
                 "total_queries": len(self.analyzer.query_log),
                 "slow_queries": len(slow_queries),
-                "query_types": dict(query_stats.keys())
+                "query_types": dict(query_stats.keys()),
             },
             "performance_metrics": {},
             "slow_queries": slow_queries[:10],  # 上位10件
             "optimization_opportunities": [],
-            "schema_analysis": self.analyze_database_schema()
+            "schema_analysis": self.analyze_database_schema(),
         }
-        
+
         # タイプ別統計
         for query_type, queries in query_stats.items():
             execution_times = [q["execution_time"] for q in queries if q["execution_time"]]
-            
+
             if execution_times:
                 report["performance_metrics"][query_type] = {
                     "count": len(queries),
                     "avg_time": sum(execution_times) / len(execution_times),
                     "max_time": max(execution_times),
-                    "min_time": min(execution_times)
+                    "min_time": min(execution_times),
                 }
-                
+
         # 最適化機会の特定
         all_suggestions = []
         for log_entry in self.analyzer.query_log:
             all_suggestions.extend(log_entry.get("optimization_suggestions", []))
-            
+
         # 重複を除去して頻度順にソート
         suggestion_counts = defaultdict(int)
         for suggestion in all_suggestions:
             suggestion_counts[suggestion] += 1
-            
+
         report["optimization_opportunities"] = [
             {"suggestion": suggestion, "frequency": count}
-            for suggestion, count in sorted(suggestion_counts.items(), key=lambda x: x[1], reverse=True)
+            for suggestion, count in sorted(
+                suggestion_counts.items(), key=lambda x: x[1], reverse=True
+            )
         ][:10]
-        
+
         return report
-        
+
     def export_report(self, filepath: str):
         """レポートをファイルにエクスポート"""
         report = self.generate_performance_report()
-        
+
         os.makedirs(os.path.dirname(filepath), exist_ok=True)
-        with open(filepath, 'w', encoding='utf-8') as f:
+        with open(filepath, "w", encoding="utf-8") as f:
             json.dump(report, f, indent=2, ensure_ascii=False)
-            
+
         self.logger.info(f"パフォーマンスレポートをエクスポート: {filepath}")
-        
+
     def suggest_indexes(self) -> List[Dict[str, Any]]:
         """インデックス提案を生成"""
         suggestions = []
-        
+
         # クエリログからWHERE条件を分析
         column_usage = defaultdict(int)
-        
+
         for log_entry in self.analyzer.query_log:
             conditions = log_entry.get("conditions", [])
             for condition in conditions:
@@ -421,40 +425,46 @@ class DatabaseOptimizer:
                 if len(parts) >= 3:
                     column = parts[0]
                     column_usage[column] += 1
-                    
+
         # 使用頻度の高いカラムにインデックスを提案
         for column, usage_count in sorted(column_usage.items(), key=lambda x: x[1], reverse=True):
             if usage_count >= 5:  # 5回以上使用されている
-                suggestions.append({
-                    "column": column,
-                    "usage_count": usage_count,
-                    "suggested_index": f"CREATE INDEX idx_{column} ON table_name ({column})",
-                    "reason": f"WHERE条件で {usage_count} 回使用されています"
-                })
-                
+                suggestions.append(
+                    {
+                        "column": column,
+                        "usage_count": usage_count,
+                        "suggested_index": f"CREATE INDEX idx_{column} ON table_name ({column})",
+                        "reason": f"WHERE条件で {usage_count} 回使用されています",
+                    }
+                )
+
         return suggestions[:10]  # 上位10件
 
+
 # 使用例とテスト
 if __name__ == "__main__":
     print("データベース最適化ツールテスト開始")
-    
+
     # テスト用データベース作成
     test_db = "C:/Users/User/Trae/ORCH-Next/data/test_optimization.db"
-    
+
     with sqlite3.connect(test_db) as conn:
         cursor = conn.cursor()
-        
+
         # テストテーブル作成
-        cursor.execute("""
+        cursor.execute(
+            """
             CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 email TEXT UNIQUE,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
             )
-        """)
-        
-        cursor.execute("""
+        """
+        )
+
+        cursor.execute(
+            """
             CREATE TABLE IF NOT EXISTS orders (
                 id INTEGER PRIMARY KEY,
                 user_id INTEGER,
@@ -463,28 +473,33 @@ if __name__ == "__main__":
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users (id)
             )
-        """)
-        
+        """
+        )
+
         # テストデータ挿入
         for i in range(100):
-            cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", 
-                         (f"User{i}", f"user{i}@example.com"))
-            cursor.execute("INSERT INTO orders (user_id, amount, status) VALUES (?, ?, ?)",
-                         (i % 50 + 1, 100.0 + i, "completed" if i % 2 == 0 else "pending"))
-        
+            cursor.execute(
+                "INSERT INTO users (name, email) VALUES (?, ?)",
+                (f"User{i}", f"user{i}@example.com"),
+            )
+            cursor.execute(
+                "INSERT INTO orders (user_id, amount, status) VALUES (?, ?, ?)",
+                (i % 50 + 1, 100.0 + i, "completed" if i % 2 == 0 else "pending"),
+            )
+
         conn.commit()
-    
+
     # 最適化ツールテスト
     optimizer = DatabaseOptimizer(test_db)
-    
+
     # テストクエリ実行
     test_queries = [
         "SELECT * FROM users WHERE email = 'user1@example.com'",
         "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id",
         "SELECT * FROM orders WHERE status = 'completed' ORDER BY created_at DESC",
-        "SELECT AVG(amount) FROM orders WHERE user_id IN (SELECT id FROM users WHERE name LIKE 'User1%')"
+        "SELECT AVG(amount) FROM orders WHERE user_id IN (SELECT id FROM users WHERE name LIKE 'User1%')",
     ]
-    
+
     print("\nテストクエリ実行と分析:")
     for query in test_queries:
         try:
@@ -495,23 +510,23 @@ if __name__ == "__main__":
             print(f"最適化提案数: {len(analysis['optimization_suggestions'])}")
         except Exception as e:
             print(f"エラー: {e}")
-    
+
     # スキーマ分析
     print("\nスキーマ分析:")
     schema_analysis = optimizer.analyze_database_schema()
     print(f"テーブル数: {schema_analysis['statistics']['total_tables']}")
     print(f"インデックス数: {schema_analysis['statistics']['total_indexes']}")
     print(f"総レコード数: {schema_analysis['statistics']['total_rows']}")
-    
+
     # パフォーマンスレポート生成
     print("\nパフォーマンスレポート生成:")
     report_path = "C:/Users/User/Trae/ORCH-Next/data/test_results/db_performance_report.json"
     optimizer.export_report(report_path)
-    
+
     # インデックス提案
     print("\nインデックス提案:")
     index_suggestions = optimizer.suggest_indexes()
     for suggestion in index_suggestions[:3]:
         print(f"- {suggestion['column']}: {suggestion['reason']}")
-    
-    print("\n✓ データベース最適化ツールテスト完了")
\ No newline at end of file
+
+    print("\n✓ データベース最適化ツールテスト完了")
diff --git a/src/load_tester.py b/src/load_tester.py
index 99e3a8d..c73f509 100644
--- a/src/load_tester.py
+++ b/src/load_tester.py
@@ -6,23 +6,25 @@ Webアプリケーションの負荷テストとストレステストを実行
 """
 
 import asyncio
-import aiohttp
 import json
+import logging
 import os
-import time
+import statistics
 import threading
+import time
 from concurrent.futures import ThreadPoolExecutor, as_completed
 from datetime import datetime, timezone
-from typing import Dict, List, Any, Optional, Callable
-import statistics
-import logging
-import psutil
+from typing import Any, Callable, Dict, List, Optional
+
+import aiohttp
 import matplotlib.pyplot as plt
 import numpy as np
+import psutil
+
 
 class LoadTestResult:
     """負荷テスト結果クラス"""
-    
+
     def __init__(self):
         self.start_time = None
         self.end_time = None
@@ -33,35 +35,42 @@ class LoadTestResult:
         self.error_details = []
         self.throughput_history = []
         self.resource_usage = []
-        
+
     def add_response(self, response_time: float, success: bool, error: str = None):
         """レスポンス結果を追加"""
         self.total_requests += 1
         self.response_times.append(response_time)
-        
+
         if success:
             self.successful_requests += 1
         else:
             self.failed_requests += 1
             if error:
-                self.error_details.append({
-                    "timestamp": datetime.now(timezone.utc).isoformat(),
-                    "error": error
-                })
-                
+                self.error_details.append(
+                    {"timestamp": datetime.now(timezone.utc).isoformat(), "error": error}
+                )
+
     def calculate_statistics(self) -> Dict[str, Any]:
         """統計情報を計算"""
         if not self.response_times:
             return {"error": "レスポンスデータがありません"}
-            
-        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
-        
+
+        duration = (
+            (self.end_time - self.start_time).total_seconds()
+            if self.end_time and self.start_time
+            else 0
+        )
+
         return {
             "duration_seconds": duration,
             "total_requests": self.total_requests,
             "successful_requests": self.successful_requests,
             "failed_requests": self.failed_requests,
-            "success_rate": (self.successful_requests / self.total_requests) * 100 if self.total_requests > 0 else 0,
+            "success_rate": (
+                (self.successful_requests / self.total_requests) * 100
+                if self.total_requests > 0
+                else 0
+            ),
             "requests_per_second": self.total_requests / duration if duration > 0 else 0,
             "response_time_stats": {
                 "min": min(self.response_times),
@@ -69,276 +78,291 @@ class LoadTestResult:
                 "mean": statistics.mean(self.response_times),
                 "median": statistics.median(self.response_times),
                 "p95": np.percentile(self.response_times, 95),
-                "p99": np.percentile(self.response_times, 99)
+                "p99": np.percentile(self.response_times, 99),
             },
-            "error_rate": (self.failed_requests / self.total_requests) * 100 if self.total_requests > 0 else 0,
-            "unique_errors": len(set(error["error"] for error in self.error_details))
+            "error_rate": (
+                (self.failed_requests / self.total_requests) * 100 if self.total_requests > 0 else 0
+            ),
+            "unique_errors": len(set(error["error"] for error in self.error_details)),
         }
 
+
 class LoadTester:
     """負荷テスタークラス"""
-    
+
     def __init__(self, base_url: str = "http://localhost:5000"):
         self.base_url = base_url
         self.session = None
         self.monitoring = False
         self.monitor_thread = None
-        
+
         # ログ設定
         logging.basicConfig(level=logging.INFO)
         self.logger = logging.getLogger(__name__)
-        
+
         # デフォルトエンドポイント
         self.default_endpoints = [
             {"path": "/", "method": "GET", "weight": 40},
             {"path": "/api/status", "method": "GET", "weight": 30},
             {"path": "/security", "method": "GET", "weight": 20},
-            {"path": "/api/health", "method": "GET", "weight": 10}
+            {"path": "/api/health", "method": "GET", "weight": 10},
         ]
-        
-    async def _make_request(self, endpoint: Dict[str, Any], session: aiohttp.ClientSession) -> Dict[str, Any]:
+
+    async def _make_request(
+        self, endpoint: Dict[str, Any], session: aiohttp.ClientSession
+    ) -> Dict[str, Any]:
         """単一リクエストを実行"""
         start_time = time.time()
-        
+
         try:
             url = f"{self.base_url}{endpoint['path']}"
-            method = endpoint.get('method', 'GET')
-            headers = endpoint.get('headers', {})
-            data = endpoint.get('data')
-            
+            method = endpoint.get("method", "GET")
+            headers = endpoint.get("headers", {})
+            data = endpoint.get("data")
+
             async with session.request(method, url, headers=headers, json=data) as response:
                 await response.text()  # レスポンスボディを読み込み
-                
+
                 response_time = time.time() - start_time
-                
+
                 return {
                     "success": response.status < 400,
                     "response_time": response_time,
                     "status_code": response.status,
-                    "error": None if response.status < 400 else f"HTTP {response.status}"
+                    "error": None if response.status < 400 else f"HTTP {response.status}",
                 }
-                
+
         except Exception as e:
             response_time = time.time() - start_time
             return {
                 "success": False,
                 "response_time": response_time,
                 "status_code": 0,
-                "error": str(e)
+                "error": str(e),
             }
-            
-    async def run_load_test(self, 
-                           concurrent_users: int = 10,
-                           duration_seconds: int = 60,
-                           endpoints: Optional[List[Dict[str, Any]]] = None,
-                           ramp_up_seconds: int = 0) -> LoadTestResult:
+
+    async def run_load_test(
+        self,
+        concurrent_users: int = 10,
+        duration_seconds: int = 60,
+        endpoints: Optional[List[Dict[str, Any]]] = None,
+        ramp_up_seconds: int = 0,
+    ) -> LoadTestResult:
         """負荷テストを実行"""
-        
+
         endpoints = endpoints or self.default_endpoints
         result = LoadTestResult()
         result.start_time = datetime.now(timezone.utc)
-        
+
         # リソース監視開始
         self._start_resource_monitoring(result)
-        
-        self.logger.info(f"負荷テスト開始: {concurrent_users} 同時ユーザー, {duration_seconds} 秒間")
-        
+
+        self.logger.info(
+            f"負荷テスト開始: {concurrent_users} 同時ユーザー, {duration_seconds} 秒間"
+        )
+
         # セマフォで同時接続数を制御
         semaphore = asyncio.Semaphore(concurrent_users)
-        
+
         async with aiohttp.ClientSession(
             timeout=aiohttp.ClientTimeout(total=30),
-            connector=aiohttp.TCPConnector(limit=concurrent_users * 2)
+            connector=aiohttp.TCPConnector(limit=concurrent_users * 2),
         ) as session:
-            
+
             tasks = []
             end_time = time.time() + duration_seconds
-            
+
             # ランプアップ処理
             if ramp_up_seconds > 0:
                 ramp_up_interval = ramp_up_seconds / concurrent_users
                 current_users = 0
             else:
                 current_users = concurrent_users
-                
+
             while time.time() < end_time:
                 # ランプアップ中の場合、徐々にユーザー数を増加
                 if ramp_up_seconds > 0 and current_users < concurrent_users:
-                    if time.time() - result.start_time.timestamp() >= current_users * ramp_up_interval:
+                    if (
+                        time.time() - result.start_time.timestamp()
+                        >= current_users * ramp_up_interval
+                    ):
                         current_users += 1
-                        
+
                 # エンドポイントを重みに基づいて選択
                 endpoint = self._select_weighted_endpoint(endpoints)
-                
+
                 # タスク作成
-                task = asyncio.create_task(self._execute_request_with_semaphore(
-                    semaphore, endpoint, session, result
-                ))
+                task = asyncio.create_task(
+                    self._execute_request_with_semaphore(semaphore, endpoint, session, result)
+                )
                 tasks.append(task)
-                
+
                 # 適度な間隔を空ける
                 await asyncio.sleep(0.1)
-                
+
                 # 完了したタスクをクリーンアップ
                 tasks = [task for task in tasks if not task.done()]
-                
+
             # 残りのタスクを待機
             if tasks:
                 await asyncio.gather(*tasks, return_exceptions=True)
-                
+
         result.end_time = datetime.now(timezone.utc)
         self._stop_resource_monitoring()
-        
+
         self.logger.info("負荷テスト完了")
         return result
-        
-    async def _execute_request_with_semaphore(self, 
-                                            semaphore: asyncio.Semaphore,
-                                            endpoint: Dict[str, Any],
-                                            session: aiohttp.ClientSession,
-                                            result: LoadTestResult):
+
+    async def _execute_request_with_semaphore(
+        self,
+        semaphore: asyncio.Semaphore,
+        endpoint: Dict[str, Any],
+        session: aiohttp.ClientSession,
+        result: LoadTestResult,
+    ):
         """セマフォ制御付きリクエスト実行"""
         async with semaphore:
             response_data = await self._make_request(endpoint, session)
             result.add_response(
-                response_data["response_time"],
-                response_data["success"],
-                response_data["error"]
+                response_data["response_time"], response_data["success"], response_data["error"]
             )
-            
+
     def _select_weighted_endpoint(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
         """重みに基づいてエンドポイントを選択"""
-        total_weight = sum(ep.get('weight', 1) for ep in endpoints)
+        total_weight = sum(ep.get("weight", 1) for ep in endpoints)
         random_value = np.random.randint(0, total_weight)
-        
+
         current_weight = 0
         for endpoint in endpoints:
-            current_weight += endpoint.get('weight', 1)
+            current_weight += endpoint.get("weight", 1)
             if random_value < current_weight:
                 return endpoint
-                
+
         return endpoints[0]  # フォールバック
-        
+
     def _start_resource_monitoring(self, result: LoadTestResult):
         """リソース監視開始"""
         self.monitoring = True
         self.monitor_thread = threading.Thread(target=self._monitor_resources, args=(result,))
         self.monitor_thread.daemon = True
         self.monitor_thread.start()
-        
+
     def _stop_resource_monitoring(self):
         """リソース監視停止"""
         self.monitoring = False
         if self.monitor_thread:
             self.monitor_thread.join()
-            
+
     def _monitor_resources(self, result: LoadTestResult):
         """リソース監視ループ"""
         while self.monitoring:
             try:
                 cpu_percent = psutil.cpu_percent()
                 memory = psutil.virtual_memory()
-                
-                result.resource_usage.append({
-                    "timestamp": datetime.now(timezone.utc).isoformat(),
-                    "cpu_percent": cpu_percent,
-                    "memory_percent": memory.percent,
-                    "memory_used_mb": memory.used / 1024 / 1024
-                })
-                
+
+                result.resource_usage.append(
+                    {
+                        "timestamp": datetime.now(timezone.utc).isoformat(),
+                        "cpu_percent": cpu_percent,
+                        "memory_percent": memory.percent,
+                        "memory_used_mb": memory.used / 1024 / 1024,
+                    }
+                )
+
                 time.sleep(1)
-                
+
             except Exception as e:
                 self.logger.error(f"リソース監視エラー: {e}")
-                
-    async def run_stress_test(self, 
-                             max_users: int = 100,
-                             step_size: int = 10,
-                             step_duration: int = 30,
-                             endpoints: Optional[List[Dict[str, Any]]] = None) -> List[LoadTestResult]:
+
+    async def run_stress_test(
+        self,
+        max_users: int = 100,
+        step_size: int = 10,
+        step_duration: int = 30,
+        endpoints: Optional[List[Dict[str, Any]]] = None,
+    ) -> List[LoadTestResult]:
         """ストレステストを実行"""
-        
+
         endpoints = endpoints or self.default_endpoints
         results = []
-        
+
         self.logger.info(f"ストレステスト開始: 最大 {max_users} ユーザー, {step_size} ずつ増加")
-        
+
         for users in range(step_size, max_users + 1, step_size):
             self.logger.info(f"ステップ {users}/{max_users} ユーザーでテスト実行")
-            
+
             result = await self.run_load_test(
-                concurrent_users=users,
-                duration_seconds=step_duration,
-                endpoints=endpoints
+                concurrent_users=users, duration_seconds=step_duration, endpoints=endpoints
             )
-            
+
             results.append(result)
-            
+
             # 統計情報をログ出力
             stats = result.calculate_statistics()
-            self.logger.info(f"ユーザー数 {users}: RPS={stats['requests_per_second']:.1f}, "
-                           f"平均応答時間={stats['response_time_stats']['mean']:.3f}s, "
-                           f"成功率={stats['success_rate']:.1f}%")
-            
+            self.logger.info(
+                f"ユーザー数 {users}: RPS={stats['requests_per_second']:.1f}, "
+                f"平均応答時間={stats['response_time_stats']['mean']:.3f}s, "
+                f"成功率={stats['success_rate']:.1f}%"
+            )
+
             # 失敗率が高い場合は停止
-            if stats['success_rate'] < 50:
+            if stats["success_rate"] < 50:
                 self.logger.warning(f"成功率が50%を下回ったため、ストレステストを停止します")
                 break
-                
+
             # 次のステップまで少し待機
             await asyncio.sleep(5)
-            
+
         self.logger.info("ストレステスト完了")
         return results
-        
+
     def generate_report(self, results: List[LoadTestResult], output_dir: str):
         """テスト結果レポートを生成"""
         os.makedirs(output_dir, exist_ok=True)
-        
+
         # JSON レポート
-        json_report = {
-            "timestamp": datetime.now(timezone.utc).isoformat(),
-            "test_results": []
-        }
-        
+        json_report = {"timestamp": datetime.now(timezone.utc).isoformat(), "test_results": []}
+
         for i, result in enumerate(results):
             stats = result.calculate_statistics()
-            json_report["test_results"].append({
-                "test_index": i,
-                "statistics": stats,
-                "resource_usage_summary": self._summarize_resource_usage(result.resource_usage)
-            })
-            
+            json_report["test_results"].append(
+                {
+                    "test_index": i,
+                    "statistics": stats,
+                    "resource_usage_summary": self._summarize_resource_usage(result.resource_usage),
+                }
+            )
+
         json_path = os.path.join(output_dir, "load_test_report.json")
-        with open(json_path, 'w', encoding='utf-8') as f:
+        with open(json_path, "w", encoding="utf-8") as f:
             json.dump(json_report, f, indent=2, ensure_ascii=False)
-            
+
         # グラフ生成
         self._generate_charts(results, output_dir)
-        
+
         self.logger.info(f"レポートを生成: {output_dir}")
-        
+
     def _summarize_resource_usage(self, resource_usage: List[Dict[str, Any]]) -> Dict[str, Any]:
         """リソース使用量を要約"""
         if not resource_usage:
             return {}
-            
+
         cpu_values = [r["cpu_percent"] for r in resource_usage]
         memory_values = [r["memory_percent"] for r in resource_usage]
-        
+
         return {
             "cpu": {
                 "min": min(cpu_values),
                 "max": max(cpu_values),
-                "mean": statistics.mean(cpu_values)
+                "mean": statistics.mean(cpu_values),
             },
             "memory": {
                 "min": min(memory_values),
                 "max": max(memory_values),
-                "mean": statistics.mean(memory_values)
-            }
+                "mean": statistics.mean(memory_values),
+            },
         }
-        
+
     def _generate_charts(self, results: List[LoadTestResult], output_dir: str):
         """パフォーマンスチャートを生成"""
         try:
@@ -347,147 +371,143 @@ class LoadTester:
             rps_values = []
             avg_response_times = []
             success_rates = []
-            
+
             for result in results:
                 stats = result.calculate_statistics()
-                rps_values.append(stats['requests_per_second'])
-                avg_response_times.append(stats['response_time_stats']['mean'])
-                success_rates.append(stats['success_rate'])
-                
+                rps_values.append(stats["requests_per_second"])
+                avg_response_times.append(stats["response_time_stats"]["mean"])
+                success_rates.append(stats["success_rate"])
+
             # チャート作成
             fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
-            
+
             # RPS チャート
-            ax1.plot(user_counts, rps_values, 'b-o')
-            ax1.set_title('Requests per Second')
-            ax1.set_xlabel('Test Step')
-            ax1.set_ylabel('RPS')
+            ax1.plot(user_counts, rps_values, "b-o")
+            ax1.set_title("Requests per Second")
+            ax1.set_xlabel("Test Step")
+            ax1.set_ylabel("RPS")
             ax1.grid(True)
-            
+
             # 応答時間チャート
-            ax2.plot(user_counts, avg_response_times, 'r-o')
-            ax2.set_title('Average Response Time')
-            ax2.set_xlabel('Test Step')
-            ax2.set_ylabel('Response Time (s)')
+            ax2.plot(user_counts, avg_response_times, "r-o")
+            ax2.set_title("Average Response Time")
+            ax2.set_xlabel("Test Step")
+            ax2.set_ylabel("Response Time (s)")
             ax2.grid(True)
-            
+
             # 成功率チャート
-            ax3.plot(user_counts, success_rates, 'g-o')
-            ax3.set_title('Success Rate')
-            ax3.set_xlabel('Test Step')
-            ax3.set_ylabel('Success Rate (%)')
+            ax3.plot(user_counts, success_rates, "g-o")
+            ax3.set_title("Success Rate")
+            ax3.set_xlabel("Test Step")
+            ax3.set_ylabel("Success Rate (%)")
             ax3.grid(True)
-            
+
             # 応答時間分布（最後のテスト結果）
             if results:
                 last_result = results[-1]
                 ax4.hist(last_result.response_times, bins=50, alpha=0.7)
-                ax4.set_title('Response Time Distribution (Last Test)')
-                ax4.set_xlabel('Response Time (s)')
-                ax4.set_ylabel('Frequency')
+                ax4.set_title("Response Time Distribution (Last Test)")
+                ax4.set_xlabel("Response Time (s)")
+                ax4.set_ylabel("Frequency")
                 ax4.grid(True)
-                
+
             plt.tight_layout()
             chart_path = os.path.join(output_dir, "performance_charts.png")
-            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
+            plt.savefig(chart_path, dpi=300, bbox_inches="tight")
             plt.close()
-            
+
             self.logger.info(f"チャートを生成: {chart_path}")
-            
+
         except Exception as e:
             self.logger.error(f"チャート生成エラー: {e}")
 
+
 class PerformanceBenchmark:
     """パフォーマンスベンチマーククラス"""
-    
+
     def __init__(self, base_url: str = "http://localhost:5000"):
         self.load_tester = LoadTester(base_url)
-        
+
     async def run_comprehensive_test(self, output_dir: str = None) -> Dict[str, Any]:
         """包括的なパフォーマンステストを実行"""
-        output_dir = output_dir or f"C:/Users/User/Trae/ORCH-Next/data/test_results/perf_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
-        
+        output_dir = (
+            output_dir
+            or f"C:/Users/User/Trae/ORCH-Next/data/test_results/perf_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
+        )
+
         test_results = {
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "baseline_test": None,
             "load_test": None,
             "stress_test": None,
-            "spike_test": None
+            "spike_test": None,
         }
-        
+
         # 1. ベースラインテスト（軽負荷）
         print("1. ベースラインテスト実行中...")
         baseline_result = await self.load_tester.run_load_test(
-            concurrent_users=1,
-            duration_seconds=30
+            concurrent_users=1, duration_seconds=30
         )
         test_results["baseline_test"] = baseline_result.calculate_statistics()
-        
+
         # 2. 負荷テスト（通常負荷）
         print("2. 負荷テスト実行中...")
         load_result = await self.load_tester.run_load_test(
-            concurrent_users=20,
-            duration_seconds=120,
-            ramp_up_seconds=30
+            concurrent_users=20, duration_seconds=120, ramp_up_seconds=30
         )
         test_results["load_test"] = load_result.calculate_statistics()
-        
+
         # 3. ストレステスト（段階的負荷増加）
         print("3. ストレステスト実行中...")
         stress_results = await self.load_tester.run_stress_test(
-            max_users=50,
-            step_size=10,
-            step_duration=30
+            max_users=50, step_size=10, step_duration=30
         )
         test_results["stress_test"] = [r.calculate_statistics() for r in stress_results]
-        
+
         # 4. スパイクテスト（急激な負荷増加）
         print("4. スパイクテスト実行中...")
         spike_result = await self.load_tester.run_load_test(
-            concurrent_users=50,
-            duration_seconds=60,
-            ramp_up_seconds=5  # 急激な増加
+            concurrent_users=50, duration_seconds=60, ramp_up_seconds=5  # 急激な増加
         )
         test_results["spike_test"] = spike_result.calculate_statistics()
-        
+
         # レポート生成
         all_results = [baseline_result, load_result] + stress_results + [spike_result]
         self.load_tester.generate_report(all_results, output_dir)
-        
+
         # 総合結果をJSONで保存
         summary_path = os.path.join(output_dir, "comprehensive_test_summary.json")
-        with open(summary_path, 'w', encoding='utf-8') as f:
+        with open(summary_path, "w", encoding="utf-8") as f:
             json.dump(test_results, f, indent=2, ensure_ascii=False)
-            
+
         return test_results
 
+
 # 使用例とテスト
 if __name__ == "__main__":
+
     async def main():
         print("負荷テストツールテスト開始")
-        
+
         # 基本的な負荷テスト
         tester = LoadTester("http://localhost:5000")
-        
+
         print("\n基本負荷テスト実行...")
-        result = await tester.run_load_test(
-            concurrent_users=5,
-            duration_seconds=30
-        )
-        
+        result = await tester.run_load_test(concurrent_users=5, duration_seconds=30)
+
         stats = result.calculate_statistics()
         print(f"総リクエスト数: {stats['total_requests']}")
         print(f"成功率: {stats['success_rate']:.1f}%")
         print(f"RPS: {stats['requests_per_second']:.1f}")
         print(f"平均応答時間: {stats['response_time_stats']['mean']:.3f}秒")
         print(f"P95応答時間: {stats['response_time_stats']['p95']:.3f}秒")
-        
+
         # 包括的テスト
         print("\n包括的パフォーマンステスト実行...")
         benchmark = PerformanceBenchmark("http://localhost:5000")
         comprehensive_results = await benchmark.run_comprehensive_test()
-        
+
         print("✓ 負荷テストツールテスト完了")
-        
+
     # イベントループ実行
-    asyncio.run(main())
\ No newline at end of file
+    asyncio.run(main())
diff --git a/src/performance_monitor.py b/src/performance_monitor.py
index b0d1c1c..cba0524 100644
--- a/src/performance_monitor.py
+++ b/src/performance_monitor.py
@@ -7,14 +7,15 @@ import json
 import logging
 import os
 import platform
-import psutil
+import threading
 import time
+from collections import deque
 from datetime import datetime, timedelta
 from pathlib import Path
 from typing import Dict, List, Optional
-import threading
+
+import psutil
 import requests
-from collections import deque
 
 
 class SystemPerformanceMonitor:
@@ -27,7 +28,7 @@ class SystemPerformanceMonitor:
         self.is_monitoring = False
         self.monitor_thread = None
         self._thread_lock = threading.Lock()
-        
+
         # ログ設定
         self.logger = logging.getLogger(__name__)
 
@@ -40,14 +41,14 @@ class SystemPerformanceMonitor:
                 "memory_usage_max": 85.0,
                 "disk_usage_max": 90.0,
                 "response_time_max": 2.0,
-                "network_latency_max": 100.0
+                "network_latency_max": 100.0,
             },
             "endpoints_to_monitor": [
                 "http://127.0.0.1:5000/health",
-                "http://127.0.0.1:5000/api/status"
+                "http://127.0.0.1:5000/api/status",
             ],
             "alert_cooldown": 300,  # 5分間のクールダウン
-            "data_retention_hours": 24
+            "data_retention_hours": 24,
         }
 
         if self.config_path.exists():
@@ -90,7 +91,7 @@ class SystemPerformanceMonitor:
                         "total": usage.total,
                         "used": usage.used,
                         "free": usage.free,
-                        "percent": (usage.used / usage.total) * 100
+                        "percent": (usage.used / usage.total) * 100,
                     }
                 except PermissionError:
                     continue
@@ -101,14 +102,14 @@ class SystemPerformanceMonitor:
 
             # プロセス情報
             process_count = len(psutil.pids())
-            
+
             # 現在のプロセス情報
             current_process = psutil.Process()
             process_info = {
                 "cpu_percent": current_process.cpu_percent(),
                 "memory_percent": current_process.memory_percent(),
                 "memory_info": current_process.memory_info()._asdict(),
-                "num_threads": current_process.num_threads()
+                "num_threads": current_process.num_threads(),
             }
 
             metrics = {
@@ -116,12 +117,12 @@ class SystemPerformanceMonitor:
                 "system_info": {
                     "platform": platform.platform(),
                     "python_version": platform.python_version(),
-                    "cpu_count": cpu_count
+                    "cpu_count": cpu_count,
                 },
                 "cpu": {
                     "usage_percent": cpu_percent,
                     "frequency": cpu_freq._asdict() if cpu_freq else None,
-                    "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
+                    "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
                 },
                 "memory": {
                     "total": memory.total,
@@ -130,7 +131,7 @@ class SystemPerformanceMonitor:
                     "percent": memory.percent,
                     "swap_total": swap.total,
                     "swap_used": swap.used,
-                    "swap_percent": swap.percent
+                    "swap_percent": swap.percent,
                 },
                 "disk": disk_usage,
                 "network": {
@@ -138,12 +139,9 @@ class SystemPerformanceMonitor:
                     "bytes_recv": network.bytes_recv,
                     "packets_sent": network.packets_sent,
                     "packets_recv": network.packets_recv,
-                    "connections": network_connections
+                    "connections": network_connections,
                 },
-                "process": {
-                    "count": process_count,
-                    "current": process_info
-                }
+                "process": {"count": process_count, "current": process_info},
             }
 
             return metrics
@@ -155,29 +153,29 @@ class SystemPerformanceMonitor:
     def collect_response_time_metrics(self) -> Dict:
         """レスポンス時間メトリクス収集"""
         response_times = {}
-        
+
         for endpoint in self.config["endpoints_to_monitor"]:
             try:
                 start_time = time.time()
                 response = requests.get(endpoint, timeout=10)
                 end_time = time.time()
-                
+
                 response_time = (end_time - start_time) * 1000  # ミリ秒
-                
+
                 response_times[endpoint] = {
                     "response_time_ms": response_time,
                     "status_code": response.status_code,
                     "success": response.status_code == 200,
-                    "timestamp": datetime.now().isoformat()
+                    "timestamp": datetime.now().isoformat(),
                 }
-                
+
             except Exception as e:
                 response_times[endpoint] = {
                     "response_time_ms": None,
                     "status_code": None,
                     "success": False,
                     "error": str(e),
-                    "timestamp": datetime.now().isoformat()
+                    "timestamp": datetime.now().isoformat(),
                 }
 
         return response_times
@@ -189,35 +187,41 @@ class SystemPerformanceMonitor:
 
         # CPU使用率チェック
         if metrics.get("cpu", {}).get("usage_percent", 0) > thresholds["cpu_usage_max"]:
-            alerts.append({
-                "type": "high_cpu_usage",
-                "severity": "warning",
-                "message": f"CPU使用率が高い: {metrics['cpu']['usage_percent']:.1f}%",
-                "value": metrics["cpu"]["usage_percent"],
-                "threshold": thresholds["cpu_usage_max"]
-            })
+            alerts.append(
+                {
+                    "type": "high_cpu_usage",
+                    "severity": "warning",
+                    "message": f"CPU使用率が高い: {metrics['cpu']['usage_percent']:.1f}%",
+                    "value": metrics["cpu"]["usage_percent"],
+                    "threshold": thresholds["cpu_usage_max"],
+                }
+            )
 
         # メモリ使用率チェック
         if metrics.get("memory", {}).get("percent", 0) > thresholds["memory_usage_max"]:
-            alerts.append({
-                "type": "high_memory_usage",
-                "severity": "warning",
-                "message": f"メモリ使用率が高い: {metrics['memory']['percent']:.1f}%",
-                "value": metrics["memory"]["percent"],
-                "threshold": thresholds["memory_usage_max"]
-            })
+            alerts.append(
+                {
+                    "type": "high_memory_usage",
+                    "severity": "warning",
+                    "message": f"メモリ使用率が高い: {metrics['memory']['percent']:.1f}%",
+                    "value": metrics["memory"]["percent"],
+                    "threshold": thresholds["memory_usage_max"],
+                }
+            )
 
         # ディスク使用率チェック
         for device, usage in metrics.get("disk", {}).items():
             if usage["percent"] > thresholds["disk_usage_max"]:
-                alerts.append({
-                    "type": "high_disk_usage",
-                    "severity": "critical" if usage["percent"] > 95 else "warning",
-                    "message": f"ディスク使用率が高い ({device}): {usage['percent']:.1f}%",
-                    "value": usage["percent"],
-                    "threshold": thresholds["disk_usage_max"],
-                    "device": device
-                })
+                alerts.append(
+                    {
+                        "type": "high_disk_usage",
+                        "severity": "critical" if usage["percent"] > 95 else "warning",
+                        "message": f"ディスク使用率が高い ({device}): {usage['percent']:.1f}%",
+                        "value": usage["percent"],
+                        "threshold": thresholds["disk_usage_max"],
+                        "device": device,
+                    }
+                )
 
         return alerts
 
@@ -228,22 +232,26 @@ class SystemPerformanceMonitor:
 
         for endpoint, data in response_times.items():
             if not data["success"]:
-                alerts.append({
-                    "type": "endpoint_failure",
-                    "severity": "critical",
-                    "message": f"エンドポイントアクセス失敗: {endpoint}",
-                    "endpoint": endpoint,
-                    "error": data.get("error", "Unknown error")
-                })
+                alerts.append(
+                    {
+                        "type": "endpoint_failure",
+                        "severity": "critical",
+                        "message": f"エンドポイントアクセス失敗: {endpoint}",
+                        "endpoint": endpoint,
+                        "error": data.get("error", "Unknown error"),
+                    }
+                )
             elif data["response_time_ms"] and data["response_time_ms"] > threshold:
-                alerts.append({
-                    "type": "slow_response",
-                    "severity": "warning",
-                    "message": f"レスポンス時間が遅い: {endpoint} ({data['response_time_ms']:.1f}ms)",
-                    "endpoint": endpoint,
-                    "value": data["response_time_ms"],
-                    "threshold": threshold
-                })
+                alerts.append(
+                    {
+                        "type": "slow_response",
+                        "severity": "warning",
+                        "message": f"レスポンス時間が遅い: {endpoint} ({data['response_time_ms']:.1f}ms)",
+                        "endpoint": endpoint,
+                        "value": data["response_time_ms"],
+                        "threshold": threshold,
+                    }
+                )
 
         return alerts
 
@@ -258,21 +266,24 @@ class SystemPerformanceMonitor:
                 "response_time": 125.5,
                 "throughput": 1250,
                 "error_rate": 0.02,
-                "timestamp": datetime.now().isoformat()
+                "timestamp": datetime.now().isoformat(),
             }
 
         latest_metrics = self.metrics_history[-1]
-        
+
         # 過去1時間の平均値計算
         one_hour_ago = datetime.now() - timedelta(hours=1)
         recent_metrics = [
-            m for m in self.metrics_history 
-            if datetime.fromisoformat(m["timestamp"]) > one_hour_ago
+            m for m in self.metrics_history if datetime.fromisoformat(m["timestamp"]) > one_hour_ago
         ]
 
         if recent_metrics:
-            avg_cpu = sum(m.get("cpu", {}).get("usage_percent", 0) for m in recent_metrics) / len(recent_metrics)
-            avg_memory = sum(m.get("memory", {}).get("percent", 0) for m in recent_metrics) / len(recent_metrics)
+            avg_cpu = sum(m.get("cpu", {}).get("usage_percent", 0) for m in recent_metrics) / len(
+                recent_metrics
+            )
+            avg_memory = sum(m.get("memory", {}).get("percent", 0) for m in recent_metrics) / len(
+                recent_metrics
+            )
         else:
             avg_cpu = latest_metrics.get("cpu", {}).get("usage_percent", 0)
             avg_memory = latest_metrics.get("memory", {}).get("percent", 0)
@@ -282,17 +293,14 @@ class SystemPerformanceMonitor:
                 "cpu_percent": latest_metrics.get("cpu", {}).get("usage_percent", 0),
                 "memory_percent": latest_metrics.get("memory", {}).get("percent", 0),
                 "disk_usage": latest_metrics.get("disk", {}),
-                "timestamp": latest_metrics.get("timestamp")
-            },
-            "averages_1h": {
-                "cpu_percent": avg_cpu,
-                "memory_percent": avg_memory
+                "timestamp": latest_metrics.get("timestamp"),
             },
+            "averages_1h": {"cpu_percent": avg_cpu, "memory_percent": avg_memory},
             "thresholds": self.config["thresholds"],
             "monitoring_status": {
                 "is_running": self.is_monitoring,
-                "metrics_count": len(self.metrics_history)
-            }
+                "metrics_count": len(self.metrics_history),
+            },
         }
 
     def start_monitoring(self) -> None:
@@ -336,10 +344,7 @@ class SystemPerformanceMonitor:
                 response_metrics = self.collect_response_time_metrics()
 
                 # 統合メトリクス
-                combined_metrics = {
-                    **system_metrics,
-                    "response_times": response_metrics
-                }
+                combined_metrics = {**system_metrics, "response_times": response_metrics}
 
                 # 履歴に追加
                 self.metrics_history.append(combined_metrics)
@@ -361,12 +366,16 @@ class SystemPerformanceMonitor:
         try:
             retention_hours = self.config["data_retention_hours"]
             cutoff_time = datetime.now() - timedelta(hours=retention_hours)
-            
+
             # 古いデータを削除
-            self.metrics_history = deque([
-                m for m in self.metrics_history 
-                if datetime.fromisoformat(m["timestamp"]) > cutoff_time
-            ], maxlen=1000)
+            self.metrics_history = deque(
+                [
+                    m
+                    for m in self.metrics_history
+                    if datetime.fromisoformat(m["timestamp"]) > cutoff_time
+                ],
+                maxlen=1000,
+            )
 
         except Exception as e:
             self.logger.error(f"Metrics cleanup failed: {e}")
@@ -378,13 +387,16 @@ class SystemPerformanceMonitor:
             "config": self.config,
             "thread_alive": self.monitor_thread.is_alive() if self.monitor_thread else False,
             "metrics_count": len(self.metrics_history),
-            "last_collection": self.metrics_history[-1]["timestamp"] if self.metrics_history else None
+            "last_collection": (
+                self.metrics_history[-1]["timestamp"] if self.metrics_history else None
+            ),
         }
 
 
 # グローバルインスタンス
 performance_monitor = None
 
+
 def get_performance_monitor() -> SystemPerformanceMonitor:
     """パフォーマンス監視インスタンス取得"""
     global performance_monitor
@@ -412,4 +424,4 @@ def main():
 
 
 if __name__ == "__main__":
-    main()
\ No newline at end of file
+    main()
diff --git a/src/performance_profiler.py b/src/performance_profiler.py
index 0281b92..32b1090 100644
--- a/src/performance_profiler.py
+++ b/src/performance_profiler.py
@@ -6,40 +6,42 @@
 """
 
 import asyncio
+import cProfile
+import io
 import json
+import logging
 import os
-import psutil
+import pstats
 import threading
 import time
 import tracemalloc
 from collections import deque
-from datetime import datetime, timezone
-from typing import Dict, List, Any, Optional, Callable
-import logging
-import cProfile
-import pstats
-import io
 from contextlib import contextmanager
+from datetime import datetime, timezone
+from typing import Any, Callable, Dict, List, Optional
+
+import psutil
+
 
 class ResourceMonitor:
     """システムリソース監視クラス"""
-    
+
     def __init__(self, interval: float = 1.0, history_size: int = 1000):
         self.interval = interval
         self.history_size = history_size
         self.monitoring = False
         self.monitor_thread = None
-        
+
         # メトリクス履歴
         self.cpu_history = deque(maxlen=history_size)
         self.memory_history = deque(maxlen=history_size)
         self.disk_history = deque(maxlen=history_size)
         self.network_history = deque(maxlen=history_size)
         self.process_history = deque(maxlen=history_size)
-        
+
         # アラートコールバック
         self.alert_callbacks: List[Callable] = []
-        
+
         # 閾値設定
         self.thresholds = {
             "cpu_warning": 70.0,
@@ -49,47 +51,47 @@ class ResourceMonitor:
             "disk_warning": 80.0,
             "disk_critical": 95.0,
         }
-        
+
         # ログ設定
         logging.basicConfig(level=logging.INFO)
         self.logger = logging.getLogger(__name__)
-        
+
     def add_alert_callback(self, callback: Callable):
         """アラートコールバックを追加"""
         self.alert_callbacks.append(callback)
-        
+
     def start_monitoring(self):
         """監視開始"""
         if self.monitoring:
             return
-            
+
         self.monitoring = True
         self.monitor_thread = threading.Thread(target=self._monitor_loop)
         self.monitor_thread.daemon = True
         self.monitor_thread.start()
         self.logger.info("リソース監視を開始しました")
-        
+
     def stop_monitoring(self):
         """監視停止"""
         self.monitoring = False
         if self.monitor_thread:
             self.monitor_thread.join()
         self.logger.info("リソース監視を停止しました")
-        
+
     def _monitor_loop(self):
         """監視ループ"""
         while self.monitoring:
             try:
                 timestamp = datetime.now(timezone.utc)
-                
+
                 # CPU使用率
                 cpu_percent = psutil.cpu_percent(interval=None)
                 cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
-                
+
                 # メモリ使用率
                 memory = psutil.virtual_memory()
                 swap = psutil.swap_memory()
-                
+
                 # ディスク使用率
                 disk_usage = {}
                 for partition in psutil.disk_partitions():
@@ -99,14 +101,14 @@ class ResourceMonitor:
                             "total": usage.total,
                             "used": usage.used,
                             "free": usage.free,
-                            "percent": (usage.used / usage.total) * 100
+                            "percent": (usage.used / usage.total) * 100,
                         }
                     except PermissionError:
                         continue
-                        
+
                 # ネットワーク統計
                 network = psutil.net_io_counters()
-                
+
                 # プロセス情報
                 current_process = psutil.Process()
                 process_info = {
@@ -118,67 +120,70 @@ class ResourceMonitor:
                     "open_files": len(current_process.open_files()),
                     "connections": len(current_process.connections()),
                 }
-                
+
                 # データ記録
-                self.cpu_history.append({
-                    "timestamp": timestamp.isoformat(),
-                    "total": cpu_percent,
-                    "per_core": cpu_per_core
-                })
-                
-                self.memory_history.append({
-                    "timestamp": timestamp.isoformat(),
-                    "virtual": memory._asdict(),
-                    "swap": swap._asdict()
-                })
-                
-                self.disk_history.append({
-                    "timestamp": timestamp.isoformat(),
-                    "usage": disk_usage
-                })
-                
-                self.network_history.append({
-                    "timestamp": timestamp.isoformat(),
-                    "stats": network._asdict()
-                })
-                
-                self.process_history.append({
-                    "timestamp": timestamp.isoformat(),
-                    "process": process_info
-                })
-                
+                self.cpu_history.append(
+                    {
+                        "timestamp": timestamp.isoformat(),
+                        "total": cpu_percent,
+                        "per_core": cpu_per_core,
+                    }
+                )
+
+                self.memory_history.append(
+                    {
+                        "timestamp": timestamp.isoformat(),
+                        "virtual": memory._asdict(),
+                        "swap": swap._asdict(),
+                    }
+                )
+
+                self.disk_history.append({"timestamp": timestamp.isoformat(), "usage": disk_usage})
+
+                self.network_history.append(
+                    {"timestamp": timestamp.isoformat(), "stats": network._asdict()}
+                )
+
+                self.process_history.append(
+                    {"timestamp": timestamp.isoformat(), "process": process_info}
+                )
+
                 # アラートチェック
                 self._check_alerts(cpu_percent, memory.percent, disk_usage)
-                
+
             except Exception as e:
                 self.logger.error(f"監視中にエラーが発生: {e}")
-                
+
             time.sleep(self.interval)
-            
+
     def _check_alerts(self, cpu_percent: float, memory_percent: float, disk_usage: Dict):
         """アラートチェック"""
         alerts = []
-        
+
         # CPU アラート
         if cpu_percent >= self.thresholds["cpu_critical"]:
             alerts.append({"type": "cpu", "level": "critical", "value": cpu_percent})
         elif cpu_percent >= self.thresholds["cpu_warning"]:
             alerts.append({"type": "cpu", "level": "warning", "value": cpu_percent})
-            
+
         # メモリ アラート
         if memory_percent >= self.thresholds["memory_critical"]:
             alerts.append({"type": "memory", "level": "critical", "value": memory_percent})
         elif memory_percent >= self.thresholds["memory_warning"]:
             alerts.append({"type": "memory", "level": "warning", "value": memory_percent})
-            
+
         # ディスク アラート
         for device, usage in disk_usage.items():
             percent = usage["percent"]
             if percent >= self.thresholds["disk_critical"]:
-                alerts.append({"type": "disk", "level": "critical", "device": device, "value": percent})
+                alerts.append(
+                    {"type": "disk", "level": "critical", "device": device, "value": percent}
+                )
             elif percent >= self.thresholds["disk_warning"]:
-                alerts.append({"type": "disk", "level": "warning", "device": device, "value": percent})
-                
+                alerts.append(
+                    {"type": "disk", "level": "warning", "device": device, "value": percent}
+                )
+
         # アラートコールバック実行
         for alert in alerts:
             for callback in self.alert_callbacks:
@@ -186,45 +191,47 @@ class ResourceMonitor:
                     callback(alert)
                 except Exception as e:
                     self.logger.error(f"アラートコールバック実行エラー: {e}")
-                    
+
     def get_current_stats(self) -> Dict[str, Any]:
         """現在の統計情報を取得"""
         if not self.cpu_history:
             return {"error": "監視データがありません"}
-            
+
         latest_cpu = self.cpu_history[-1]
         latest_memory = self.memory_history[-1]
         latest_disk = self.disk_history[-1]
         latest_network = self.network_history[-1]
         latest_process = self.process_history[-1]
-        
+
         return {
             "timestamp": latest_cpu["timestamp"],
             "cpu": latest_cpu,
             "memory": latest_memory,
             "disk": latest_disk,
             "network": latest_network,
-            "process": latest_process
+            "process": latest_process,
         }
-        
+
     def get_historical_stats(self, minutes: int = 10) -> Dict[str, List]:
         """過去の統計情報を取得"""
         cutoff_time = datetime.now(timezone.utc).timestamp() - (minutes * 60)
-        
+
         def filter_by_time(history):
             return [
-                item for item in history
-                if datetime.fromisoformat(item["timestamp"].replace('Z', '+00:00')).timestamp() >= cutoff_time
+                item
+                for item in history
+                if datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).timestamp()
+                >= cutoff_time
             ]
-            
+
         return {
             "cpu": filter_by_time(self.cpu_history),
             "memory": filter_by_time(self.memory_history),
             "disk": filter_by_time(self.disk_history),
             "network": filter_by_time(self.network_history),
-            "process": filter_by_time(self.process_history)
+            "process": filter_by_time(self.process_history),
         }
-        
+
     def export_stats(self, filepath: str):
         """統計情報をファイルにエクスポート"""
         stats = {
@@ -234,23 +241,24 @@ class ResourceMonitor:
             "memory_history": list(self.memory_history),
             "disk_history": list(self.disk_history),
             "network_history": list(self.network_history),
-            "process_history": list(self.process_history)
+            "process_history": list(self.process_history),
         }
-        
+
         os.makedirs(os.path.dirname(filepath), exist_ok=True)
-        with open(filepath, 'w', encoding='utf-8') as f:
+        with open(filepath, "w", encoding="utf-8") as f:
             json.dump(stats, f, indent=2, ensure_ascii=False)
-            
+
         self.logger.info(f"統計情報をエクスポート: {filepath}")
 
+
 class PerformanceProfiler:
     """パフォーマンスプロファイラー"""
-    
+
     def __init__(self):
         self.profiler = None
         self.profiling_active = False
         self.resource_monitor = ResourceMonitor()
-        
+
     @contextmanager
     def profile_context(self, output_file: Optional[str] = None):
         """プロファイリングコンテキストマネージャー"""
@@ -259,49 +267,49 @@ class PerformanceProfiler:
             yield self
         finally:
             self.stop_profiling(output_file)
-            
+
     def start_profiling(self):
         """プロファイリング開始"""
         if self.profiling_active:
             return
-            
+
         self.profiler = cProfile.Profile()
         self.profiler.enable()
         self.profiling_active = True
-        
+
         # リソース監視も開始
         self.resource_monitor.start_monitoring()
-        
+
         # メモリトレース開始
         tracemalloc.start()
-        
+
     def stop_profiling(self, output_file: Optional[str] = None):
         """プロファイリング停止"""
         if not self.profiling_active:
             return
-            
+
         self.profiler.disable()
         self.profiling_active = False
-        
+
         # リソース監視停止
         self.resource_monitor.stop_monitoring()
-        
+
         # メモリトレース停止
         current, peak = tracemalloc.get_traced_memory()
         tracemalloc.stop()
-        
+
         # 結果出力
         if output_file:
             self._save_profile_results(output_file, current, peak)
-            
+
     def _save_profile_results(self, output_file: str, memory_current: int, memory_peak: int):
         """プロファイル結果を保存"""
         # プロファイル統計
         s = io.StringIO()
         ps = pstats.Stats(self.profiler, stream=s)
-        ps.sort_stats('cumulative')
+        ps.sort_stats("cumulative")
         ps.print_stats(50)  # 上位50関数
-        
+
         # 結果をまとめる
         results = {
             "timestamp": datetime.now(timezone.utc).isoformat(),
@@ -309,102 +317,104 @@ class PerformanceProfiler:
                 "current_bytes": memory_current,
                 "peak_bytes": memory_peak,
                 "current_mb": memory_current / 1024 / 1024,
-                "peak_mb": memory_peak / 1024 / 1024
+                "peak_mb": memory_peak / 1024 / 1024,
             },
             "profile_stats": s.getvalue(),
-            "resource_stats": self.resource_monitor.get_current_stats()
+            "resource_stats": self.resource_monitor.get_current_stats(),
         }
-        
+
         # ファイル保存
         os.makedirs(os.path.dirname(output_file), exist_ok=True)
-        
+
         # JSON形式で保存
-        json_file = output_file.replace('.prof', '.json')
-        with open(json_file, 'w', encoding='utf-8') as f:
+        json_file = output_file.replace(".prof", ".json")
+        with open(json_file, "w", encoding="utf-8") as f:
             json.dump(results, f, indent=2, ensure_ascii=False)
-            
+
         # バイナリプロファイルも保存
         self.profiler.dump_stats(output_file)
-        
+
         print(f"プロファイル結果を保存: {json_file}")
         print(f"バイナリプロファイル: {output_file}")
-        
+
     def analyze_hotspots(self, top_n: int = 20) -> List[Dict[str, Any]]:
         """ホットスポット分析"""
         if not self.profiler:
             return []
-            
+
         s = io.StringIO()
         ps = pstats.Stats(self.profiler, stream=s)
-        ps.sort_stats('cumulative')
-        
+        ps.sort_stats("cumulative")
+
         hotspots = []
         for func, (cc, nc, tt, ct, callers) in ps.stats.items():
             filename, line, func_name = func
-            hotspots.append({
-                "function": func_name,
-                "filename": filename,
-                "line": line,
-                "call_count": cc,
-                "total_time": tt,
-                "cumulative_time": ct,
-                "time_per_call": tt / cc if cc > 0 else 0
-            })
-            
-        return sorted(hotspots, key=lambda x: x['cumulative_time'], reverse=True)[:top_n]
-        
+            hotspots.append(
+                {
+                    "function": func_name,
+                    "filename": filename,
+                    "line": line,
+                    "call_count": cc,
+                    "total_time": tt,
+                    "cumulative_time": ct,
+                    "time_per_call": tt / cc if cc > 0 else 0,
+                }
+            )
+
+        return sorted(hotspots, key=lambda x: x["cumulative_time"], reverse=True)[:top_n]
+
     def get_memory_profile(self) -> Dict[str, Any]:
         """メモリプロファイル取得"""
         if not tracemalloc.is_tracing():
             return {"error": "メモリトレースが無効です"}
-            
+
         current, peak = tracemalloc.get_traced_memory()
         snapshot = tracemalloc.take_snapshot()
-        top_stats = snapshot.statistics('lineno')
-        
+        top_stats = snapshot.statistics("lineno")
+
         memory_hotspots = []
         for stat in top_stats[:20]:
-            memory_hotspots.append({
-                "filename": stat.traceback.format()[0],
-                "size_bytes": stat.size,
-                "size_mb": stat.size / 1024 / 1024,
-                "count": stat.count
-            })
-            
+            memory_hotspots.append(
+                {
+                    "filename": stat.traceback.format()[0],
+                    "size_bytes": stat.size,
+                    "size_mb": stat.size / 1024 / 1024,
+                    "count": stat.count,
+                }
+            )
+
         return {
-            "current_usage": {
-                "bytes": current,
-                "mb": current / 1024 / 1024
-            },
-            "peak_usage": {
-                "bytes": peak,
-                "mb": peak / 1024 / 1024
-            },
-            "hotspots": memory_hotspots
+            "current_usage": {"bytes": current, "mb": current / 1024 / 1024},
+            "peak_usage": {"bytes": peak, "mb": peak / 1024 / 1024},
+            "hotspots": memory_hotspots,
         }
 
+
 # グローバルプロファイラーインスタンス
 global_profiler = PerformanceProfiler()
 
+
 def profile_function(func):
     """関数デコレーター：関数のプロファイリング"""
+
     def wrapper(*args, **kwargs):
         timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
         output_file = f"C:/Users/User/Trae/ORCH-Next/data/profiles/{func.__name__}_{timestamp}.prof"
-        
+
         with global_profiler.profile_context(output_file):
             return func(*args, **kwargs)
-            
+
     return wrapper
 
+
 def alert_handler(alert: Dict[str, Any]):
     """デフォルトアラートハンドラー"""
     level = alert.get("level", "info")
     alert_type = alert.get("type", "unknown")
     value = alert.get("value", 0)
-    
+
     message = f"[{level.upper()}] {alert_type} アラート: {value:.1f}%"
-    
+
     if level == "critical":
         logging.error(message)
     elif level == "warning":
@@ -412,26 +422,27 @@ def alert_handler(alert: Dict[str, Any]):
     else:
         logging.info(message)
 
+
 # デフォルトアラートハンドラーを設定
 global_profiler.resource_monitor.add_alert_callback(alert_handler)
 
 if __name__ == "__main__":
     # テスト実行
     print("パフォーマンスプロファイラーテスト開始")
-    
+
     # リソース監視テスト
     monitor = ResourceMonitor(interval=0.5)
     monitor.start_monitoring()
-    
+
     print("5秒間のリソース監視...")
     time.sleep(5)
-    
+
     stats = monitor.get_current_stats()
     print(f"現在のCPU使用率: {stats['cpu']['total']:.1f}%")
     print(f"現在のメモリ使用率: {stats['memory']['virtual']['percent']:.1f}%")
-    
+
     monitor.stop_monitoring()
-    
+
     # プロファイリングテスト
     @profile_function
     def test_function():
@@ -440,9 +451,9 @@ if __name__ == "__main__":
         for i in range(1000000):
             total += i * i
         return total
-        
+
     print("\nプロファイリングテスト実行...")
     result = test_function()
     print(f"計算結果: {result}")
-    
-    print("✓ パフォーマンスプロファイラーテスト完了")
\ No newline at end of file
+
+    print("✓ パフォーマンスプロファイラーテスト完了")
diff --git a/src/security_manager.py b/src/security_manager.py
index aaec785..3ad712f 100644
--- a/src/security_manager.py
+++ b/src/security_manager.py
@@ -3,62 +3,64 @@
 認証、暗号化、アクセス制御を統合管理
 """
 
-import os
+import base64
 import hashlib
+import ipaddress
+import json
+import logging
+import os
 import secrets
-import jwt
-import bcrypt
+import time
 from datetime import datetime, timedelta, timezone
-from typing import Dict, List, Optional, Any, Tuple
+from functools import wraps
+from pathlib import Path
+from typing import Any, Dict, List, Optional, Tuple
+
+import bcrypt
+import jwt
 from cryptography.fernet import Fernet
 from cryptography.hazmat.primitives import hashes
 from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
-import base64
-import logging
-import json
-import time
-from functools import wraps
-import ipaddress
-from pathlib import Path
+
 
 class SecurityManager:
     """セキュリティ管理システム"""
-    
+
     def __init__(self, config_path: str = "config/security.json"):
         self.logger = logging.getLogger(__name__)
         self.config_path = config_path
         self.config = self._load_config()
-        
+
         # 暗号化キー管理
         self.encryption_key = self._get_or_create_encryption_key()
         self.cipher_suite = Fernet(self.encryption_key)
-        
+
         # JWT設定
         self.jwt_secret = self._get_or_create_jwt_secret()
         self.jwt_algorithm = "HS256"
         self.jwt_expiry_hours = 24
-        
+
         # ユーザー管理
         self.users: Dict[str, Dict] = {}
-        
+
         # セッション管理
         self.sessions: Dict[str, Dict] = {}
         self.active_sessions: Dict[str, Dict] = {}
         self.failed_attempts: Dict[str, List[float]] = {}
-        
+
         # 監査ログ
         self.audit_logs: List[Dict] = []
-        
+
         # アクセス制御
         self.permissions: Dict[str, List[str]] = {}
         self.roles: Dict[str, List[str]] = {}
-        
+
         # IPホワイトリスト
         self.ip_whitelist: List[str] = []
-        
+
         # レート制限
         self.rate_limits: Dict[str, List[float]] = {}
-        
+
         # セキュリティポリシー
         self.security_policies = {
             "max_failed_attempts": 5,
@@ -67,16 +69,16 @@ class SecurityManager:
             "password_require_special": True,
             "session_timeout": 3600,  # 1時間
             "allowed_ip_ranges": ["127.0.0.1/32", "192.168.0.0/16"],
-            "rate_limit_per_minute": 10
+            "rate_limit_per_minute": 10,
         }
-        
+
         self.logger.info("SecurityManager初期化完了")
 
     def _load_config(self) -> Dict:
         """設定ファイル読み込み"""
         try:
             if os.path.exists(self.config_path):
-                with open(self.config_path, 'r', encoding='utf-8') as f:
+                with open(self.config_path, "r", encoding="utf-8") as f:
                     return json.load(f)
             else:
                 # デフォルト設定
@@ -84,7 +86,7 @@ class SecurityManager:
                     "encryption_enabled": True,
                     "audit_logging": True,
                     "rate_limiting": True,
-                    "ip_whitelist_enabled": False
+                    "ip_whitelist_enabled": False,
                 }
                 self._save_config(default_config)
                 return default_config
@@ -96,7 +98,7 @@ class SecurityManager:
         """設定ファイル保存"""
         try:
             os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
-            with open(self.config_path, 'w', encoding='utf-8') as f:
+            with open(self.config_path, "w", encoding="utf-8") as f:
                 json.dump(config, f, indent=2, ensure_ascii=False)
         except Exception as e:
             self.logger.error(f"設定ファイル保存エラー: {e}")
@@ -106,12 +108,12 @@ class SecurityManager:
         key_file = "config/encryption.key"
         try:
             if os.path.exists(key_file):
-                with open(key_file, 'rb') as f:
+                with open(key_file, "rb") as f:
                     return f.read()
             else:
                 key = Fernet.generate_key()
                 os.makedirs(os.path.dirname(key_file), exist_ok=True)
-                with open(key_file, 'wb') as f:
+                with open(key_file, "wb") as f:
                     f.write(key)
                 return key
         except Exception as e:
@@ -123,12 +125,12 @@ class SecurityManager:
         secret_file = "config/jwt_secret.key"
         try:
             if os.path.exists(secret_file):
-                with open(secret_file, 'r') as f:
+                with open(secret_file, "r") as f:
                     return f.read().strip()
             else:
                 secret = secrets.token_urlsafe(32)
                 os.makedirs(os.path.dirname(secret_file), exist_ok=True)
-                with open(secret_file, 'w') as f:
+                with open(secret_file, "w") as f:
                     f.write(secret)
                 return secret
         except Exception as e:
@@ -139,8 +141,8 @@ class SecurityManager:
         """パスワードハッシュ化"""
         try:
             salt = bcrypt.gensalt()
-            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
-            return hashed.decode('utf-8')
+            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
+            return hashed.decode("utf-8")
         except Exception as e:
             self.logger.error(f"パスワードハッシュ化エラー: {e}")
             raise
@@ -148,7 +150,7 @@ class SecurityManager:
     def verify_password(self, password: str, hashed: str) -> bool:
         """パスワード検証"""
         try:
-            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
+            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
         except Exception as e:
             self.logger.error(f"パスワード検証エラー: {e}")
             return False
@@ -156,24 +158,26 @@ class SecurityManager:
     def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
         """パスワード強度検証"""
         errors = []
-        
+
         if len(password) < self.security_policies["password_min_length"]:
-            errors.append(f"パスワードは{self.security_policies['password_min_length']}文字以上である必要があります")
-        
+            errors.append(
+                f"パスワードは{self.security_policies['password_min_length']}文字以上である必要があります"
+            )
+
         if not any(c.isupper() for c in password):
             errors.append("大文字を含む必要があります")
-        
+
         if not any(c.islower() for c in password):
             errors.append("小文字を含む必要があります")
-        
+
         if not any(c.isdigit() for c in password):
             errors.append("数字を含む必要があります")
-        
+
         if self.security_policies["password_require_special"]:
             special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
             if not any(c in special_chars for c in password):
                 errors.append("特殊文字を含む必要があります")
-        
+
         return len(errors) == 0, errors
 
     def check_password_strength(self, password: str) -> bool:
@@ -188,12 +192,12 @@ class SecurityManager:
             if not self.check_password_strength(password):
                 self.logger.warning(f"パスワード強度不足: {username}")
                 return False
-            
+
             # 既存ユーザーチェック
             if username in self.users:
                 self.logger.warning(f"ユーザー既存: {username}")
                 return False
-            
+
             # ユーザー登録
             hashed_password = self.hash_password(password)
             self.users[username] = {
@@ -202,15 +206,15 @@ class SecurityManager:
                 "created_at": datetime.now().isoformat(),
                 "last_login": None,
                 "failed_attempts": 0,
-                "locked_until": None
+                "locked_until": None,
             }
-            
+
             # 監査ログ
             self.log_security_event("user_registered", username, f"ユーザー登録: {role}")
-            
+
             self.logger.info(f"ユーザー登録成功: {username}")
             return True
-            
+
         except Exception as e:
             self.logger.error(f"ユーザー登録エラー: {e}")
             return False
@@ -222,9 +226,9 @@ class SecurityManager:
             if username not in self.users:
                 self.log_security_event("login_failed", username, "ユーザー不存在")
                 return None
-            
+
             user = self.users[username]
-            
+
             # アカウントロックチェック
             if user.get("locked_until"):
                 lock_time = datetime.fromisoformat(user["locked_until"])
@@ -235,31 +239,39 @@ class SecurityManager:
                     # ロック解除
                     user["locked_until"] = None
                     user["failed_attempts"] = 0
-            
+
             # パスワード検証
             if self.verify_password(password, user["password_hash"]):
                 # 認証成功
                 user["last_login"] = datetime.now().isoformat()
                 user["failed_attempts"] = 0
-                
+
                 # JWTトークン生成
                 token = self.generate_jwt_token(username, [user["role"]])
-                
+
                 self.log_security_event("login_success", username, "認証成功")
                 return token
             else:
                 # 認証失敗
                 user["failed_attempts"] += 1
-                
+
                 # 失敗回数チェック
                 if user["failed_attempts"] >= self.security_policies["max_failed_attempts"]:
-                    lock_until = datetime.now() + timedelta(seconds=self.security_policies["lockout_duration"])
+                    lock_until = datetime.now() + timedelta(
+                        seconds=self.security_policies["lockout_duration"]
+                    )
                     user["locked_until"] = lock_until.isoformat()
-                    self.log_security_event("account_locked", username, f"アカウントロック: {user['failed_attempts']}回失敗")
-                
-                self.log_security_event("login_failed", username, f"パスワード不正: {user['failed_attempts']}回目")
+                    self.log_security_event(
+                        "account_locked",
+                        username,
+                        f"アカウントロック: {user['failed_attempts']}回失敗",
+                    )
+
+                self.log_security_event(
+                    "login_failed", username, f"パスワード不正: {user['failed_attempts']}回目"
+                )
                 return None
-                
+
         except Exception as e:
             self.logger.error(f"認証エラー: {e}")
             return None
@@ -271,10 +283,10 @@ class SecurityManager:
                 "user_id": user_id,
                 "roles": roles or [],
                 "iat": datetime.now(timezone.utc),
-                "exp": datetime.now(timezone.utc) + timedelta(hours=self.jwt_expiry_hours)
+                "exp": datetime.now(timezone.utc) + timedelta(hours=self.jwt_expiry_hours),
             }
             token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
-            
+
             # セッション記録
             session_id = secrets.token_urlsafe(16)
             self.active_sessions[session_id] = {
@@ -282,9 +294,9 @@ class SecurityManager:
                 "token": token,
                 "created_at": time.time(),
                 "last_activity": time.time(),
-                "ip_address": None  # 実際の実装では取得
+                "ip_address": None,  # 実際の実装では取得
             }
-            
+
             return token
         except Exception as e:
             self.logger.error(f"JWTトークン生成エラー: {e}")
@@ -298,23 +310,26 @@ class SecurityManager:
         """JWTトークン検証"""
         try:
             payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
-            
+
             # ユーザー名をpayloadに追加（互換性のため）
             if "user_id" in payload:
                 payload["username"] = payload["user_id"]
-            
+
             # セッション確認
             for session_id, session_data in self.active_sessions.items():
                 if session_data["token"] == token:
                     # セッションタイムアウト確認
-                    if time.time() - session_data["last_activity"] > self.security_policies["session_timeout"]:
+                    if (
+                        time.time() - session_data["last_activity"]
+                        > self.security_policies["session_timeout"]
+                    ):
                         del self.active_sessions[session_id]
                         return None
-                    
+
                     # 最終活動時刻更新
                     session_data["last_activity"] = time.time()
                     return payload
-            
+
             return None
         except jwt.ExpiredSignatureError:
             self.logger.warning("期限切れトークン")
@@ -329,8 +344,8 @@ class SecurityManager:
     def encrypt_data(self, data: str) -> str:
         """データ暗号化"""
         try:
-            encrypted = self.cipher_suite.encrypt(data.encode('utf-8'))
-            return base64.b64encode(encrypted).decode('utf-8')
+            encrypted = self.cipher_suite.encrypt(data.encode("utf-8"))
+            return base64.b64encode(encrypted).decode("utf-8")
         except Exception as e:
             self.logger.error(f"データ暗号化エラー: {e}")
             raise
@@ -338,34 +353,35 @@ class SecurityManager:
     def decrypt_data(self, encrypted_data: str) -> str:
         """データ復号化"""
         try:
-            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
+            encrypted_bytes = base64.b64decode(encrypted_data.encode("utf-8"))
             decrypted = self.cipher_suite.decrypt(encrypted_bytes)
-            return decrypted.decode('utf-8')
+            return decrypted.decode("utf-8")
         except Exception as e:
             self.logger.error(f"データ復号化エラー: {e}")
             raise
 
-    def check_rate_limit_detailed(self, identifier: str, max_attempts: int = None, window_seconds: int = 300) -> bool:
+    def check_rate_limit_detailed(
+        self, identifier: str, max_attempts: int = None, window_seconds: int = 300
+    ) -> bool:
         """詳細レート制限チェック"""
         if max_attempts is None:
             max_attempts = self.security_policies["max_failed_attempts"]
-        
+
         current_time = time.time()
-        
+
         if identifier not in self.rate_limits:
             self.rate_limits[identifier] = []
-        
+
         # 古いエントリを削除
         cutoff_time = current_time - window_seconds
         self.rate_limits[identifier] = [
-            timestamp for timestamp in self.rate_limits[identifier]
-            if timestamp > cutoff_time
+            timestamp for timestamp in self.rate_limits[identifier] if timestamp > cutoff_time
         ]
-        
+
         # レート制限チェック
         if len(self.rate_limits[identifier]) >= max_attempts:
             return False
-        
+
         # 新しいリクエストを記録
         self.rate_limits[identifier].append(current_time)
         return True
@@ -374,7 +390,7 @@ class SecurityManager:
         """失敗試行記録"""
         if identifier not in self.failed_attempts:
             self.failed_attempts[identifier] = []
-        
+
         self.failed_attempts[identifier].append(time.time())
         self.logger.warning(f"認証失敗記録: {identifier}")
 
@@ -382,7 +398,7 @@ class SecurityManager:
         """IP許可確認（詳細版）"""
         if not self.config.get("ip_whitelist_enabled", False):
             return True
-        
+
         try:
             ip = ipaddress.ip_address(ip_address)
             for allowed_range in self.security_policies["allowed_ip_ranges"]:
@@ -397,7 +413,7 @@ class SecurityManager:
         """ロール権限追加"""
         if role not in self.permissions:
             self.permissions[role] = []
-        
+
         if permission not in self.permissions[role]:
             self.permissions[role].append(permission)
             self.logger.info(f"権限追加: {role} -> {permission}")
@@ -413,19 +429,19 @@ class SecurityManager:
         """監査ログ記録"""
         if not self.config.get("audit_logging", True):
             return
-        
+
         log_entry = {
             "timestamp": datetime.now().isoformat(),
             "event_type": event_type,
             "user_id": user_id,
-            "details": details or {}
+            "details": details or {},
         }
-        
+
         audit_file = f"logs/security_audit_{datetime.now().strftime('%Y%m%d')}.log"
         try:
             os.makedirs(os.path.dirname(audit_file), exist_ok=True)
-            with open(audit_file, 'a', encoding='utf-8') as f:
-                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
+            with open(audit_file, "a", encoding="utf-8") as f:
+                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
         except Exception as e:
             self.logger.error(f"監査ログ記録エラー: {e}")
 
@@ -434,14 +450,18 @@ class SecurityManager:
         return {
             "overall_status": "healthy",
             "active_sessions": len(self.active_sessions),
-            "failed_login_attempts": sum(len(attempts) for attempts in self.failed_attempts.values()),
+            "failed_login_attempts": sum(
+                len(attempts) for attempts in self.failed_attempts.values()
+            ),
             "security_score": 85,
-            "failed_attempts_count": sum(len(attempts) for attempts in self.failed_attempts.values()),
+            "failed_attempts_count": sum(
+                len(attempts) for attempts in self.failed_attempts.values()
+            ),
             "encryption_enabled": self.config.get("encryption_enabled", True),
             "audit_logging": self.config.get("audit_logging", True),
             "ip_whitelist_enabled": self.config.get("ip_whitelist_enabled", False),
             "security_policies": self.security_policies,
-            "timestamp": datetime.now().isoformat()
+            "timestamp": datetime.now().isoformat(),
         }
 
     def log_security_event(self, action: str, user: str, details: str) -> None:
@@ -450,10 +470,10 @@ class SecurityManager:
             "action": action,
             "user": user,
             "timestamp": datetime.now().isoformat(),
-            "details": details
+            "details": details,
         }
         self.audit_logs.append(log_entry)
-        
+
         # ファイルにも記録
         self.audit_log(action, user, {"details": details})
 
@@ -467,7 +487,7 @@ class SecurityManager:
         self.sessions[session_id] = {
             "username": username,
             "created_at": time.time(),
-            "last_activity": time.time()
+            "last_activity": time.time(),
         }
         return session_id
 
@@ -475,15 +495,15 @@ class SecurityManager:
         """セッション検証"""
         if session_id not in self.sessions:
             return False
-        
+
         session = self.sessions[session_id]
         current_time = time.time()
-        
+
         # セッションタイムアウトチェック
         if current_time - session["last_activity"] > self.security_policies["session_timeout"]:
             del self.sessions[session_id]
             return False
-        
+
         # 最終アクティビティ更新
         session["last_activity"] = current_time
         return True
@@ -501,22 +521,21 @@ class SecurityManager:
     def check_rate_limit(self, client_ip: str) -> bool:
         """レート制限チェック（簡易版）"""
         current_time = time.time()
-        
+
         if client_ip not in self.rate_limits:
             self.rate_limits[client_ip] = []
-        
+
         # 1分以内のリクエストをカウント
         recent_requests = [
-            req_time for req_time in self.rate_limits[client_ip]
-            if current_time - req_time < 60
+            req_time for req_time in self.rate_limits[client_ip] if current_time - req_time < 60
         ]
-        
+
         self.rate_limits[client_ip] = recent_requests
-        
+
         # レート制限チェック
         if len(recent_requests) >= self.security_policies["rate_limit_per_minute"]:
             return False
-        
+
         # 新しいリクエストを記録
         self.rate_limits[client_ip].append(current_time)
         return True
@@ -525,37 +544,37 @@ class SecurityManager:
         """IP許可確認"""
         if not self.config.get("ip_whitelist_enabled", False):
             return True
-        
+
         # ホワイトリストが空の場合はすべて許可
         if not self.ip_whitelist:
             return True
-        
+
         return ip_address in self.ip_whitelist
 
     def check_permission(self, username: str, required_permission: str) -> bool:
         """権限確認（ユーザー名ベース）"""
         if username not in self.users:
             return False
-        
+
         user_role = self.users[username]["role"]
-        
+
         # 管理者は全権限を持つ
         if user_role == "admin":
             return True
-        
+
         # ユーザーロールの場合、user権限のみ
         if user_role == "user" and required_permission == "user":
             return True
-        
+
         return False
 
     def get_user_permissions(self, username: str) -> List[str]:
         """ユーザー権限取得"""
         if username not in self.users:
             return []
-        
+
         user_role = self.users[username]["role"]
-        
+
         if user_role == "admin":
             return ["admin", "user", "read", "write", "delete"]
         elif user_role == "user":
@@ -567,102 +586,110 @@ class SecurityManager:
         """ユーザー権限追加"""
         if username not in self.users:
             return False
-        
+
         if "permissions" not in self.users[username]:
             self.users[username]["permissions"] = []
-        
+
         if permission not in self.users[username]["permissions"]:
             self.users[username]["permissions"].append(permission)
-        
+
         return True
 
     def remove_user_permission(self, username: str, permission: str) -> bool:
         """ユーザー権限削除"""
         if username not in self.users:
             return False
-        
+
         if "permissions" not in self.users[username]:
             return False
-        
+
         if permission in self.users[username]["permissions"]:
             self.users[username]["permissions"].remove(permission)
             return True
-        
+
         return False
 
     def cleanup_expired_sessions(self) -> None:
         """期限切れセッション削除"""
         current_time = time.time()
         expired_sessions = []
-        
+
         for session_id, session_data in self.active_sessions.items():
-            if current_time - session_data["last_activity"] > self.security_policies["session_timeout"]:
+            if (
+                current_time - session_data["last_activity"]
+                > self.security_policies["session_timeout"]
+            ):
                 expired_sessions.append(session_id)
-        
+
         for session_id in expired_sessions:
             del self.active_sessions[session_id]
             self.logger.info(f"期限切れセッション削除: {session_id}")
 
+
 def require_auth(required_permission: str = None):
     """認証デコレータ"""
+
     def decorator(f):
         @wraps(f)
         def decorated_function(*args, **kwargs):
             # 実際の実装では、リクエストからトークンを取得
             # ここではサンプル実装
-            token = kwargs.get('auth_token')
+            token = kwargs.get("auth_token")
             if not token:
                 return {"error": "認証が必要です"}, 401
-            
+
             security_manager = SecurityManager()
             payload = security_manager.verify_jwt_token(token)
             if not payload:
                 return {"error": "無効なトークンです"}, 401
-            
+
             if required_permission:
-                user_roles = payload.get('roles', [])
+                user_roles = payload.get("roles", [])
                 if not security_manager.check_permission(user_roles, required_permission):
                     return {"error": "権限が不足しています"}, 403
-            
-            kwargs['current_user'] = payload
+
+            kwargs["current_user"] = payload
             return f(*args, **kwargs)
+
         return decorated_function
+
     return decorator
 
+
 if __name__ == "__main__":
     # テスト実行
     security_manager = SecurityManager()
-    
+
     # パスワード強度テスト
     password = "TestPass123!"
     is_valid, errors = security_manager.validate_password_strength(password)
     print(f"パスワード強度: {is_valid}, エラー: {errors}")
-    
+
     # ハッシュ化テスト
     hashed = security_manager.hash_password(password)
     print(f"ハッシュ化: {hashed}")
-    
+
     # 検証テスト
     is_valid = security_manager.verify_password(password, hashed)
     print(f"パスワード検証: {is_valid}")
-    
+
     # JWTトークンテスト
     token = security_manager.generate_jwt_token("test_user", ["admin"])
     print(f"JWTトークン: {token}")
-    
+
     # トークン検証テスト
     payload = security_manager.verify_jwt_token(token)
     print(f"トークン検証: {payload}")
-    
+
     # 暗号化テスト
     data = "機密データ"
     encrypted = security_manager.encrypt_data(data)
     print(f"暗号化: {encrypted}")
-    
+
     # 復号化テスト
     decrypted = security_manager.decrypt_data(encrypted)
     print(f"復号化: {decrypted}")
-    
+
     # セキュリティ状態
     status = security_manager.get_security_status()
-    print(f"セキュリティ状態: {status}")
\ No newline at end of file
+    print(f"セキュリティ状態: {status}")
diff --git a/src/style_manager.py b/src/style_manager.py
index fca9eb3..14eb422 100644
--- a/src/style_manager.py
+++ b/src/style_manager.py
@@ -2,10 +2,13 @@
 リアルタイムCSS調整システム
 文字色や配置を動的に変更できる管理機能
 """
+
 import json
 import os
-from flask import Flask, request, jsonify, render_template_string
-from typing import Dict, Any
+from typing import Any, Dict
+
+from flask import Flask, jsonify, render_template_string, request
+
 
 class StyleManager:
     def __init__(self):
@@ -19,33 +22,33 @@ class StyleManager:
             "button_text_color": "#ffffff",
             "nav_text_color": "#d8e1ff",
             "accent_color": "#00eaff",
-            "muted_text_color": "#8aa0c8"
+            "muted_text_color": "#8aa0c8",
         }
         self.load_styles()
-    
+
     def load_styles(self) -> Dict[str, str]:
         """保存されたスタイル設定を読み込み"""
         if os.path.exists(self.config_file):
             try:
-                with open(self.config_file, 'r', encoding='utf-8') as f:
+                with open(self.config_file, "r", encoding="utf-8") as f:
                     self.styles = json.load(f)
             except:
                 self.styles = self.default_styles.copy()
         else:
             self.styles = self.default_styles.copy()
         return self.styles
-    
+
     def save_styles(self) -> bool:
         """スタイル設定を保存"""
         try:
             os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
-            with open(self.config_file, 'w', encoding='utf-8') as f:
+            with open(self.config_file, "w", encoding="utf-8") as f:
                 json.dump(self.styles, f, indent=2, ensure_ascii=False)
             return True
         except Exception as e:
             print(f"スタイル保存エラー: {e}")
             return False
-    
+
     def update_style(self, key: str, value: str) -> bool:
         """個別スタイルを更新"""
         if key in self.default_styles:
@@ -53,7 +56,7 @@ class StyleManager:
             self.generate_css()
             return self.save_styles()
         return False
-    
+
     def update_multiple_styles(self, updates: Dict[str, str]) -> bool:
         """複数スタイルを一括更新"""
         for key, value in updates.items():
@@ -61,13 +64,13 @@ class StyleManager:
                 self.styles[key] = value
         self.generate_css()
         return self.save_styles()
-    
+
     def reset_to_defaults(self) -> bool:
         """デフォルトスタイルにリセット"""
         self.styles = self.default_styles.copy()
         self.generate_css()
         return self.save_styles()
-    
+
     def generate_css(self) -> str:
         """動的CSSファイルを生成"""
         css_content = f"""
@@ -136,90 +139,100 @@ table td {{
   border-radius: 3px !important;
 }}
 """
-        
+
         try:
             os.makedirs(os.path.dirname(self.css_file), exist_ok=True)
-            with open(self.css_file, 'w', encoding='utf-8') as f:
+            with open(self.css_file, "w", encoding="utf-8") as f:
                 f.write(css_content)
             return css_content
         except Exception as e:
             print(f"CSS生成エラー: {e}")
             return ""
 
+
 def create_style_api(app: Flask):
     """FlaskアプリにスタイルAPIエンドポイントを追加"""
     style_manager = StyleManager()
-    
-    @app.route('/api/styles', methods=['GET'])
+
+    @app.route("/api/styles", methods=["GET"])
     def get_styles():
         """現在のスタイル設定を取得"""
         return jsonify(style_manager.styles)
-    
-    @app.route('/api/styles', methods=['POST'])
+
+    @app.route("/api/styles", methods=["POST"])
     def update_styles():
         """スタイル設定を更新"""
         try:
             data = request.get_json()
             if not data:
                 return jsonify({"error": "データが必要です"}), 400
-            
-            if 'key' in data and 'value' in data:
+
+            if "key" in data and "value" in data:
                 # 単一更新
-                success = style_manager.update_style(data['key'], data['value'])
-            elif 'styles' in data:
+                success = style_manager.update_style(data["key"], data["value"])
+            elif "styles" in data:
                 # 一括更新
-                success = style_manager.update_multiple_styles(data['styles'])
+                success = style_manager.update_multiple_styles(data["styles"])
             else:
                 return jsonify({"error": "無効なデータ形式"}), 400
-            
+
             if success:
-                return jsonify({
-                    "success": True, 
-                    "styles": style_manager.styles,
-                    "message": "スタイルが更新されました"
-                })
+                return jsonify(
+                    {
+                        "success": True,
+                        "styles": style_manager.styles,
+                        "message": "スタイルが更新されました",
+                    }
+                )
             else:
                 return jsonify({"error": "スタイル更新に失敗しました"}), 500
-                
+
         except Exception as e:
             return jsonify({"error": f"エラー: {str(e)}"}), 500
-    
-    @app.route('/api/styles/reset', methods=['POST'])
+
+    @app.route("/api/styles/reset", methods=["POST"])
     def reset_styles():
         """スタイルをデフォルトにリセット"""
         try:
             success = style_manager.reset_to_defaults()
             if success:
-                return jsonify({
-                    "success": True,
-                    "styles": style_manager.styles,
-                    "message": "デフォルトスタイルにリセットしました"
-                })
+                return jsonify(
+                    {
+                        "success": True,
+                        "styles": style_manager.styles,
+                        "message": "デフォルトスタイルにリセットしました",
+                    }
+                )
             else:
                 return jsonify({"error": "リセットに失敗しました"}), 500
         except Exception as e:
             return jsonify({"error": f"エラー: {str(e)}"}), 500
-    
-    @app.route('/api/pages', methods=['GET'])
+
+    @app.route("/api/pages", methods=["GET"])
     def get_available_pages():
         """利用可能なページ一覧を取得"""
         pages = [
-            {"url": "/dashboard", "name": "ダッシュボード", "description": "メインダッシュボード画面"},
+            {
+                "url": "/dashboard",
+                "name": "ダッシュボード",
+                "description": "メインダッシュボード画面",
+            },
             {"url": "/tasks", "name": "タスク管理", "description": "タスク一覧と管理画面"},
-            {"url": "/agents", "name": "エージェント", "description": "AI エージェント管理画面"}
+            {"url": "/agents", "name": "エージェント", "description": "AI エージェント管理画面"},
         ]
         return jsonify(pages)
-    
-    @app.route('/style-manager')
+
+    @app.route("/style-manager")
     def style_manager_page():
         """スタイル管理画面"""
         return render_template_string(STYLE_MANAGER_TEMPLATE)
-    
+
     # 初期CSS生成
     style_manager.generate_css()
-    
+
     return style_manager
 
+
 # スタイル管理画面のHTMLテンプレート
 STYLE_MANAGER_TEMPLATE = """
 <!DOCTYPE html>
@@ -2133,4 +2146,4 @@ if __name__ == "__main__":
     # テスト用
     app = Flask(__name__)
     style_manager = create_style_api(app)
-    app.run(debug=True, port=5003)
\ No newline at end of file
+    app.run(debug=True, port=5003)
diff --git a/src/tools/file_utils.py b/src/tools/file_utils.py
index 5f679a8..f9513a0 100644
--- a/src/tools/file_utils.py
+++ b/src/tools/file_utils.py
@@ -33,95 +33,97 @@ SAFE_PLACEHOLDERS = {"REDACTED", "CHANGEME", "jwt-ci", "webhook-ci", "CHANGE_ME_
 
 class FileSecurityError(Exception):
     """ファイルセキュリティ違反エラー"""
+
     pass
 
 
 class FileIntegrityError(Exception):
     """ファイル整合性エラー"""
+
     pass
 
 
 def check_secrets(content: str, file_path: Optional[str] = None) -> List[Tuple[str, int, str]]:
     """
     コンテンツ内のsecret検出
-    
+
     Args:
         content: 検査対象コンテンツ
         file_path: ファイルパス（ログ用）
-    
+
     Returns:
         検出されたsecretのリスト [(pattern_name, line_number, line_content), ...]
-    
+
     Raises:
         FileSecurityError: secretが検出された場合
     """
     findings = []
     lines = content.splitlines()
-    
+
     for line_num, line in enumerate(lines, 1):
         # Safe placeholderをチェック
         if any(placeholder in line for placeholder in SAFE_PLACEHOLDERS):
             continue
-            
+
         # Secret patternをチェック
         for pattern_name, pattern in SECRET_PATTERNS:
             if pattern.search(line):
                 findings.append((pattern_name, line_num, line.strip()))
-    
+
     if findings:
         error_msg = f"Secrets detected in {file_path or 'content'}:\n"
         for pattern_name, line_num, line_content in findings:
             error_msg += f"  - {pattern_name} at line {line_num}: {line_content[:50]}...\n"
         raise FileSecurityError(error_msg)
-    
+
     return findings
 
 
 def check_eol(content: str, file_path: Optional[str] = None) -> bool:
     """
     EOL検証（LF必須）
-    
+
     Args:
         content: 検査対象コンテンツ
         file_path: ファイルパス（ログ用）
-    
+
     Returns:
         True if LF only, False if CRLF detected
-    
+
     Raises:
         FileIntegrityError: CRLF が検出された場合
     """
-    if '\r\n' in content:
+    if "\r\n" in content:
         raise FileIntegrityError(f"CRLF detected in {file_path or 'content'}. LF required.")
-    
+
     return True
 
 
 def normalize_eol(content: str) -> str:
     """
     EOL正規化（CRLF → LF）
-    
+
     Args:
         content: 正規化対象コンテンツ
-    
+
     Returns:
         LF正規化されたコンテンツ
     """
-    return content.replace('\r\n', '\n').replace('\r', '\n')
+    return content.replace("\r\n", "\n").replace("\r", "\n")
 
 
 def compute_sha256(content: Union[str, bytes]) -> str:
     """
     SHA256ハッシュ計算
-    
+
     Args:
         content: ハッシュ対象コンテンツ
-    
+
     Returns:
         SHA256ハッシュ（16進文字列）
     """
     if isinstance(content, str):
-        content = content.encode('utf-8')
+        content = content.encode("utf-8")
     return hashlib.sha256(content).hexdigest()
 
 
@@ -129,16 +131,16 @@ def atomic_write_text(
     file_path: Union[str, Path],
     content: str,
     *,
-    encoding: str = 'utf-8',
-    newline: str = '\n',
+    encoding: str = "utf-8",
+    newline: str = "\n",
     check_secrets_enabled: bool = True,
     normalize_eol_enabled: bool = True,
     backup: bool = True,
-    verify_integrity: bool = True
+    verify_integrity: bool = True,
 ) -> Dict[str, Any]:
     """
     Atomic text file write with security and integrity checks
-    
+
     Args:
         file_path: 書き込み先ファイルパス
         content: 書き込み内容
@@ -148,7 +150,7 @@ def atomic_write_text(
         normalize_eol_enabled: EOL正規化を実行するか
         backup: バックアップを作成するか
         verify_integrity: 整合性検証を実行するか
-    
+
     Returns:
         操作結果辞書 {
             'sha_in': 入力SHA256,
@@ -156,83 +158,83 @@ def atomic_write_text(
             'backup_path': バックアップパス,
             'verified': 検証結果
         }
-    
+
     Raises:
         FileSecurityError: secret検出時
         FileIntegrityError: 整合性エラー時
     """
     path = Path(file_path)
     path.parent.mkdir(parents=True, exist_ok=True)
-    
+
     # 入力コンテンツ処理
-    processed_content = content# EOL正規化
+    processed_content = content  # EOL正規化
     if normalize_eol_enabled:
         processed_content = normalize_eol(processed_content)
-    
+
     # Security checks
     if check_secrets_enabled:
         check_secrets(processed_content, str(path))
-    
+
     # EOL check
     check_eol(processed_content, str(path))
-    
+
     # SHA256計算
     sha_in = compute_sha256(processed_content)
-    
+
     # Backup existing file
     backup_path = None
     if backup and path.exists():
-        backup_path = path.with_suffix(path.suffix + '.bak')
+        backup_path = path.with_suffix(path.suffix + ".bak")
         if backup_path.exists():
             backup_path.unlink()
         shutil.copy2(path, backup_path)
-    
+
     # Atomic write: tmp → validate → rename
-    tmp_path = path.with_suffix(path.suffix + '.tmp')
+    tmp_path = path.with_suffix(path.suffix + ".tmp")
     try:
         # Write to temporary file
-        with open(tmp_path, 'w', encoding=encoding, newline=newline) as f:
+        with open(tmp_path, "w", encoding=encoding, newline=newline) as f:
             f.write(processed_content)
-        
+
         # Verify written content
         if verify_integrity:
-            with open(tmp_path, 'r', encoding=encoding) as f:
+            with open(tmp_path, "r", encoding=encoding) as f:
                 written_content = f.read()
-            
+
             # Verify content matches
             if written_content != processed_content:
                 raise FileIntegrityError(f"Content verification failed for {path}")
-            
+
             # Verify SHA256
             sha_out = compute_sha256(written_content)
             if sha_out != sha_in:
                 raise FileIntegrityError(f"SHA256 mismatch for {path}: {sha_in} != {sha_out}")
         else:
             sha_out = sha_in
-        
+
         # Atomic rename
-        if os.name == 'nt':
+        if os.name == "nt":
             # Windows: remove target if exists
             if path.exists():
                 path.unlink()
         tmp_path.replace(path)
-        
+
         return {
-            'sha_in': sha_in,
-            'sha_out': sha_out,
-            'backup_path': str(backup_path) if backup_path else None,
-            'verified': verify_integrity
+            "sha_in": sha_in,
+            "sha_out": sha_out,
+            "backup_path": str(backup_path) if backup_path else None,
+            "verified": verify_integrity,
         }
-        
+
     except Exception as e:
         # Cleanup on error
         if tmp_path.exists():
             tmp_path.unlink()
-        
+
         # Restore backup if needed
         if backup_path and backup_path.exists() and not path.exists():
             shutil.copy2(backup_path, path)
-        
+
         raise e
 
 
@@ -243,11 +245,11 @@ def atomic_write_json(
     ensure_ascii: bool = False,
     indent: Optional[int] = 2,
     sort_keys: bool = True,
-    **kwargs
+    **kwargs,
 ) -> Dict[str, Any]:
     """
     Atomic JSON file write with security and integrity checks
-    
+
     Args:
         file_path: 書き込み先ファイルパス
         data: JSON書き込みデータ
@@ -255,7 +257,7 @@ def atomic_write_json(
         indent: インデント（Noneで圧縮）
         sort_keys: キーソートフラグ
         **kwargs: atomic_write_textへの追加引数
-    
+
     Returns:
         atomic_write_textの戻り値
     """
@@ -264,49 +266,49 @@ def atomic_write_json(
         ensure_ascii=ensure_ascii,
         indent=indent,
         sort_keys=sort_keys,
-        separators=(',', ': ') if indent else (',', ':')
+        separators=(",", ": ") if indent else (",", ":"),
     )
-    
+
     # Add trailing newline for consistency
-    if not json_content.endswith('\n'):
-        json_content += '\n'
-    
+    if not json_content.endswith("\n"):
+        json_content += "\n"
+
     return atomic_write_text(file_path, json_content, **kwargs)
 
 
 def safe_read_text(
     file_path: Union[str, Path],
     *,
-    encoding: str = 'utf-8',
+    encoding: str = "utf-8",
     check_secrets_enabled: bool = False,
-    verify_eol: bool = False
+    verify_eol: bool = False,
 ) -> Tuple[str, Dict[str, Any]]:
     """
     Safe text file read with optional security checks
-    
+
     Args:
         file_path: 読み込みファイルパス
         encoding: 文字エンコーディング
         check_secrets_enabled: secret検証を実行するか
         verify_eol: EOL検証を実行するか
-    
+
     Returns:
         (content, metadata) タプル
         metadata: {'sha256': str, 'size': int, 'eol_ok': bool}
-    
+
     Raises:
         FileSecurityError: secret検出時
         FileIntegrityError: EOL違反時
     """
     path = Path(file_path)
-    
-    with open(path, 'r', encoding=encoding) as f:
+
+    with open(path, "r", encoding=encoding) as f:
         content = f.read()
-    
+
     # Security checks
     if check_secrets_enabled:
         check_secrets(content, str(path))
-    
+
     # EOL verification
     eol_ok = True
     if verify_eol:
@@ -316,32 +318,29 @@ def safe_read_text(
             eol_ok = False
             if verify_eol:
                 raise
-    
+
     metadata = {
-        'sha256': compute_sha256(content),
-        'size': len(content.encode(encoding)),
-        'eol_ok': eol_ok
+        "sha256": compute_sha256(content),
+        "size": len(content.encode(encoding)),
+        "eol_ok": eol_ok,
     }
-    
+
     return content, metadata
 
 
-def safe_read_json(
-    file_path: Union[str, Path],
-    **kwargs
-) -> Tuple[Any, Dict[str, Any]]:
+def safe_read_json(file_path: Union[str, Path], **kwargs) -> Tuple[Any, Dict[str, Any]]:
     """
     Safe JSON file read with optional security checks
-    
+
     Args:
         file_path: 読み込みファイルパス
         **kwargs: safe_read_textへの追加引数
-    
+
     Returns:
         (parsed_data, metadata) タプル
     """
     content, metadata = safe_read_text(file_path, **kwargs)
-    
+
     try:
         data = json.loads(content)
         return data, metadata
@@ -352,7 +351,7 @@ def safe_read_json(
 # Convenience functions
 def write_text_lf(file_path: Union[str, Path], content: str, **kwargs) -> Dict[str, Any]:
     """UTF-8 LF text write (convenience function)"""
-    return atomic_write_text(file_path, content, encoding='utf-8', newline='\n', **kwargs)
+    return atomic_write_text(file_path, content, encoding="utf-8", newline="\n", **kwargs)
 
 
 def write_json_lf(file_path: Union[str, Path], data: Any, **kwargs) -> Dict[str, Any]:
@@ -369,4 +368,4 @@ def read_text_safe(file_path: Union[str, Path], **kwargs) -> str:
 def read_json_safe(file_path: Union[str, Path], **kwargs) -> Any:
     """Safe JSON read (data only)"""
     data, _ = safe_read_json(file_path, **kwargs)
-    return data
\ No newline at end of file
+    return data
diff --git a/test_api_functionality.py b/test_api_functionality.py
index c8dd1fa..04ba2fb 100644
--- a/test_api_functionality.py
+++ b/test_api_functionality.py
@@ -4,215 +4,226 @@
 スタイル管理API機能テスト
 """
 
-import requests
 import json
 import time
 from datetime import datetime
 
+import requests
+
+
 class StyleManagerAPITester:
     def __init__(self, base_url="http://localhost:5000"):
         self.base_url = base_url
         self.test_results = []
-        
+
     def test_get_styles(self):
         """スタイル取得APIのテスト"""
         print("\n=== スタイル取得APIテスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/api/styles")
-            
+
             if response.status_code == 200:
                 data = response.json()
                 print(f"✓ スタイル取得成功: {len(data)} 項目")
                 print(f"  レスポンス例: {list(data.keys())[:5]}")
-                self.test_results.append({
-                    "test": "Get Styles API",
-                    "status": "PASS",
-                    "message": f"Successfully retrieved {len(data)} style items"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Get Styles API",
+                        "status": "PASS",
+                        "message": f"Successfully retrieved {len(data)} style items",
+                    }
+                )
             else:
                 print(f"✗ スタイル取得失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Get Styles API",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}: {response.text}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Get Styles API",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}: {response.text}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ スタイル取得エラー: {e}")
-            self.test_results.append({
-                "test": "Get Styles API",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Get Styles API", "status": "FAIL", "message": str(e)}
+            )
+
     def test_update_styles(self):
         """スタイル更新APIのテスト"""
         print("\n=== スタイル更新APIテスト ===")
-        
-        test_data = {
-            "key": "test_color",
-            "value": "#ff0000"
-        }
-        
+
+        test_data = {"key": "test_color", "value": "#ff0000"}
+
         try:
             response = requests.post(
                 f"{self.base_url}/api/styles",
                 json=test_data,
-                headers={'Content-Type': 'application/json'}
+                headers={"Content-Type": "application/json"},
             )
-            
+
             if response.status_code == 200:
                 data = response.json()
                 if data.get("success"):
                     print(f"✓ スタイル更新成功: {test_data['key']} = {test_data['value']}")
-                    self.test_results.append({
-                        "test": "Update Styles API",
-                        "status": "PASS",
-                        "message": "Style update successful"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Update Styles API",
+                            "status": "PASS",
+                            "message": "Style update successful",
+                        }
+                    )
                 else:
                     print(f"✗ スタイル更新失敗: {data.get('message', 'Unknown error')}")
-                    self.test_results.append({
-                        "test": "Update Styles API",
-                        "status": "FAIL",
-                        "message": data.get('message', 'Unknown error')
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Update Styles API",
+                            "status": "FAIL",
+                            "message": data.get("message", "Unknown error"),
+                        }
+                    )
             else:
                 print(f"✗ スタイル更新失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Update Styles API",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}: {response.text}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Update Styles API",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}: {response.text}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ スタイル更新エラー: {e}")
-            self.test_results.append({
-                "test": "Update Styles API",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Update Styles API", "status": "FAIL", "message": str(e)}
+            )
+
     def test_create_patch(self):
         """パッチ作成APIのテスト"""
         print("\n=== パッチ作成APIテスト ===")
-        
+
         test_data = {
             "changes": [
                 {"selector": ".test-element", "property": "color", "value": "#00ff00"},
-                {"selector": ".test-element", "property": "background-color", "value": "#000000"}
+                {"selector": ".test-element", "property": "background-color", "value": "#000000"},
             ]
         }
-        
+
         try:
             response = requests.post(
                 f"{self.base_url}/api/patch",
                 json=test_data,
-                headers={'Content-Type': 'application/json'}
+                headers={"Content-Type": "application/json"},
             )
-            
+
             if response.status_code == 200:
                 data = response.json()
                 if data.get("success"):
                     print(f"✓ パッチ作成成功")
                     print(f"  パッチ内容: {data.get('patch', '')[:100]}...")
-                    self.test_results.append({
-                        "test": "Create Patch API",
-                        "status": "PASS",
-                        "message": "Patch creation successful"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Create Patch API",
+                            "status": "PASS",
+                            "message": "Patch creation successful",
+                        }
+                    )
                 else:
                     print(f"✗ パッチ作成失敗: {data.get('message', 'Unknown error')}")
-                    self.test_results.append({
-                        "test": "Create Patch API",
-                        "status": "FAIL",
-                        "message": data.get('message', 'Unknown error')
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Create Patch API",
+                            "status": "FAIL",
+                            "message": data.get("message", "Unknown error"),
+                        }
+                    )
             else:
                 print(f"✗ パッチ作成失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Create Patch API",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}: {response.text}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Create Patch API",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}: {response.text}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ パッチ作成エラー: {e}")
-            self.test_results.append({
-                "test": "Create Patch API",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Create Patch API", "status": "FAIL", "message": str(e)}
+            )
+
     def test_pages_api(self):
         """ページ一覧APIのテスト"""
         print("\n=== ページ一覧APIテスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/api/pages")
-            
+
             if response.status_code == 200:
                 data = response.json()
                 print(f"✓ ページ一覧取得成功: {len(data)} ページ")
                 for page in data[:3]:  # 最初の3つを表示
                     print(f"  - {page.get('name', 'Unknown')}: {page.get('url', 'No URL')}")
-                self.test_results.append({
-                    "test": "Pages API",
-                    "status": "PASS",
-                    "message": f"Successfully retrieved {len(data)} pages"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Pages API",
+                        "status": "PASS",
+                        "message": f"Successfully retrieved {len(data)} pages",
+                    }
+                )
             else:
                 print(f"✗ ページ一覧取得失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Pages API",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}: {response.text}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Pages API",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}: {response.text}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ ページ一覧取得エラー: {e}")
-            self.test_results.append({
-                "test": "Pages API",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append({"test": "Pages API", "status": "FAIL", "message": str(e)})
+
     def test_invalid_requests(self):
         """不正なリクエストのテスト"""
         print("\n=== 不正リクエストテスト ===")
-        
+
         # 不正なJSONデータでのテスト
         try:
             response = requests.post(
                 f"{self.base_url}/api/styles",
                 data="invalid json",
-                headers={'Content-Type': 'application/json'}
+                headers={"Content-Type": "application/json"},
             )
-            
+
             if response.status_code >= 400:
                 print(f"✓ 不正JSON処理正常: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Invalid JSON Handling",
-                    "status": "PASS",
-                    "message": f"Properly handled invalid JSON with HTTP {response.status_code}"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Invalid JSON Handling",
+                        "status": "PASS",
+                        "message": f"Properly handled invalid JSON with HTTP {response.status_code}",
+                    }
+                )
             else:
                 print(f"✗ 不正JSON処理異常: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Invalid JSON Handling",
-                    "status": "FAIL",
-                    "message": f"Should have returned error for invalid JSON, got HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Invalid JSON Handling",
+                        "status": "FAIL",
+                        "message": f"Should have returned error for invalid JSON, got HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ 不正JSON処理エラー: {e}")
-            self.test_results.append({
-                "test": "Invalid JSON Handling",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Invalid JSON Handling", "status": "FAIL", "message": str(e)}
+            )
+
     def save_results(self):
         """テスト結果を保存"""
         results = {
@@ -220,46 +231,49 @@ class StyleManagerAPITester:
             "summary": {
                 "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                 "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
-                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"])
+                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"]),
             },
-            "results": self.test_results
+            "results": self.test_results,
         }
-        
+
         with open("api_test_results.json", "w", encoding="utf-8") as f:
             json.dump(results, f, ensure_ascii=False, indent=2)
-    
+
     def run_all_tests(self):
         """全てのテストを実行"""
         print("🚀 スタイル管理API機能テスト開始")
         print("=" * 50)
-        
+
         self.test_get_styles()
         self.test_update_styles()
         self.test_create_patch()
         self.test_pages_api()
         self.test_invalid_requests()
-        
+
         print("\n📊 テスト結果")
         print("=" * 50)
-        
+
         passed = len([r for r in self.test_results if r["status"] == "PASS"])
         failed = len([r for r in self.test_results if r["status"] == "FAIL"])
         skipped = len([r for r in self.test_results if r["status"] == "SKIP"])
-        
+
         for result in self.test_results:
-            status_icon = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            status_icon = (
+                "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            )
             print(f"{status_icon} {result['test']}: {result['status']}")
             print(f"   {result['message']}")
-        
+
         print(f"\n📈 サマリー")
         print(f"✅ 成功: {passed}")
         print(f"❌ 失敗: {failed}")
         print(f"⏭️ スキップ: {skipped}")
         print(f"📊 合計: {len(self.test_results)}")
-        
+
         self.save_results()
         print(f"\n💾 詳細結果を api_test_results.json に保存しました")
 
+
 if __name__ == "__main__":
     tester = StyleManagerAPITester()
-    tester.run_all_tests()
\ No newline at end of file
+    tester.run_all_tests()
diff --git a/test_auto_retrain.py b/test_auto_retrain.py
index 63ad0d2..50e9db4 100644
--- a/test_auto_retrain.py
+++ b/test_auto_retrain.py
@@ -21,38 +21,33 @@ class TestAutoRetrainScheduler(unittest.TestCase):
     def setUp(self):
         """テストセットアップ"""
         self.scheduler = AutoRetrainScheduler()
-        
+
         # テスト用の一時ディレクトリ
         self.temp_dir = tempfile.mkdtemp()
         self.config_path = Path(self.temp_dir) / "monitoring.json"
-        
+
         # テスト用設定ファイル作成
-        test_config = {
-            "ai_prediction": {
-                "retrain_interval_hours": 1,
-                "min_training_samples": 10
-            }
-        }
-        with open(self.config_path, 'w', encoding='utf-8') as f:
+        test_config = {"ai_prediction": {"retrain_interval_hours": 1, "min_training_samples": 10}}
+        with open(self.config_path, "w", encoding="utf-8") as f:
             json.dump(test_config, f)
 
     def tearDown(self):
         """テストクリーンアップ"""
         import shutil
+
         shutil.rmtree(self.temp_dir, ignore_errors=True)
 
     def test_load_config(self):
         """設定読み込みテスト"""
         # 正常な設定ファイル
-        with patch('src.auto_retrain_scheduler.Path') as mock_path:
+        with patch("src.auto_retrain_scheduler.Path") as mock_path:
             mock_path.return_value.exists.return_value = True
-            mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps({
-                "ai_prediction": {
-                    "retrain_interval_hours": 2,
-                    "min_training_samples": 20
-                }
-            })
-            
+            mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = (
+                json.dumps(
+                    {"ai_prediction": {"retrain_interval_hours": 2, "min_training_samples": 20}}
+                )
+            )
+
             config = self.scheduler.load_config()
             self.assertEqual(config["retrain_interval_hours"], 6)
             self.assertEqual(config["min_training_samples"], 100)
@@ -60,44 +55,46 @@ class TestAutoRetrainScheduler(unittest.TestCase):
     def test_get_status(self):
         """状態取得テスト"""
         status = self.scheduler.get_status()
-        
+
         self.assertIn("is_running", status)
         self.assertIn("config", status)
         self.assertIn("next_run_estimate", status)
         self.assertIsInstance(status["is_running"], bool)
 
-    @patch('src.auto_retrain_scheduler.QualityPredictor')
-    @patch('src.auto_retrain_scheduler.ResourceDemandPredictor')
+    @patch("src.auto_retrain_scheduler.QualityPredictor")
+    @patch("src.auto_retrain_scheduler.ResourceDemandPredictor")
     def test_retrain_models(self, mock_resource_predictor, mock_quality_predictor):
         """モデル再訓練テスト"""
         # モックの設定
         mock_quality_instance = MagicMock()
         mock_quality_instance.train_model.return_value = {"accuracy": 0.85}
         mock_quality_predictor.return_value = mock_quality_instance
-        
+
         mock_resource_instance = MagicMock()
         mock_resource_instance.train_model.return_value = {"mse": 0.15}
         mock_resource_predictor.return_value = mock_resource_instance
-        
+
         # 再訓練実行（同期的にテスト）
         import asyncio
+
         results = asyncio.run(self.scheduler.retrain_models())
-        
+
         # 結果検証
         self.assertIn("quality_model", results)
         self.assertIn("resource_model", results)
         self.assertEqual(results["quality_model"]["success"], True)
         self.assertEqual(results["resource_model"]["success"], True)
 
-    @patch('src.auto_retrain_scheduler.QualityPredictor')
+    @patch("src.auto_retrain_scheduler.QualityPredictor")
     def test_retrain_models_with_error(self, mock_quality_predictor):
         """エラー時の再訓練テスト"""
         # エラーを発生させるモック
         mock_quality_predictor.side_effect = Exception("Training failed")
-        
+
         import asyncio
+
         results = asyncio.run(self.scheduler.retrain_models())
-        
+
         # エラー結果検証
         self.assertIn("quality_model", results)
         self.assertIn("errors", results)
@@ -107,112 +104,112 @@ class TestAutoRetrainScheduler(unittest.TestCase):
         """再訓練ログ保存テスト"""
         test_results = {
             "quality_model": {"status": "success", "accuracy": 0.85},
-            "resource_model": {"status": "success", "mse": 0.15}
+            "resource_model": {"status": "success", "mse": 0.15},
         }
-        
-        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
-            with patch('src.auto_retrain_scheduler.Path') as mock_path:
+
+        with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
+            with patch("src.auto_retrain_scheduler.Path") as mock_path:
                 mock_path.return_value.parent.mkdir = MagicMock()
-                
+
                 self.scheduler.save_retrain_log(test_results)
-                
+
                 # ファイル書き込み確認
                 mock_file.assert_called_once()
                 handle = mock_file.return_value.__enter__.return_value
-                written_content = ''.join(call.args[0] for call in handle.write.call_args_list)
+                written_content = "".join(call.args[0] for call in handle.write.call_args_list)
                 self.assertIn("quality_model", written_content)
                 self.assertIn("resource_model", written_content)
 
     def test_start_stop_scheduler(self):
         """スケジューラー開始・停止テスト"""
         import asyncio
-        
+
         async def run_test():
             # 短時間でテストを終了するため
             self.scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒
-            
+
             # 開始
             start_task = asyncio.create_task(self.scheduler.start())
-            
+
             # 少し待ってから停止
             await asyncio.sleep(0.1)
             await self.scheduler.stop()
-            
+
             # タスクの完了を待つ
             try:
                 await asyncio.wait_for(start_task, timeout=1.0)
             except asyncio.TimeoutError:
                 start_task.cancel()
-            
+
             # 停止状態確認
             self.assertFalse(self.scheduler.is_running)
-        
+
         asyncio.run(run_test())
 
 
 class TestAutoRetrainIntegration(unittest.TestCase):
     """自動再訓練統合テスト"""
-    
+
     def test_full_integration(self):
         """完全統合テスト"""
         import asyncio
-        
+
         async def run_integration_test():
             scheduler = AutoRetrainScheduler()
-            
+
             # 状態確認
             status = scheduler.get_status()
             assert "is_running" in status
             assert status["is_running"] is False
-            
+
             # 短時間実行テスト
             scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒
-            
+
             # 開始・停止テスト
             start_task = asyncio.create_task(scheduler.start())
             await asyncio.sleep(0.1)
             await scheduler.stop()
-            
+
             try:
                 await asyncio.wait_for(start_task, timeout=1.0)
             except asyncio.TimeoutError:
                 start_task.cancel()
-        
+
         asyncio.run(run_integration_test())
 
 
 def test_scheduler_integration():
     """pytest用統合テスト"""
     import asyncio
-    
+
     async def run_test():
         scheduler = AutoRetrainScheduler()
-        
+
         # 状態確認
         status = scheduler.get_status()
         assert "is_running" in status
         assert status["is_running"] is False
-        
+
         # 短時間実行テスト
         scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒
-        
+
         # 開始・停止テスト
         start_task = asyncio.create_task(scheduler.start())
         await asyncio.sleep(0.1)
         await scheduler.stop()
-        
+
         try:
             await asyncio.wait_for(start_task, timeout=1.0)
         except asyncio.TimeoutError:
             start_task.cancel()
-    
+
     asyncio.run(run_test())
 
 
 if __name__ == "__main__":
     # 同期テスト実行
-    unittest.main(argv=[''], exit=False, verbosity=2)
-    
+    unittest.main(argv=[""], exit=False, verbosity=2)
+
     # 非同期テスト実行
     print("\n=== 非同期テスト実行 ===")
-    asyncio.run(test_scheduler_integration())
\ No newline at end of file
+    asyncio.run(test_scheduler_integration())
diff --git a/test_element_selection.py b/test_element_selection.py
index f36ce73..29ee1cd 100644
--- a/test_element_selection.py
+++ b/test_element_selection.py
@@ -4,21 +4,23 @@
 スタイル管理の要素選択機能テスト
 """
 
-import time
 import json
+import time
+from datetime import datetime
+
 from selenium import webdriver
+from selenium.common.exceptions import NoSuchElementException, TimeoutException
 from selenium.webdriver.common.by import By
-from selenium.webdriver.support.ui import WebDriverWait
 from selenium.webdriver.support import expected_conditions as EC
-from selenium.common.exceptions import TimeoutException, NoSuchElementException
-from datetime import datetime
+from selenium.webdriver.support.ui import WebDriverWait
+
 
 class ElementSelectionTester:
     def __init__(self, base_url="http://localhost:5000"):
         self.base_url = base_url
         self.test_results = []
         self.driver = None
-        
+
     def setup(self):
         """Seleniumドライバーのセットアップ"""
         print("🔧 ブラウザドライバーを初期化中...")
@@ -26,7 +28,7 @@ class ElementSelectionTester:
         options.add_argument("--headless")  # ヘッドレスモードで実行
         options.add_argument("--no-sandbox")
         options.add_argument("--disable-dev-shm-usage")
-        
+
         try:
             self.driver = webdriver.Chrome(options=options)
             self.driver.set_window_size(1366, 768)
@@ -34,19 +36,15 @@ class ElementSelectionTester:
             return True
         except Exception as e:
             print(f"✗ ブラウザドライバー初期化失敗: {e}")
-            self.test_results.append({
-                "test": "Browser Setup",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append({"test": "Browser Setup", "status": "FAIL", "message": str(e)})
             return False
-    
+
     def teardown(self):
         """ドライバーのクリーンアップ"""
         if self.driver:
             self.driver.quit()
             print("✓ ブラウザドライバーを終了しました")
-    
+
     def navigate_to_style_manager(self):
         """スタイル管理ページに移動"""
         print("\n=== スタイル管理ページへの移動 ===")
@@ -56,21 +54,21 @@ class ElementSelectionTester:
                 EC.presence_of_element_located((By.ID, "styleManagerApp"))
             )
             print("✓ スタイル管理ページに移動成功")
-            self.test_results.append({
-                "test": "Navigate to Style Manager",
-                "status": "PASS",
-                "message": "Successfully navigated to style manager page"
-            })
+            self.test_results.append(
+                {
+                    "test": "Navigate to Style Manager",
+                    "status": "PASS",
+                    "message": "Successfully navigated to style manager page",
+                }
+            )
             return True
         except Exception as e:
             print(f"✗ スタイル管理ページへの移動失敗: {e}")
-            self.test_results.append({
-                "test": "Navigate to Style Manager",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append(
+                {"test": "Navigate to Style Manager", "status": "FAIL", "message": str(e)}
+            )
             return False
-    
+
     def test_select_mode_activation(self):
         """選択モードの有効化テスト"""
         print("\n=== 選択モード有効化テスト ===")
@@ -80,37 +78,39 @@ class ElementSelectionTester:
                 EC.element_to_be_clickable((By.ID, "selectModeBtn"))
             )
             select_btn.click()
-            
+
             # 選択モードが有効になったか確認
             time.sleep(1)  # UIの更新を待つ
             select_btn_class = select_btn.get_attribute("class")
-            
+
             if "active" in select_btn_class:
                 print("✓ 選択モードが正常に有効化されました")
-                self.test_results.append({
-                    "test": "Select Mode Activation",
-                    "status": "PASS",
-                    "message": "Select mode successfully activated"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Select Mode Activation",
+                        "status": "PASS",
+                        "message": "Select mode successfully activated",
+                    }
+                )
                 return True
             else:
                 print("✗ 選択モードの有効化に失敗しました")
-                self.test_results.append({
-                    "test": "Select Mode Activation",
-                    "status": "FAIL",
-                    "message": "Select mode button did not become active"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Select Mode Activation",
+                        "status": "FAIL",
+                        "message": "Select mode button did not become active",
+                    }
+                )
                 return False
-                
+
         except Exception as e:
             print(f"✗ 選択モードテストエラー: {e}")
-            self.test_results.append({
-                "test": "Select Mode Activation",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append(
+                {"test": "Select Mode Activation", "status": "FAIL", "message": str(e)}
+            )
             return False
-    
+
     def test_preview_frame_loading(self):
         """プレビューフレームの読み込みテスト"""
         print("\n=== プレビューフレーム読み込みテスト ===")
@@ -119,41 +119,41 @@ class ElementSelectionTester:
             preview_frame = WebDriverWait(self.driver, 5).until(
                 EC.presence_of_element_located((By.ID, "previewFrame"))
             )
-            
+
             # フレームに切り替え
             self.driver.switch_to.frame(preview_frame)
-            
+
             # フレーム内のコンテンツが読み込まれているか確認
             body = WebDriverWait(self.driver, 5).until(
                 EC.presence_of_element_located((By.TAG_NAME, "body"))
             )
-            
+
             # メインフレームに戻る
             self.driver.switch_to.default_content()
-            
+
             print("✓ プレビューフレームが正常に読み込まれました")
-            self.test_results.append({
-                "test": "Preview Frame Loading",
-                "status": "PASS",
-                "message": "Preview frame successfully loaded with content"
-            })
+            self.test_results.append(
+                {
+                    "test": "Preview Frame Loading",
+                    "status": "PASS",
+                    "message": "Preview frame successfully loaded with content",
+                }
+            )
             return True
-            
+
         except Exception as e:
             # エラーが発生した場合、メインフレームに戻る
             try:
                 self.driver.switch_to.default_content()
             except:
                 pass
-                
+
             print(f"✗ プレビューフレーム読み込みエラー: {e}")
-            self.test_results.append({
-                "test": "Preview Frame Loading",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append(
+                {"test": "Preview Frame Loading", "status": "FAIL", "message": str(e)}
+            )
             return False
-    
+
     def test_element_selection(self):
         """要素選択機能のテスト"""
         print("\n=== 要素選択機能テスト ===")
@@ -163,75 +163,79 @@ class ElementSelectionTester:
             if "active" not in select_btn.get_attribute("class"):
                 select_btn.click()
                 time.sleep(1)
-            
+
             # プレビューフレームに切り替え
             preview_frame = self.driver.find_element(By.ID, "previewFrame")
             self.driver.switch_to.frame(preview_frame)
-            
+
             # フレーム内の要素をクリック (例: 最初の見出し要素)
             try:
                 heading = WebDriverWait(self.driver, 5).until(
                     EC.element_to_be_clickable((By.CSS_SELECTOR, "h1, h2, h3, h4, h5, h6"))
                 )
                 heading.click()
-                
+
                 # メインフレームに戻る
                 self.driver.switch_to.default_content()
-                
+
                 # 選択情報パネルが表示されているか確認
                 selection_panel = WebDriverWait(self.driver, 5).until(
                     EC.visibility_of_element_located((By.ID, "selectionInfoPanel"))
                 )
-                
+
                 panel_text = selection_panel.text
                 if panel_text and len(panel_text) > 0:
                     print(f"✓ 要素が正常に選択され、情報パネルが表示されました")
                     print(f"  選択情報: {panel_text[:100]}...")
-                    self.test_results.append({
-                        "test": "Element Selection",
-                        "status": "PASS",
-                        "message": "Element successfully selected and info panel displayed"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Element Selection",
+                            "status": "PASS",
+                            "message": "Element successfully selected and info panel displayed",
+                        }
+                    )
                     return True
                 else:
                     print("✗ 要素は選択されましたが、情報パネルが正しく表示されていません")
-                    self.test_results.append({
-                        "test": "Element Selection",
-                        "status": "FAIL",
-                        "message": "Info panel not properly populated after selection"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Element Selection",
+                            "status": "FAIL",
+                            "message": "Info panel not properly populated after selection",
+                        }
+                    )
                     return False
-                    
+
             except Exception as e:
                 # エラーが発生した場合、メインフレームに戻る
                 try:
                     self.driver.switch_to.default_content()
                 except:
                     pass
-                    
+
                 print(f"✗ 要素選択エラー: {e}")
-                self.test_results.append({
-                    "test": "Element Selection",
-                    "status": "FAIL",
-                    "message": f"Error during element selection: {str(e)}"
-                })
+                self.test_results.append(
+                    {
+                        "test": "Element Selection",
+                        "status": "FAIL",
+                        "message": f"Error during element selection: {str(e)}",
+                    }
+                )
                 return False
-                
+
         except Exception as e:
             # エラーが発生した場合、メインフレームに戻る
             try:
                 self.driver.switch_to.default_content()
             except:
                 pass
-                
+
             print(f"✗ 要素選択テストエラー: {e}")
-            self.test_results.append({
-                "test": "Element Selection",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append(
+                {"test": "Element Selection", "status": "FAIL", "message": str(e)}
+            )
             return False
-    
+
     def test_selection_mode_switching(self):
         """選択モードの切り替えテスト"""
         print("\n=== 選択モード切り替えテスト ===")
@@ -242,52 +246,54 @@ class ElementSelectionTester:
             )
             color_btn.click()
             time.sleep(1)
-            
+
             # 色モードが有効になったか確認
             if "active" in color_btn.get_attribute("class"):
                 print("✓ 色モードに正常に切り替わりました")
-                
+
                 # テキストモードに切り替え
                 text_btn = self.driver.find_element(By.ID, "textModeBtn")
                 text_btn.click()
                 time.sleep(1)
-                
+
                 # テキストモードが有効になったか確認
                 if "active" in text_btn.get_attribute("class"):
                     print("✓ テキストモードに正常に切り替わりました")
-                    
+
                     # 移動モードに切り替え
                     move_btn = self.driver.find_element(By.ID, "moveModeBtn")
                     move_btn.click()
                     time.sleep(1)
-                    
+
                     # 移動モードが有効になったか確認
                     if "active" in move_btn.get_attribute("class"):
                         print("✓ 移動モードに正常に切り替わりました")
-                        self.test_results.append({
-                            "test": "Selection Mode Switching",
-                            "status": "PASS",
-                            "message": "Successfully switched between all selection modes"
-                        })
+                        self.test_results.append(
+                            {
+                                "test": "Selection Mode Switching",
+                                "status": "PASS",
+                                "message": "Successfully switched between all selection modes",
+                            }
+                        )
                         return True
-            
+
             print("✗ 選択モードの切り替えに一部失敗しました")
-            self.test_results.append({
-                "test": "Selection Mode Switching",
-                "status": "FAIL",
-                "message": "Failed to switch between some selection modes"
-            })
+            self.test_results.append(
+                {
+                    "test": "Selection Mode Switching",
+                    "status": "FAIL",
+                    "message": "Failed to switch between some selection modes",
+                }
+            )
             return False
-                
+
         except Exception as e:
             print(f"✗ 選択モード切り替えテストエラー: {e}")
-            self.test_results.append({
-                "test": "Selection Mode Switching",
-                "status": "FAIL",
-                "message": str(e)
-            })
+            self.test_results.append(
+                {"test": "Selection Mode Switching", "status": "FAIL", "message": str(e)}
+            )
             return False
-    
+
     def save_results(self):
         """テスト結果を保存"""
         results = {
@@ -295,23 +301,23 @@ class ElementSelectionTester:
             "summary": {
                 "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                 "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
-                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"])
+                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"]),
             },
-            "results": self.test_results
+            "results": self.test_results,
         }
-        
+
         with open("element_selection_test_results.json", "w", encoding="utf-8") as f:
             json.dump(results, f, ensure_ascii=False, indent=2)
-    
+
     def run_all_tests(self):
         """全てのテストを実行"""
         print("🚀 スタイル管理要素選択機能テスト開始")
         print("=" * 50)
-        
+
         if not self.setup():
             print("✗ セットアップに失敗したため、テストを中止します")
             return
-        
+
         try:
             if self.navigate_to_style_manager():
                 self.test_select_mode_activation()
@@ -320,28 +326,31 @@ class ElementSelectionTester:
                 self.test_selection_mode_switching()
         finally:
             self.teardown()
-        
+
         print("\n📊 テスト結果")
         print("=" * 50)
-        
+
         passed = len([r for r in self.test_results if r["status"] == "PASS"])
         failed = len([r for r in self.test_results if r["status"] == "FAIL"])
         skipped = len([r for r in self.test_results if r["status"] == "SKIP"])
-        
+
         for result in self.test_results:
-            status_icon = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            status_icon = (
+                "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            )
             print(f"{status_icon} {result['test']}: {result['status']}")
             print(f"   {result['message']}")
-        
+
         print(f"\n📈 サマリー")
         print(f"✅ 成功: {passed}")
         print(f"❌ 失敗: {failed}")
         print(f"⏭️ スキップ: {skipped}")
         print(f"📊 合計: {len(self.test_results)}")
-        
+
         self.save_results()
         print(f"\n💾 詳細結果を element_selection_test_results.json に保存しました")
 
+
 if __name__ == "__main__":
     tester = ElementSelectionTester()
-    tester.run_all_tests()
\ No newline at end of file
+    tester.run_all_tests()
diff --git a/test_style_manager.py b/test_style_manager.py
index e00a46c..835aea8 100644
--- a/test_style_manager.py
+++ b/test_style_manager.py
@@ -3,21 +3,23 @@
 スタイル管理機能の実施テストスクリプト
 """
 
-import requests
-import time
 import json
+import time
+
+import requests
 from selenium import webdriver
+from selenium.webdriver.chrome.options import Options
 from selenium.webdriver.common.by import By
-from selenium.webdriver.support.ui import WebDriverWait
 from selenium.webdriver.support import expected_conditions as EC
-from selenium.webdriver.chrome.options import Options
+from selenium.webdriver.support.ui import WebDriverWait
+
 
 class StyleManagerTester:
     def __init__(self, base_url="http://localhost:5000"):
         self.base_url = base_url
         self.driver = None
         self.test_results = []
-        
+
     def setup_driver(self):
         """WebDriverのセットアップ"""
         try:
@@ -25,7 +27,7 @@ class StyleManagerTester:
             chrome_options.add_argument("--headless")  # ヘッドレスモード
             chrome_options.add_argument("--no-sandbox")
             chrome_options.add_argument("--disable-dev-shm-usage")
-            
+
             try:
                 self.driver = webdriver.Chrome(options=chrome_options)
                 return True
@@ -37,73 +39,96 @@ class StyleManagerTester:
             print(f"WebDriver setup failed: {e}")
             print("WebDriverテストはスキップします")
             return False
-    
+
     def test_dashboard_access(self):
         """ダッシュボードアクセステスト"""
         test_name = "Dashboard Access Test"
         try:
             response = requests.get(self.base_url, timeout=10)
             if response.status_code == 200:
-                self.test_results.append({"test": test_name, "status": "PASS", "message": "Dashboard accessible"})
+                self.test_results.append(
+                    {"test": test_name, "status": "PASS", "message": "Dashboard accessible"}
+                )
                 return True
             else:
-                self.test_results.append({"test": test_name, "status": "FAIL", "message": f"Status code: {response.status_code}"})
+                self.test_results.append(
+                    {
+                        "test": test_name,
+                        "status": "FAIL",
+                        "message": f"Status code: {response.status_code}",
+                    }
+                )
                 return False
         except Exception as e:
             self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})
             return False
-    
+
     def test_style_manager_page(self):
         """スタイル管理ページアクセステスト"""
         test_name = "Style Manager Page Test"
         try:
             response = requests.get(f"{self.base_url}/style-manager", timeout=10)
             if response.status_code == 200:
-                self.test_results.append({"test": test_name, "status": "PASS", "message": "Style manager page accessible"})
+                self.test_results.append(
+                    {
+                        "test": test_name,
+                        "status": "PASS",
+                        "message": "Style manager page accessible",
+                    }
+                )
                 return True
             else:
-                self.test_results.append({"test": test_name, "status": "FAIL", "message": f"Status code: {response.status_code}"})
+                self.test_results.append(
+                    {
+                        "test": test_name,
+                        "status": "FAIL",
+                        "message": f"Status code: {response.status_code}",
+                    }
+                )
                 return False
         except Exception as e:
             self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})
             return False
-    
+
     def test_api_endpoints(self):
         """API エンドポイントテスト"""
-        endpoints = [
-            "/api/styles",
-            "/api/pages",
-            "/api/prediction",
-            "/api/trends"
-        ]
-        
+        endpoints = ["/api/styles", "/api/pages", "/api/prediction", "/api/trends"]
+
         for endpoint in endpoints:
             test_name = f"API Endpoint Test: {endpoint}"
             try:
                 response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                 if response.status_code == 200:
-                    self.test_results.append({"test": test_name, "status": "PASS", "message": "API endpoint accessible"})
+                    self.test_results.append(
+                        {"test": test_name, "status": "PASS", "message": "API endpoint accessible"}
+                    )
                 else:
-                    self.test_results.append({"test": test_name, "status": "FAIL", "message": f"Status code: {response.status_code}"})
+                    self.test_results.append(
+                        {
+                            "test": test_name,
+                            "status": "FAIL",
+                            "message": f"Status code: {response.status_code}",
+                        }
+                    )
             except Exception as e:
                 self.test_results.append({"test": test_name, "status": "FAIL", "message": str(e)})
-    
+
     def test_ui_elements(self):
         """UI要素のテスト"""
         print("\n=== UI要素テスト ===")
-        
+
         if not self.driver:
             print("WebDriverが利用できないため、UI要素テストをスキップします")
             return
-            
+
         try:
             self.driver.get(f"{self.base_url}/style-manager")
             time.sleep(2)
-            
+
             # ページタイトルの確認
             title = self.driver.title
             print(f"ページタイトル: {title}")
-            
+
             # 主要な要素の存在確認
             elements_to_check = [
                 ("pageSelect", "ページセレクタ"),
@@ -112,85 +137,87 @@ class StyleManagerTester:
                 ("textModeBtn", "テキストモードボタン"),
                 ("moveModeBtn", "移動モードボタン"),
                 ("previewFrame", "プレビューフレーム"),
-                ("selectionInfoPanel", "選択情報パネル")
+                ("selectionInfoPanel", "選択情報パネル"),
             ]
-            
+
             for element_id, element_name in elements_to_check:
                 try:
                     element = self.driver.find_element(By.ID, element_id)
                     print(f"✓ {element_name} が見つかりました")
                 except:
                     print(f"✗ {element_name} が見つかりません")
-                    
+
         except Exception as e:
             print(f"UI要素テストでエラー: {e}")
-    
+
     def run_all_tests(self):
         """全テストの実行"""
         print("🚀 スタイル管理機能実施テスト開始")
         print("=" * 50)
-        
+
         # 基本テスト
         self.test_dashboard_access()
         self.test_style_manager_page()
         self.test_api_endpoints()
-        
+
         # WebDriverセットアップ試行
         if self.setup_driver():
             self.test_ui_elements()
             self.cleanup()
-    
+
     def cleanup(self):
         """リソースのクリーンアップ"""
-        if hasattr(self, 'driver') and self.driver:
+        if hasattr(self, "driver") and self.driver:
             self.driver.quit()
-        
+
         # 結果出力
         self.print_results()
         return self.test_results
-    
+
     def print_results(self):
         """テスト結果の出力"""
         print("\n📊 テスト結果")
         print("=" * 50)
-        
+
         passed = 0
         failed = 0
         skipped = 0
-        
+
         for result in self.test_results:
-            status_icon = {
-                "PASS": "✅",
-                "FAIL": "❌", 
-                "SKIP": "⏭️"
-            }.get(result["status"], "❓")
-            
+            status_icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}.get(result["status"], "❓")
+
             print(f"{status_icon} {result['test']}: {result['status']}")
             print(f"   {result['message']}")
-            
+
             if result["status"] == "PASS":
                 passed += 1
             elif result["status"] == "FAIL":
                 failed += 1
             else:
                 skipped += 1
-        
+
         print("\n📈 サマリー")
         print(f"✅ 成功: {passed}")
         print(f"❌ 失敗: {failed}")
         print(f"⏭️ スキップ: {skipped}")
         print(f"📊 合計: {len(self.test_results)}")
-        
+
         # 結果をJSONファイルに保存
         with open("test_results.json", "w", encoding="utf-8") as f:
-            json.dump({
-                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
-                "summary": {"passed": passed, "failed": failed, "skipped": skipped},
-                "results": self.test_results
-            }, f, ensure_ascii=False, indent=2)
-        
+            json.dump(
+                {
+                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
+                    "summary": {"passed": passed, "failed": failed, "skipped": skipped},
+                    "results": self.test_results,
+                },
+                f,
+                ensure_ascii=False,
+                indent=2,
+            )
+
         print(f"\n💾 詳細結果を test_results.json に保存しました")
 
+
 if __name__ == "__main__":
     tester = StyleManagerTester()
-    tester.run_all_tests()
\ No newline at end of file
+    tester.run_all_tests()
diff --git a/test_visual_editing.py b/test_visual_editing.py
index 217286b..8328624 100644
--- a/test_visual_editing.py
+++ b/test_visual_editing.py
@@ -4,26 +4,28 @@
 スタイル管理のビジュアル編集機能テスト
 """
 
-import requests
 import json
 import time
 from datetime import datetime
 
+import requests
+
+
 class VisualEditingTester:
     def __init__(self, base_url="http://localhost:5000"):
         self.base_url = base_url
         self.test_results = []
-        
+
     def test_style_manager_page_load(self):
         """スタイル管理ページの読み込みテスト"""
         print("\n=== スタイル管理ページ読み込みテスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/style-manager")
-            
+
             if response.status_code == 200:
                 content = response.text
-                
+
                 # 必要なコンポーネントが含まれているか確認
                 required_elements = [
                     "styleManagerApp",
@@ -33,55 +35,59 @@ class VisualEditingTester:
                     "textModeBtn",
                     "moveModeBtn",
                     "previewFrame",
-                    "selectionInfoPanel"
+                    "selectionInfoPanel",
                 ]
-                
+
                 missing_elements = []
                 for element in required_elements:
                     if element not in content:
                         missing_elements.append(element)
-                
+
                 if not missing_elements:
                     print(f"✓ スタイル管理ページが正常に読み込まれました")
                     print(f"  必要な要素: {len(required_elements)} 個すべて確認")
-                    self.test_results.append({
-                        "test": "Style Manager Page Load",
-                        "status": "PASS",
-                        "message": f"All {len(required_elements)} required elements found"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Style Manager Page Load",
+                            "status": "PASS",
+                            "message": f"All {len(required_elements)} required elements found",
+                        }
+                    )
                 else:
                     print(f"✗ 一部の要素が見つかりません: {missing_elements}")
-                    self.test_results.append({
-                        "test": "Style Manager Page Load",
-                        "status": "FAIL",
-                        "message": f"Missing elements: {missing_elements}"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Style Manager Page Load",
+                            "status": "FAIL",
+                            "message": f"Missing elements: {missing_elements}",
+                        }
+                    )
             else:
                 print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Style Manager Page Load",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Style Manager Page Load",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ ページ読み込みエラー: {e}")
-            self.test_results.append({
-                "test": "Style Manager Page Load",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Style Manager Page Load", "status": "FAIL", "message": str(e)}
+            )
+
     def test_color_tools_presence(self):
         """カラーツールの存在確認テスト"""
         print("\n=== カラーツール存在確認テスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/style-manager")
-            
+
             if response.status_code == 200:
                 content = response.text
-                
+
                 # カラーツール関連の要素を確認
                 color_elements = [
                     "colorPicker",
@@ -89,48 +95,50 @@ class VisualEditingTester:
                     "colorHistory",
                     "colorMode",
                     "backgroundColorPicker",
-                    "textColorPicker"
+                    "textColorPicker",
                 ]
-                
+
                 found_elements = []
                 for element in color_elements:
                     if element in content:
                         found_elements.append(element)
-                
+
                 print(f"✓ カラーツール要素: {len(found_elements)}/{len(color_elements)} 個確認")
                 print(f"  確認された要素: {found_elements}")
-                
-                self.test_results.append({
-                    "test": "Color Tools Presence",
-                    "status": "PASS",
-                    "message": f"Found {len(found_elements)} color tool elements"
-                })
+
+                self.test_results.append(
+                    {
+                        "test": "Color Tools Presence",
+                        "status": "PASS",
+                        "message": f"Found {len(found_elements)} color tool elements",
+                    }
+                )
             else:
                 print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Color Tools Presence",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Color Tools Presence",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ カラーツールテストエラー: {e}")
-            self.test_results.append({
-                "test": "Color Tools Presence",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Color Tools Presence", "status": "FAIL", "message": str(e)}
+            )
+
     def test_font_tools_presence(self):
         """フォントツールの存在確認テスト"""
         print("\n=== フォントツール存在確認テスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/style-manager")
-            
+
             if response.status_code == 200:
                 content = response.text
-                
+
                 # フォントツール関連の要素を確認
                 font_elements = [
                     "fontFamily",
@@ -140,49 +148,51 @@ class VisualEditingTester:
                     "googleFonts",
                     "textAlign",
                     "lineHeight",
-                    "letterSpacing"
+                    "letterSpacing",
                 ]
-                
+
                 found_elements = []
                 for element in content:
                     if any(font_elem in content for font_elem in font_elements):
                         found_elements = [elem for elem in font_elements if elem in content]
                         break
-                
+
                 print(f"✓ フォントツール要素: {len(found_elements)}/{len(font_elements)} 個確認")
                 print(f"  確認された要素: {found_elements}")
-                
-                self.test_results.append({
-                    "test": "Font Tools Presence",
-                    "status": "PASS",
-                    "message": f"Found {len(found_elements)} font tool elements"
-                })
+
+                self.test_results.append(
+                    {
+                        "test": "Font Tools Presence",
+                        "status": "PASS",
+                        "message": f"Found {len(found_elements)} font tool elements",
+                    }
+                )
             else:
                 print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Font Tools Presence",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Font Tools Presence",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ フォントツールテストエラー: {e}")
-            self.test_results.append({
-                "test": "Font Tools Presence",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Font Tools Presence", "status": "FAIL", "message": str(e)}
+            )
+
     def test_layout_tools_presence(self):
         """レイアウトツールの存在確認テスト"""
         print("\n=== レイアウトツール存在確認テスト ===")
-        
+
         try:
             response = requests.get(f"{self.base_url}/style-manager")
-            
+
             if response.status_code == 200:
                 content = response.text
-                
+
                 # レイアウトツール関連の要素を確認
                 layout_elements = [
                     "margin",
@@ -192,169 +202,178 @@ class VisualEditingTester:
                     "position",
                     "display",
                     "flexbox",
-                    "grid"
+                    "grid",
                 ]
-                
+
                 found_elements = []
                 for element in layout_elements:
                     if element in content.lower():
                         found_elements.append(element)
-                
-                print(f"✓ レイアウトツール要素: {len(found_elements)}/{len(layout_elements)} 個確認")
+
+                print(
+                    f"✓ レイアウトツール要素: {len(found_elements)}/{len(layout_elements)} 個確認"
+                )
                 print(f"  確認された要素: {found_elements}")
-                
-                self.test_results.append({
-                    "test": "Layout Tools Presence",
-                    "status": "PASS",
-                    "message": f"Found {len(found_elements)} layout tool elements"
-                })
+
+                self.test_results.append(
+                    {
+                        "test": "Layout Tools Presence",
+                        "status": "PASS",
+                        "message": f"Found {len(found_elements)} layout tool elements",
+                    }
+                )
             else:
                 print(f"✗ ページ読み込み失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Layout Tools Presence",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Layout Tools Presence",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ レイアウトツールテストエラー: {e}")
-            self.test_results.append({
-                "test": "Layout Tools Presence",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Layout Tools Presence", "status": "FAIL", "message": str(e)}
+            )
+
     def test_preview_functionality(self):
         """プレビュー機能のテスト"""
         print("\n=== プレビュー機能テスト ===")
-        
+
         try:
             # ダッシュボードページのプレビューを取得
             response = requests.get(f"{self.base_url}/dashboard")
-            
+
             if response.status_code == 200:
                 content = response.text
-                
+
                 # プレビューに必要な要素が含まれているか確認
-                preview_elements = [
-                    "<html",
-                    "<head",
-                    "<body",
-                    "stylesheet",
-                    "script"
-                ]
-                
+                preview_elements = ["<html", "<head", "<body", "stylesheet", "script"]
+
                 found_elements = []
                 for element in preview_elements:
                     if element in content.lower():
                         found_elements.append(element)
-                
+
                 if len(found_elements) >= 3:  # 最低限のHTML構造があるか
                     print(f"✓ プレビュー機能が正常に動作しています")
                     print(f"  HTML要素: {len(found_elements)}/{len(preview_elements)} 個確認")
-                    self.test_results.append({
-                        "test": "Preview Functionality",
-                        "status": "PASS",
-                        "message": f"Preview content properly structured with {len(found_elements)} elements"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Preview Functionality",
+                            "status": "PASS",
+                            "message": f"Preview content properly structured with {len(found_elements)} elements",
+                        }
+                    )
                 else:
                     print(f"✗ プレビューコンテンツが不完全です")
-                    self.test_results.append({
-                        "test": "Preview Functionality",
-                        "status": "FAIL",
-                        "message": f"Incomplete preview content, only {len(found_elements)} elements found"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Preview Functionality",
+                            "status": "FAIL",
+                            "message": f"Incomplete preview content, only {len(found_elements)} elements found",
+                        }
+                    )
             else:
                 print(f"✗ プレビュー取得失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Preview Functionality",
-                    "status": "FAIL",
-                    "message": f"HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Preview Functionality",
+                        "status": "FAIL",
+                        "message": f"HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ プレビュー機能テストエラー: {e}")
-            self.test_results.append({
-                "test": "Preview Functionality",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Preview Functionality", "status": "FAIL", "message": str(e)}
+            )
+
     def test_style_persistence(self):
         """スタイル永続化テスト"""
         print("\n=== スタイル永続化テスト ===")
-        
+
         try:
             # 現在のスタイルを取得
             response = requests.get(f"{self.base_url}/api/styles")
-            
+
             if response.status_code == 200:
                 original_styles = response.json()
-                
+
                 # テストスタイルを更新
-                test_style = {
-                    "key": "test_persistence",
-                    "value": "#123456"
-                }
-                
+                test_style = {"key": "test_persistence", "value": "#123456"}
+
                 update_response = requests.post(
                     f"{self.base_url}/api/styles",
                     json=test_style,
-                    headers={'Content-Type': 'application/json'}
+                    headers={"Content-Type": "application/json"},
                 )
-                
+
                 if update_response.status_code == 200:
                     # 更新後のスタイルを再取得
                     verify_response = requests.get(f"{self.base_url}/api/styles")
-                    
+
                     if verify_response.status_code == 200:
                         updated_styles = verify_response.json()
-                        
+
                         if test_style["key"] in updated_styles:
                             print(f"✓ スタイルが正常に永続化されました")
-                            print(f"  テストキー: {test_style['key']} = {updated_styles[test_style['key']]}")
-                            self.test_results.append({
-                                "test": "Style Persistence",
-                                "status": "PASS",
-                                "message": "Style successfully persisted and retrieved"
-                            })
+                            print(
+                                f"  テストキー: {test_style['key']} = {updated_styles[test_style['key']]}"
+                            )
+                            self.test_results.append(
+                                {
+                                    "test": "Style Persistence",
+                                    "status": "PASS",
+                                    "message": "Style successfully persisted and retrieved",
+                                }
+                            )
                         else:
                             print(f"✗ スタイルの永続化に失敗しました")
-                            self.test_results.append({
-                                "test": "Style Persistence",
-                                "status": "FAIL",
-                                "message": "Style not found after update"
-                            })
+                            self.test_results.append(
+                                {
+                                    "test": "Style Persistence",
+                                    "status": "FAIL",
+                                    "message": "Style not found after update",
+                                }
+                            )
                     else:
                         print(f"✗ 更新後のスタイル取得に失敗: HTTP {verify_response.status_code}")
-                        self.test_results.append({
-                            "test": "Style Persistence",
-                            "status": "FAIL",
-                            "message": f"Failed to retrieve updated styles: HTTP {verify_response.status_code}"
-                        })
+                        self.test_results.append(
+                            {
+                                "test": "Style Persistence",
+                                "status": "FAIL",
+                                "message": f"Failed to retrieve updated styles: HTTP {verify_response.status_code}",
+                            }
+                        )
                 else:
                     print(f"✗ スタイル更新に失敗: HTTP {update_response.status_code}")
-                    self.test_results.append({
-                        "test": "Style Persistence",
-                        "status": "FAIL",
-                        "message": f"Failed to update style: HTTP {update_response.status_code}"
-                    })
+                    self.test_results.append(
+                        {
+                            "test": "Style Persistence",
+                            "status": "FAIL",
+                            "message": f"Failed to update style: HTTP {update_response.status_code}",
+                        }
+                    )
             else:
                 print(f"✗ 初期スタイル取得に失敗: HTTP {response.status_code}")
-                self.test_results.append({
-                    "test": "Style Persistence",
-                    "status": "FAIL",
-                    "message": f"Failed to get initial styles: HTTP {response.status_code}"
-                })
-                
+                self.test_results.append(
+                    {
+                        "test": "Style Persistence",
+                        "status": "FAIL",
+                        "message": f"Failed to get initial styles: HTTP {response.status_code}",
+                    }
+                )
+
         except Exception as e:
             print(f"✗ スタイル永続化テストエラー: {e}")
-            self.test_results.append({
-                "test": "Style Persistence",
-                "status": "FAIL",
-                "message": str(e)
-            })
-    
+            self.test_results.append(
+                {"test": "Style Persistence", "status": "FAIL", "message": str(e)}
+            )
+
     def save_results(self):
         """テスト結果を保存"""
         results = {
@@ -362,47 +381,50 @@ class VisualEditingTester:
             "summary": {
                 "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                 "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
-                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"])
+                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"]),
             },
-            "results": self.test_results
+            "results": self.test_results,
         }
-        
+
         with open("visual_editing_test_results.json", "w", encoding="utf-8") as f:
             json.dump(results, f, ensure_ascii=False, indent=2)
-    
+
     def run_all_tests(self):
         """全てのテストを実行"""
         print("🚀 スタイル管理ビジュアル編集機能テスト開始")
         print("=" * 50)
-        
+
         self.test_style_manager_page_load()
         self.test_color_tools_presence()
         self.test_font_tools_presence()
         self.test_layout_tools_presence()
         self.test_preview_functionality()
         self.test_style_persistence()
-        
+
         print("\n📊 テスト結果")
         print("=" * 50)
-        
+
         passed = len([r for r in self.test_results if r["status"] == "PASS"])
         failed = len([r for r in self.test_results if r["status"] == "FAIL"])
         skipped = len([r for r in self.test_results if r["status"] == "SKIP"])
-        
+
         for result in self.test_results:
-            status_icon = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            status_icon = (
+                "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⏭️"
+            )
             print(f"{status_icon} {result['test']}: {result['status']}")
             print(f"   {result['message']}")
-        
+
         print(f"\n📈 サマリー")
         print(f"✅ 成功: {passed}")
         print(f"❌ 失敗: {failed}")
         print(f"⏭️ スキップ: {skipped}")
         print(f"📊 合計: {len(self.test_results)}")
-        
+
         self.save_results()
         print(f"\n💾 詳細結果を visual_editing_test_results.json に保存しました")
 
+
 if __name__ == "__main__":
     tester = VisualEditingTester()
-    tester.run_all_tests()
\ No newline at end of file
+    tester.run_all_tests()
diff --git a/tests/e2e/test_healthz.py b/tests/e2e/test_healthz.py
index 800dc1a..22edbbf 100644
--- a/tests/e2e/test_healthz.py
+++ b/tests/e2e/test_healthz.py
@@ -13,4 +13,4 @@ def test_healthz_returns_ok():
     data = resp.get_json()
     assert isinstance(data, dict)
     assert data.get("status") == "ok"
-    assert "time" in data
\ No newline at end of file
+    assert "time" in data
diff --git a/tests/e2e/test_navigation_status.py b/tests/e2e/test_navigation_status.py
index a0ecd60..c74d16c 100644
--- a/tests/e2e/test_navigation_status.py
+++ b/tests/e2e/test_navigation_status.py
@@ -21,4 +21,4 @@ def test_style_manager_status():
 def test_tasks_status():
     client = app.test_client()
     resp = client.get("/tasks")
-    assert resp.status_code == 200
\ No newline at end of file
+    assert resp.status_code == 200
diff --git a/tests/e2e/test_style_manager.py b/tests/e2e/test_style_manager.py
index 35ad814..fa7e8d6 100644
--- a/tests/e2e/test_style_manager.py
+++ b/tests/e2e/test_style_manager.py
@@ -1,8 +1,8 @@
 import os
+
 import pytest
 from playwright.sync_api import sync_playwright
 
-
 BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
 
 
@@ -12,7 +12,9 @@ def test_style_manager_page_ok():
         browser = p.chromium.launch()
         page = browser.new_page()
         resp = page.goto(f"{BASE_URL}/style-manager", wait_until="domcontentloaded")
-        assert resp is not None and resp.ok, f"/style-manager status {resp.status if resp else 'None'}"
+        assert (
+            resp is not None and resp.ok
+        ), f"/style-manager status {resp.status if resp else 'None'}"
         content = page.content()
         assert "Style Manager" in content or "Styles" in content, "Unexpected page content"
         browser.close()
@@ -31,4 +33,4 @@ def test_api_styles_get_ok():
             # Fallback: read text and perform minimal validation
             data = None
         assert data is None or isinstance(data, dict), "Expected JSON object or valid response"
-        browser.close()
\ No newline at end of file
+        browser.close()
diff --git a/tests/e2e/test_style_manager_flow.py b/tests/e2e/test_style_manager_flow.py
index f53c3ca..5288606 100644
--- a/tests/e2e/test_style_manager_flow.py
+++ b/tests/e2e/test_style_manager_flow.py
@@ -1,8 +1,8 @@
 import os
+
 import pytest
 from playwright.sync_api import sync_playwright
 
-
 BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
 
 
@@ -23,7 +23,9 @@ def test_style_manager_flow_apply_and_save():
 
         # Navigate to Style Manager
         resp = page.goto(f"{BASE_URL}/style-manager", wait_until="domcontentloaded")
-        assert resp is not None and resp.ok, f"/style-manager status {resp.status if resp else 'None'}"
+        assert (
+            resp is not None and resp.ok
+        ), f"/style-manager status {resp.status if resp else 'None'}"
 
         # Update color via JS to ensure input event fires for <input type="color">
         # Try multiple known IDs to tolerate template differences
@@ -55,8 +57,8 @@ def test_style_manager_flow_apply_and_save():
         )
 
         # Verify preview reflects the change, but only if preview DOM exists
-        preview_selectors = ['#nav-preview', '#text-preview', '#table-preview']
-        if page.locator(','.join(preview_selectors)).count() > 0:
+        preview_selectors = ["#nav-preview", "#text-preview", "#table-preview"]
+        if page.locator(",".join(preview_selectors)).count() > 0:
             preview_color = page.evaluate(
                 """
                 () => {
@@ -75,7 +77,11 @@ def test_style_manager_flow_apply_and_save():
                 """,
             )
             # Computed style should be rgb(255, 0, 255) for #ff00ff
-            assert preview_color in ("rgb(255, 0, 255)", "#ff00ff", "rgba(255, 0, 255, 1)"), f"Preview color not updated: {preview_color}"
+            assert preview_color in (
+                "rgb(255, 0, 255)",
+                "#ff00ff",
+                "rgba(255, 0, 255, 1)",
+            ), f"Preview color not updated: {preview_color}"
         else:
             print("[E2E] Preview container not found; skipping visual assertion.")
 
@@ -83,14 +89,16 @@ def test_style_manager_flow_apply_and_save():
         # If the button path fails (template mismatch), fall back to direct POST with chosen_key
         post_status = None
         try:
-            with page.expect_response(lambda r: r.url.endswith('/api/styles') and r.request.method == 'POST', timeout=5000) as post_info:
+            with page.expect_response(
+                lambda r: r.url.endswith("/api/styles") and r.request.method == "POST", timeout=5000
+            ) as post_info:
                 # Prefer semantic anchor; then class in style_manager; then dashboard fallback
                 if page.locator('[data-sem-role="apply-button"]').count() > 0:
                     page.click('[data-sem-role="apply-button"]')
-                elif page.locator('.btn-apply').count() > 0:
-                    page.click('.btn-apply')
+                elif page.locator(".btn-apply").count() > 0:
+                    page.click(".btn-apply")
                 else:
-                    page.click('#applyBtn')
+                    page.click("#applyBtn")
             post_resp = post_info.value
             post_status = post_resp.status
         except Exception:
@@ -108,12 +116,16 @@ def test_style_manager_flow_apply_and_save():
                     }).then(r => r.status).catch(() => null);
                 }
                 """,
-                { "key": chosen_key, "color": test_color },
+                {"key": chosen_key, "color": test_color},
             )
             assert direct_status == 200, f"Direct POST /api/styles failed: {direct_status}"
 
         # Optionally, check status banner text appears
-        status_text = page.text_content('#status-message') if page.locator('#status-message').count() > 0 else None
+        status_text = (
+            page.text_content("#status-message")
+            if page.locator("#status-message").count() > 0
+            else None
+        )
         # Do not hard fail on missing banner; focus on persisted values
 
         # Verify persisted styles via GET /api/styles
@@ -126,8 +138,11 @@ def test_style_manager_flow_apply_and_save():
         assert isinstance(data, dict), "Expected JSON object from /api/styles"
         # Accept persisted value for any of the known keys
         persisted_ok = any(
-            data.get(k) == test_color for k in ["accent_color", "nav_text_color", "button_text_color", "table_text_color"]
+            data.get(k) == test_color
+            for k in ["accent_color", "nav_text_color", "button_text_color", "table_text_color"]
         )
-        assert persisted_ok, f"Persisted color mismatch: accent={data.get('accent_color')} nav={data.get('nav_text_color')}"
+        assert (
+            persisted_ok
+        ), f"Persisted color mismatch: accent={data.get('accent_color')} nav={data.get('nav_text_color')}"
 
-        browser.close()
\ No newline at end of file
+        browser.close()
diff --git a/tests/load/sse_smoke_test.py b/tests/load/sse_smoke_test.py
index e809ec1..feef8b0 100644
--- a/tests/load/sse_smoke_test.py
+++ b/tests/load/sse_smoke_test.py
@@ -9,10 +9,10 @@ SSE スモーク/耐性テスト
 CIでの軽量検証用。長時間・高負荷は別途 k6/locust を推奨。
 """
 
-import time
 import threading
-import requests
+import time
 
+import requests
 
 BASE_URL = "http://127.0.0.1:5000"
 
@@ -77,4 +77,4 @@ def test_sse_concurrency_smoke():
     for t in threads:
         t.join(timeout=12)
 
-    assert frames_ct >= 5, f"Concurrency smoke failed: frames_ct={frames_ct}"
\ No newline at end of file
+    assert frames_ct >= 5, f"Concurrency smoke failed: frames_ct={frames_ct}"
diff --git a/tests/test_file_utils.py b/tests/test_file_utils.py
index aa00ba0..f212b25 100644
--- a/tests/test_file_utils.py
+++ b/tests/test_file_utils.py
@@ -9,53 +9,54 @@ import json
 import os
 import tempfile
 from pathlib import Path
+
 import pytest
 
 from src.tools.file_utils import (
-    FileSecurityError,
     FileIntegrityError,
-    atomic_write_text,
+    FileSecurityError,
     atomic_write_json,
-    safe_read_text,
-    safe_read_json,
-    check_secrets,
+    atomic_write_text,
     check_eol,
-    normalize_eol,
+    check_secrets,
     compute_sha256,
-    write_text_lf,
-    write_json_lf,
-    read_text_safe,
+    normalize_eol,
     read_json_safe,
+    read_text_safe,
+    safe_read_json,
+    safe_read_text,
+    write_json_lf,
+    write_text_lf,
 )
 
 
 class TestSecretDetection:
     """Secret検出テスト"""
-    
+
     def test_detect_aws_key(self):
         """AWS Access Key検出"""
         content = "AWS_ACCESS_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"
         with pytest.raises(FileSecurityError, match="AWS Access Key"):
             check_secrets(content)
-    
+
     def test_detect_generic_secret(self):
         """Generic SECRET検出"""
         content = "SECRET_KEY=" + "abc123" + "def456" + "ghi789"
         with pytest.raises(FileSecurityError, match="Generic SECRET"):
             check_secrets(content)
-    
+
     def test_detect_bearer_token(self):
         """Bearer Token検出"""
         content = "Authorization: Bearer " + "eyJhbGciOiJI" + "UzI1NiIsInR5cCI6IkpXVCJ9"
         with pytest.raises(FileSecurityError, match="Bearer Token"):
             check_secrets(content)
-    
+
     def test_detect_private_key(self):
         """Private Key検出"""
         content = "-----BEGIN " + "RSA PRIVATE KEY" + "-----\nMIIEpAIBAAKCAQEA..."
         with pytest.raises(FileSecurityError, match="Private Key"):
             check_secrets(content)
-    
+
     def test_safe_placeholders(self):
         """Safe placeholder許可"""
         safe_content = """
@@ -67,7 +68,7 @@ class TestSecretDetection:
         """
         # Should not raise
         check_secrets(safe_content)
-    
+
     def test_no_secrets(self):
         """Secret無しコンテンツ"""
         clean_content = """
@@ -82,24 +83,24 @@ class TestSecretDetection:
 
 class TestEOLHandling:
     """EOL処理テスト"""
-    
+
     def test_detect_crlf(self):
         """CRLF検出"""
         content = "line1\r\nline2\r\nline3"
         with pytest.raises(FileIntegrityError, match="CRLF detected"):
             check_eol(content)
-    
+
     def test_allow_lf(self):
         """LF許可"""
         content = "line1\nline2\nline3"
         assert check_eol(content) is True
-    
+
     def test_normalize_crlf_to_lf(self):
         """CRLF → LF正規化"""
         content = "line1\r\nline2\r\nline3"
         normalized = normalize_eol(content)
         assert normalized == "line1\nline2\nline3"
-    
+
     def test_normalize_mixed_eol(self):
         """混在EOL正規化"""
         content = "line1\r\nline2\nline3\rline4"
@@ -109,204 +110,200 @@ class TestEOLHandling:
 
 class TestAtomicWrite:
     """Atomic write テスト"""
-    
+
     def test_atomic_write_text_basic(self):
         """基本的なatomic text write"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content = "Hello, World!\nThis is a test."
-            
+
             result = atomic_write_text(file_path, content)
-            
+
             # ファイルが作成されている
             assert file_path.exists()
-            
+
             # 内容が正しい
-            with open(file_path, 'r', encoding='utf-8') as f:
+            with open(file_path, "r", encoding="utf-8") as f:
                 written_content = f.read()
             assert written_content == content
-            
+
             # SHA256が一致
-            assert result['sha_in'] == result['sha_out']
-            assert result['sha_in'] == compute_sha256(content)
-            assert result['verified'] is True
-    
+            assert result["sha_in"] == result["sha_out"]
+            assert result["sha_in"] == compute_sha256(content)
+            assert result["verified"] is True
+
     def test_atomic_write_with_backup(self):
         """バックアップ付きatomic write"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
-            
+
             # 既存ファイル作成
             original_content = "Original content"
-            with open(file_path, 'w', encoding='utf-8') as f:
+            with open(file_path, "w", encoding="utf-8") as f:
                 f.write(original_content)
-            
+
             # 新しい内容で上書き
             new_content = "New content"
             result = atomic_write_text(file_path, new_content, backup=True)
-            
+
             # 新しい内容が書き込まれている
-            with open(file_path, 'r', encoding='utf-8') as f:
+            with open(file_path, "r", encoding="utf-8") as f:
                 assert f.read() == new_content
-            
+
             # バックアップが作成されている
-            backup_path = Path(result['backup_path'])
+            backup_path = Path(result["backup_path"])
             assert backup_path.exists()
-            with open(backup_path, 'r', encoding='utf-8') as f:
+            with open(backup_path, "r", encoding="utf-8") as f:
                 assert f.read() == original_content
-    
+
     def test_atomic_write_eol_normalization(self):
         """EOL正規化付きatomic write"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content_with_crlf = "line1\r\nline2\r\nline3"
             expected_content = "line1\nline2\nline3"
-            
+
             result = atomic_write_text(file_path, content_with_crlf, normalize_eol_enabled=True)
-            
+
             # LFに正規化されている
-            with open(file_path, 'r', encoding='utf-8') as f:
+            with open(file_path, "r", encoding="utf-8") as f:
                 written_content = f.read()
             assert written_content == expected_content
-            
+
             # SHA256は正規化後の内容
-            assert result['sha_out'] == compute_sha256(expected_content)
-    
+            assert result["sha_out"] == compute_sha256(expected_content)
+
     def test_atomic_write_secret_detection(self):
         """Secret検出付きatomic write"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content_with_secret = "API_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"
-            
+
             with pytest.raises(FileSecurityError):
                 atomic_write_text(file_path, content_with_secret, check_secrets_enabled=True)
-            
+
             # ファイルが作成されていない
             assert not file_path.exists()
-    
+
     def test_atomic_write_json(self):
         """Atomic JSON write"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.json"
-            data = {
-                "name": "test",
-                "value": 123,
-                "nested": {"key": "value"}
-            }
-            
+            data = {"name": "test", "value": 123, "nested": {"key": "value"}}
+
             result = atomic_write_json(file_path, data)
-            
+
             # ファイルが作成されている
             assert file_path.exists()
-            
+
             # JSON内容が正しい
-            with open(file_path, 'r', encoding='utf-8') as f:
+            with open(file_path, "r", encoding="utf-8") as f:
                 loaded_data = json.load(f)
             assert loaded_data == data
-            
+
             # 整合性チェック
-            assert result['verified'] is True
+            assert result["verified"] is True
 
 
 class TestSafeRead:
     """Safe read テスト"""
-    
+
     def test_safe_read_text(self):
         """Safe text read"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content = "Hello, World!\nThis is a test."
-            
+
             # ファイル作成
-            with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
+            with open(file_path, "w", encoding="utf-8", newline="\n") as f:
                 f.write(content)
-            
+
             # Safe read
             read_content, metadata = safe_read_text(file_path)
-            
+
             assert read_content == content
-            assert metadata['sha256'] == compute_sha256(content)
-            assert metadata['size'] == len(content.encode('utf-8'))
-            assert metadata['eol_ok'] is True
-    
+            assert metadata["sha256"] == compute_sha256(content)
+            assert metadata["size"] == len(content.encode("utf-8"))
+            assert metadata["eol_ok"] is True
+
     def test_safe_read_with_secret_check(self):
         """Secret検証付きsafe read"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content_with_secret = "API_KEY=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"
-            
+
             # ファイル作成
-            with open(file_path, 'w', encoding='utf-8') as f:
+            with open(file_path, "w", encoding="utf-8") as f:
                 f.write(content_with_secret)
-            
+
             # Secret検出でエラー
             with pytest.raises(FileSecurityError):
                 safe_read_text(file_path, check_secrets_enabled=True)
-    
+
     def test_safe_read_json(self):
         """Safe JSON read"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.json"
             data = {"key": "value", "number": 42}
-            
+
             # JSON ファイル作成
-            with open(file_path, 'w', encoding='utf-8') as f:
+            with open(file_path, "w", encoding="utf-8") as f:
                 json.dump(data, f)
-            
+
             # Safe read
             read_data, metadata = safe_read_json(file_path)
-            
+
             assert read_data == data
-            assert 'sha256' in metadata
+            assert "sha256" in metadata
 
 
 class TestConvenienceFunctions:
     """便利関数テスト"""
-    
+
     def test_write_text_lf(self):
         """write_text_lf便利関数"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content = "Hello\nWorld"
-            
+
             result = write_text_lf(file_path, content)
-            
+
             assert file_path.exists()
-            assert result['verified'] is True
-    
+            assert result["verified"] is True
+
     def test_write_json_lf(self):
         """write_json_lf便利関数"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.json"
             data = {"test": True}
-            
+
             result = write_json_lf(file_path, data)
-            
+
             assert file_path.exists()
-            assert result['verified'] is True
-    
+            assert result["verified"] is True
+
     def test_read_text_safe(self):
         """read_text_safe便利関数"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
             content = "Test content"
-            
+
             # ファイル作成
             write_text_lf(file_path, content)
-            
+
             # 読み込み
             read_content = read_text_safe(file_path)
             assert read_content == content
-    
+
     def test_read_json_safe(self):
         """read_json_safe便利関数"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.json"
             data = {"test": True, "value": 123}
-            
+
             # JSON作成
             write_json_lf(file_path, data)
-            
+
             # 読み込み
             read_data = read_json_safe(file_path)
             assert read_data == data
@@ -314,33 +311,29 @@ class TestConvenienceFunctions:
 
 class TestErrorHandling:
     """エラーハンドリングテスト"""
-    
+
     def test_atomic_write_cleanup_on_error(self):
         """エラー時のクリーンアップ"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
-            
+
             # 無効なエンコーディングでエラーを発生させる
             with pytest.raises(Exception):
-                atomic_write_text(
-                    file_path, 
-                    "test", 
-                    encoding='invalid-encoding'
-                )
-            
+                atomic_write_text(file_path, "test", encoding="invalid-encoding")
+
             # 一時ファイルがクリーンアップされている
             tmp_files = list(Path(tmpdir).glob("*.tmp"))
             assert len(tmp_files) == 0
-    
+
     def test_integrity_verification_failure(self):
         """整合性検証失敗"""
         with tempfile.TemporaryDirectory() as tmpdir:
             file_path = Path(tmpdir) / "test.txt"
-            
+
             # モックして整合性エラーを発生させる
             # 実際のテストでは、ディスク容量不足などで発生する可能性がある
             pass  # 実装は複雑になるため省略
 
 
 if __name__ == "__main__":
-    pytest.main([__file__, "-v"])
\ No newline at end of file
+    pytest.main([__file__, "-v"])
diff --git a/tests/test_monitoring_integration.py b/tests/test_monitoring_integration.py
index e77a4b1..5c6db0b 100644
--- a/tests/test_monitoring_integration.py
+++ b/tests/test_monitoring_integration.py
@@ -4,179 +4,179 @@
 包括的なテストケースで監視システムの動作を検証
 """
 
-import unittest
-import sys
-import os
-import time
 import json
+import os
+import sys
 import tempfile
-from unittest.mock import Mock, patch, MagicMock
+import time
+import unittest
 from datetime import datetime, timedelta
+from unittest.mock import MagicMock, Mock, patch
 
 # プロジェクトルートをパスに追加
 sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
-from src.monitoring_system import MonitoringSystem
 from src.alert_enhancer import AlertEnhancer
+from src.monitoring_system import MonitoringSystem
 from src.performance_monitor import SystemPerformanceMonitor
 
 
 class TestMonitoringSystemIntegration(unittest.TestCase):
     """監視システム統合テストクラス"""
-    
+
     def setUp(self):
         """テスト前の準備"""
         self.monitoring_system = None
         self.temp_dir = tempfile.mkdtemp()
-        
+
     def tearDown(self):
         """テスト後のクリーンアップ"""
-        if self.monitoring_system and hasattr(self.monitoring_system, 'stop'):
+        if self.monitoring_system and hasattr(self.monitoring_system, "stop"):
             try:
                 self.monitoring_system.stop()
             except:
                 pass
-        
+
     def test_monitoring_system_initialization(self):
         """監視システムの初期化テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
             self.assertIsNotNone(self.monitoring_system)
-            self.assertTrue(hasattr(self.monitoring_system, 'logger'))
+            self.assertTrue(hasattr(self.monitoring_system, "logger"))
             print("✓ 監視システム初期化テスト成功")
         except Exception as e:
             self.fail(f"監視システム初期化失敗: {e}")
-    
+
     def test_system_status_retrieval(self):
         """システム状態取得テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
             status = self.monitoring_system.get_system_status()
-            
+
             self.assertIsInstance(status, dict)
-            self.assertIn('overall_status', status)
-            self.assertIn('last_update', status)
-            self.assertIn('monitoring_active', status)
-            
+            self.assertIn("overall_status", status)
+            self.assertIn("last_update", status)
+            self.assertIn("monitoring_active", status)
+
             print(f"✓ システム状態取得テスト成功: {status['overall_status']}")
         except Exception as e:
             self.fail(f"システム状態取得失敗: {e}")
-    
+
     def test_performance_summary_retrieval(self):
         """パフォーマンスサマリー取得テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
             performance = self.monitoring_system.get_performance_summary()
-            
+
             self.assertIsInstance(performance, dict)
-            self.assertIn('timestamp', performance)
-            
+            self.assertIn("timestamp", performance)
+
             # エラーがある場合でも適切に処理されることを確認
-            if 'error' in performance:
+            if "error" in performance:
                 print(f"✓ パフォーマンスサマリー取得テスト成功（エラーハンドリング確認）")
             else:
-                self.assertIn('cpu_usage', performance)
+                self.assertIn("cpu_usage", performance)
                 print(f"✓ パフォーマンスサマリー取得テスト成功")
         except Exception as e:
             self.fail(f"パフォーマンスサマリー取得失敗: {e}")
-    
+
     def test_alert_statistics_retrieval(self):
         """アラート統計取得テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
             alerts = self.monitoring_system.get_alert_statistics()
-            
+
             self.assertIsInstance(alerts, dict)
-            self.assertIn('timestamp', alerts)
-            
+            self.assertIn("timestamp", alerts)
+
             # AlertEnhancerが利用可能な場合とフォールバックの場合の両方をテスト
-            if 'total_alerts_24h' in alerts:
-                self.assertIn('by_severity', alerts)
+            if "total_alerts_24h" in alerts:
+                self.assertIn("by_severity", alerts)
                 print("✓ アラート統計取得テスト成功（AlertEnhancer使用）")
             else:
                 # フォールバック実装のテスト
-                self.assertTrue('active_count' in alerts or 'error' in alerts)
+                self.assertTrue("active_count" in alerts or "error" in alerts)
                 print("✓ アラート統計取得テスト成功（フォールバック）")
         except Exception as e:
             self.fail(f"アラート統計取得失敗: {e}")
-    
+
     def test_metrics_history_retrieval(self):
         """メトリクス履歴取得テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
             history = self.monitoring_system.get_metrics_history(hours=6)
-            
+
             self.assertIsInstance(history, dict)
-            self.assertIn('performance', history)
-            self.assertIn('response_times', history)
-            
+            self.assertIn("performance", history)
+            self.assertIn("response_times", history)
+
             # 履歴データの構造をテスト
-            if history['performance']:
-                sample_perf = history['performance'][0]
-                self.assertIn('timestamp', sample_perf)
-                self.assertIn('cpu_usage', sample_perf)
-                
+            if history["performance"]:
+                sample_perf = history["performance"][0]
+                self.assertIn("timestamp", sample_perf)
+                self.assertIn("cpu_usage", sample_perf)
+
             print(f"✓ メトリクス履歴取得テスト成功: {len(history['performance'])}件")
         except Exception as e:
             self.fail(f"メトリクス履歴取得失敗: {e}")
-    
+
     def test_monitoring_system_lifecycle(self):
         """監視システムのライフサイクルテスト"""
         try:
             self.monitoring_system = MonitoringSystem()
-            
+
             # 開始テスト
-            if hasattr(self.monitoring_system, 'start'):
+            if hasattr(self.monitoring_system, "start"):
                 result = self.monitoring_system.start()
                 self.assertTrue(result or result is None)  # 成功またはNone
-            
+
             # 実行中状態の確認
-            if hasattr(self.monitoring_system, 'is_running'):
+            if hasattr(self.monitoring_system, "is_running"):
                 self.assertIsInstance(self.monitoring_system.is_running, bool)
-            
+
             # 停止テスト
-            if hasattr(self.monitoring_system, 'stop'):
+            if hasattr(self.monitoring_system, "stop"):
                 result = self.monitoring_system.stop()
                 self.assertTrue(result or result is None)  # 成功またはNone
-            
+
             print("✓ 監視システムライフサイクルテスト成功")
         except Exception as e:
             self.fail(f"監視システムライフサイクルテスト失敗: {e}")
-    
+
     def test_error_handling(self):
         """エラーハンドリングテスト"""
         try:
             self.monitoring_system = MonitoringSystem()
-            
+
             # 無効なパラメータでのテスト
             history = self.monitoring_system.get_metrics_history(hours=-1)
             self.assertIsInstance(history, dict)
-            
+
             # 大きすぎるパラメータでのテスト
             history = self.monitoring_system.get_metrics_history(hours=1000)
             self.assertIsInstance(history, dict)
-            
+
             print("✓ エラーハンドリングテスト成功")
         except Exception as e:
             self.fail(f"エラーハンドリングテスト失敗: {e}")
-    
+
     def test_data_consistency(self):
         """データ整合性テスト"""
         try:
             self.monitoring_system = MonitoringSystem()
-            
+
             # 複数回の取得で一貫性を確認
             status1 = self.monitoring_system.get_system_status()
             time.sleep(0.1)
             status2 = self.monitoring_system.get_system_status()
-            
+
             # 基本構造が同じであることを確認
             self.assertEqual(set(status1.keys()), set(status2.keys()))
-            
+
             # タイムスタンプが更新されていることを確認
-            if 'last_update' in status1 and 'last_update' in status2:
-                self.assertNotEqual(status1['last_update'], status2['last_update'])
-            
+            if "last_update" in status1 and "last_update" in status2:
+                self.assertNotEqual(status1["last_update"], status2["last_update"])
+
             print("✓ データ整合性テスト成功")
         except Exception as e:
             self.fail(f"データ整合性テスト失敗: {e}")
@@ -184,15 +184,15 @@ class TestMonitoringSystemIntegration(unittest.TestCase):
 
 class TestAlertEnhancerIntegration(unittest.TestCase):
     """アラート強化システム統合テストクラス"""
-    
+
     def setUp(self):
         """テスト前の準備"""
         self.alert_enhancer = None
-        
+
     def tearDown(self):
         """テスト後のクリーンアップ"""
         pass
-    
+
     def test_alert_enhancer_initialization(self):
         """アラート強化システム初期化テスト"""
         try:
@@ -210,19 +210,19 @@ class TestAlertEnhancerIntegration(unittest.TestCase):
 
 class TestPerformanceMonitorIntegration(unittest.TestCase):
     """パフォーマンス監視システム統合テストクラス"""
-    
+
     def setUp(self):
         """テスト前の準備"""
         self.performance_monitor = None
-        
+
     def tearDown(self):
         """テスト後のクリーンアップ"""
-        if self.performance_monitor and hasattr(self.performance_monitor, 'stop_monitoring'):
+        if self.performance_monitor and hasattr(self.performance_monitor, "stop_monitoring"):
             try:
                 self.performance_monitor.stop_monitoring()
             except:
                 pass
-    
+
     def test_performance_monitor_initialization(self):
         """パフォーマンス監視システム初期化テスト"""
         try:
@@ -241,40 +241,42 @@ class TestPerformanceMonitorIntegration(unittest.TestCase):
 def run_comprehensive_tests():
     """包括的テストの実行"""
     print("=== 監視システム包括的テストスイート開始 ===\n")
-    
+
     # テストスイートの作成
     test_suite = unittest.TestSuite()
-    
+
     # 監視システム統合テスト
     test_suite.addTest(unittest.makeSuite(TestMonitoringSystemIntegration))
     test_suite.addTest(unittest.makeSuite(TestAlertEnhancerIntegration))
     test_suite.addTest(unittest.makeSuite(TestPerformanceMonitorIntegration))
-    
+
     # テストランナーの設定
     runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
-    
+
     # テスト実行
     result = runner.run(test_suite)
-    
+
     print(f"\n=== テスト結果サマリー ===")
     print(f"実行テスト数: {result.testsRun}")
     print(f"失敗: {len(result.failures)}")
     print(f"エラー: {len(result.errors)}")
-    print(f"成功率: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
-    
+    print(
+        f"成功率: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%"
+    )
+
     if result.failures:
         print(f"\n失敗したテスト:")
         for test, traceback in result.failures:
             print(f"- {test}: {traceback}")
-    
+
     if result.errors:
         print(f"\nエラーが発生したテスト:")
         for test, traceback in result.errors:
             print(f"- {test}: {traceback}")
-    
+
     return result.wasSuccessful()
 
 
 if __name__ == "__main__":
     success = run_comprehensive_tests()
-    sys.exit(0 if success else 1)
\ No newline at end of file
+    sys.exit(0 if success else 1)
diff --git a/tests/test_performance_suite.py b/tests/test_performance_suite.py
index cb05cc8..5a740d2 100644
--- a/tests/test_performance_suite.py
+++ b/tests/test_performance_suite.py
@@ -6,20 +6,21 @@
 """
 
 import asyncio
+import gc
 import json
 import os
-import psutil
-import pytest
-import requests
 import statistics
+import sys
 import threading
 import time
+import tracemalloc
 from concurrent.futures import ThreadPoolExecutor, as_completed
 from datetime import datetime, timezone
-from typing import Dict, List, Tuple, Any
-import sys
-import gc
-import tracemalloc
+from typing import Any, Dict, List, Tuple
+
+import psutil
+import pytest
+import requests
 
 # テスト対象のエンドポイント
 ENDPOINTS = [
@@ -35,15 +36,16 @@ ENDPOINTS = [
 PERFORMANCE_THRESHOLDS = {
     "response_time_p95": 0.5,  # 500ms
     "response_time_p99": 1.0,  # 1s
-    "error_rate_max": 0.01,    # 1%
-    "cpu_usage_max": 80.0,     # 80%
+    "error_rate_max": 0.01,  # 1%
+    "cpu_usage_max": 80.0,  # 80%
     "memory_usage_max": 85.0,  # 85%
-    "throughput_min": 100,     # 100 req/s
+    "throughput_min": 100,  # 100 req/s
 }
 
+
 class PerformanceMetrics:
     """パフォーマンスメトリクス収集クラス"""
-    
+
     def __init__(self):
         self.response_times = []
         self.error_count = 0
@@ -53,38 +55,38 @@ class PerformanceMetrics:
         self.cpu_usage = []
         self.memory_usage = []
         self.memory_peak = 0
-        
+
     def start_monitoring(self):
         """監視開始"""
         self.start_time = time.perf_counter()
         tracemalloc.start()
-        
+
     def stop_monitoring(self):
         """監視終了"""
         self.end_time = time.perf_counter()
         current, peak = tracemalloc.get_traced_memory()
         tracemalloc.stop()
         self.memory_peak = peak / 1024 / 1024  # MB
-        
+
     def record_request(self, response_time: float, success: bool):
         """リクエスト結果を記録"""
         self.response_times.append(response_time)
         self.total_requests += 1
         if not success:
             self.error_count += 1
-            
+
     def record_system_metrics(self):
         """システムメトリクスを記録"""
         self.cpu_usage.append(psutil.cpu_percent())
         self.memory_usage.append(psutil.virtual_memory().percent)
-        
+
     def get_summary(self) -> Dict[str, Any]:
         """メトリクスサマリーを取得"""
         if not self.response_times:
             return {"error": "No data collected"}
-            
+
         duration = self.end_time - self.start_time if self.end_time else 0
-        
+
         return {
             "duration_seconds": duration,
             "total_requests": self.total_requests,
@@ -95,8 +97,16 @@ class PerformanceMetrics:
                 "max": max(self.response_times),
                 "mean": statistics.mean(self.response_times),
                 "median": statistics.median(self.response_times),
-                "p95": statistics.quantiles(self.response_times, n=100)[94] if len(self.response_times) >= 20 else max(self.response_times),
-                "p99": statistics.quantiles(self.response_times, n=100)[98] if len(self.response_times) >= 20 else max(self.response_times),
+                "p95": (
+                    statistics.quantiles(self.response_times, n=100)[94]
+                    if len(self.response_times) >= 20
+                    else max(self.response_times)
+                ),
+                "p99": (
+                    statistics.quantiles(self.response_times, n=100)[98]
+                    if len(self.response_times) >= 20
+                    else max(self.response_times)
+                ),
             },
             "throughput_rps": self.total_requests / duration if duration > 0 else 0,
             "cpu_usage": {
@@ -107,156 +117,169 @@ class PerformanceMetrics:
                 "mean": statistics.mean(self.memory_usage) if self.memory_usage else 0,
                 "max": max(self.memory_usage) if self.memory_usage else 0,
                 "peak_mb": self.memory_peak,
-            }
+            },
         }
 
+
 class PerformanceTestSuite:
     """パフォーマンステストスイート"""
-    
+
     def __init__(self):
         self.metrics = PerformanceMetrics()
         self.monitoring_active = False
-        
+
     def system_monitor_thread(self):
         """システム監視スレッド"""
         while self.monitoring_active:
             self.metrics.record_system_metrics()
             time.sleep(0.1)  # 100ms間隔
-            
-    def make_request(self, endpoint: str, method: str = "GET", timeout: int = 5) -> Tuple[float, bool]:
+
+    def make_request(
+        self, endpoint: str, method: str = "GET", timeout: int = 5
+    ) -> Tuple[float, bool]:
         """HTTPリクエストを実行"""
         start_time = time.perf_counter()
         success = False
-        
+
         try:
             if method.upper() == "GET":
                 response = requests.get(endpoint, timeout=timeout)
             else:
                 response = requests.request(method, endpoint, timeout=timeout)
-            
+
             success = 200 <= response.status_code < 300
         except Exception as e:
             print(f"Request failed for {endpoint}: {e}")
-            
+
         response_time = time.perf_counter() - start_time
         return response_time, success
-        
-    def run_single_endpoint_test(self, endpoint: str, method: str, iterations: int = 100) -> Dict[str, Any]:
+
+    def run_single_endpoint_test(
+        self, endpoint: str, method: str, iterations: int = 100
+    ) -> Dict[str, Any]:
         """単一エンドポイントのテスト"""
         print(f"Testing {endpoint} ({method}) - {iterations} iterations")
-        
+
         local_metrics = PerformanceMetrics()
         local_metrics.start_monitoring()
-        
+
         for i in range(iterations):
             response_time, success = self.make_request(endpoint, method)
             local_metrics.record_request(response_time, success)
-            
+
             if i % 10 == 0:  # 10回ごとにシステムメトリクス記録
                 local_metrics.record_system_metrics()
-                
+
         local_metrics.stop_monitoring()
         return local_metrics.get_summary()
-        
-    def run_concurrent_test(self, max_workers: int = 10, duration_seconds: int = 30) -> Dict[str, Any]:
+
+    def run_concurrent_test(
+        self, max_workers: int = 10, duration_seconds: int = 30
+    ) -> Dict[str, Any]:
         """並行負荷テスト"""
         print(f"Running concurrent test - {max_workers} workers for {duration_seconds}s")
-        
+
         self.metrics = PerformanceMetrics()
         self.metrics.start_monitoring()
         self.monitoring_active = True
-        
+
         # システム監視スレッド開始
         monitor_thread = threading.Thread(target=self.system_monitor_thread)
         monitor_thread.start()
-        
+
         end_time = time.time() + duration_seconds
-        
+
         def worker():
             while time.time() < end_time:
                 endpoint, method = ENDPOINTS[0]  # メインエンドポイントをテスト
                 response_time, success = self.make_request(endpoint, method)
                 self.metrics.record_request(response_time, success)
-                
+
         # ワーカースレッド実行
         with ThreadPoolExecutor(max_workers=max_workers) as executor:
             futures = [executor.submit(worker) for _ in range(max_workers)]
-            
+
             # 全ワーカー完了まで待機
             for future in as_completed(futures):
                 try:
                     future.result()
                 except Exception as e:
                     print(f"Worker error: {e}")
-                    
+
         self.monitoring_active = False
         monitor_thread.join()
         self.metrics.stop_monitoring()
-        
+
         return self.metrics.get_summary()
-        
-    def run_stress_test(self, start_workers: int = 1, max_workers: int = 50, step: int = 5) -> List[Dict[str, Any]]:
+
+    def run_stress_test(
+        self, start_workers: int = 1, max_workers: int = 50, step: int = 5
+    ) -> List[Dict[str, Any]]:
         """ストレステスト - 段階的に負荷を増加"""
         print(f"Running stress test - {start_workers} to {max_workers} workers")
-        
+
         results = []
-        
+
         for workers in range(start_workers, max_workers + 1, step):
             print(f"Testing with {workers} concurrent workers...")
             result = self.run_concurrent_test(max_workers=workers, duration_seconds=10)
             result["concurrent_workers"] = workers
             results.append(result)
-            
+
             # 短い休憩
             time.sleep(2)
-            
+
         return results
 
+
 @pytest.fixture
 def performance_suite():
     """パフォーマンステストスイートのフィクスチャ"""
     return PerformanceTestSuite()
 
+
 class TestPerformanceSuite:
     """パフォーマンステストクラス"""
-    
+
     def test_single_endpoint_performance(self, performance_suite):
         """単一エンドポイントのパフォーマンステスト"""
         print("\n=== 単一エンドポイントパフォーマンステスト ===")
-        
+
         results = {}
         for endpoint, method in ENDPOINTS:
             try:
                 result = performance_suite.run_single_endpoint_test(endpoint, method, iterations=50)
                 results[endpoint] = result
-                
+
                 # 結果表示
                 print(f"\n{endpoint}:")
                 print(f"  応答時間 P95: {result['response_time']['p95']:.3f}s")
                 print(f"  エラー率: {result['error_rate']*100:.2f}%")
                 print(f"  スループット: {result['throughput_rps']:.1f} req/s")
-                
+
                 # アサーション
-                assert result['response_time']['p95'] < PERFORMANCE_THRESHOLDS['response_time_p95'], \
-                    f"P95応答時間が基準値を超過: {result['response_time']['p95']:.3f}s > {PERFORMANCE_THRESHOLDS['response_time_p95']}s"
-                    
-                assert result['error_rate'] < PERFORMANCE_THRESHOLDS['error_rate_max'], \
-                    f"エラー率が基準値を超過: {result['error_rate']*100:.2f}% > {PERFORMANCE_THRESHOLDS['error_rate_max']*100:.2f}%"
-                    
+                assert (
+                    result["response_time"]["p95"] < PERFORMANCE_THRESHOLDS["response_time_p95"]
+                ), f"P95応答時間が基準値を超過: {result['response_time']['p95']:.3f}s > {PERFORMANCE_THRESHOLDS['response_time_p95']}s"
+
+                assert (
+                    result["error_rate"] < PERFORMANCE_THRESHOLDS["error_rate_max"]
+                ), f"エラー率が基準値を超過: {result['error_rate']*100:.2f}% > {PERFORMANCE_THRESHOLDS['error_rate_max']*100:.2f}%"
+
             except Exception as e:
                 print(f"エンドポイント {endpoint} のテストでエラー: {e}")
                 results[endpoint] = {"error": str(e)}
-                
+
         # 結果をファイルに保存
         self._save_results("single_endpoint_performance", results)
         print("✓ 単一エンドポイントパフォーマンステスト完了")
-        
+
     def test_concurrent_load(self, performance_suite):
         """並行負荷テスト"""
         print("\n=== 並行負荷テスト ===")
-        
+
         result = performance_suite.run_concurrent_test(max_workers=20, duration_seconds=30)
-        
+
         print(f"総リクエスト数: {result['total_requests']}")
         print(f"エラー数: {result['error_count']}")
         print(f"エラー率: {result['error_rate']*100:.2f}%")
@@ -265,125 +288,143 @@ class TestPerformanceSuite:
         print(f"スループット: {result['throughput_rps']:.1f} req/s")
         print(f"平均CPU使用率: {result['cpu_usage']['mean']:.1f}%")
         print(f"平均メモリ使用率: {result['memory_usage']['mean']:.1f}%")
-        
+
         # アサーション
-        assert result['error_rate'] < PERFORMANCE_THRESHOLDS['error_rate_max'], \
-            f"エラー率が基準値を超過: {result['error_rate']*100:.2f}%"
-            
-        assert result['throughput_rps'] > PERFORMANCE_THRESHOLDS['throughput_min'], \
-            f"スループットが基準値を下回る: {result['throughput_rps']:.1f} req/s"
-            
+        assert (
+            result["error_rate"] < PERFORMANCE_THRESHOLDS["error_rate_max"]
+        ), f"エラー率が基準値を超過: {result['error_rate']*100:.2f}%"
+
+        assert (
+            result["throughput_rps"] > PERFORMANCE_THRESHOLDS["throughput_min"]
+        ), f"スループットが基準値を下回る: {result['throughput_rps']:.1f} req/s"
+
         self._save_results("concurrent_load", result)
         print("✓ 並行負荷テスト完了")
-        
+
     def test_stress_test(self, performance_suite):
         """ストレステスト"""
         print("\n=== ストレステスト ===")
-        
+
         results = performance_suite.run_stress_test(start_workers=5, max_workers=30, step=5)
-        
+
         print("\nストレステスト結果:")
         for result in results:
-            workers = result['concurrent_workers']
-            throughput = result['throughput_rps']
-            error_rate = result['error_rate'] * 100
-            p95 = result['response_time']['p95']
-            
-            print(f"  {workers:2d} workers: {throughput:6.1f} req/s, {error_rate:5.2f}% errors, P95: {p95:.3f}s")
-            
+            workers = result["concurrent_workers"]
+            throughput = result["throughput_rps"]
+            error_rate = result["error_rate"] * 100
+            p95 = result["response_time"]["p95"]
+
+            print(
+                f"  {workers:2d} workers: {throughput:6.1f} req/s, {error_rate:5.2f}% errors, P95: {p95:.3f}s"
+            )
+
         # 最大スループットを見つける
-        max_throughput = max(r['throughput_rps'] for r in results)
-        optimal_workers = next(r['concurrent_workers'] for r in results if r['throughput_rps'] == max_throughput)
-        
-        print(f"\n最適並行数: {optimal_workers} workers (最大スループット: {max_throughput:.1f} req/s)")
-        
-        self._save_results("stress_test", {
-            "results": results,
-            "optimal_workers": optimal_workers,
-            "max_throughput": max_throughput
-        })
+        max_throughput = max(r["throughput_rps"] for r in results)
+        optimal_workers = next(
+            r["concurrent_workers"] for r in results if r["throughput_rps"] == max_throughput
+        )
+
+        print(
+            f"\n最適並行数: {optimal_workers} workers (最大スループット: {max_throughput:.1f} req/s)"
+        )
+
+        self._save_results(
+            "stress_test",
+            {
+                "results": results,
+                "optimal_workers": optimal_workers,
+                "max_throughput": max_throughput,
+            },
+        )
         print("✓ ストレステスト完了")
-        
+
     def test_memory_usage_analysis(self):
         """メモリ使用量分析"""
         print("\n=== メモリ使用量分析 ===")
-        
+
         # ガベージコレクション前のメモリ状況
         gc.collect()
         initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
-        
+
         # メモリ集約的な処理をシミュレート
         tracemalloc.start()
-        
+
         # 大量のリクエストを実行
         suite = PerformanceTestSuite()
         result = suite.run_concurrent_test(max_workers=10, duration_seconds=15)
-        
+
         current, peak = tracemalloc.get_traced_memory()
         tracemalloc.stop()
-        
+
         final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
         memory_growth = final_memory - initial_memory
         peak_memory_mb = peak / 1024 / 1024
-        
+
         print(f"初期メモリ使用量: {initial_memory:.1f} MB")
         print(f"最終メモリ使用量: {final_memory:.1f} MB")
         print(f"メモリ増加量: {memory_growth:.1f} MB")
         print(f"ピークメモリ使用量: {peak_memory_mb:.1f} MB")
-        
+
         memory_analysis = {
             "initial_memory_mb": initial_memory,
             "final_memory_mb": final_memory,
             "memory_growth_mb": memory_growth,
             "peak_memory_mb": peak_memory_mb,
-            "performance_result": result
+            "performance_result": result,
         }
-        
+
         # メモリリークの検出
         assert memory_growth < 100, f"メモリ使用量の増加が大きすぎます: {memory_growth:.1f} MB"
-        
+
         self._save_results("memory_analysis", memory_analysis)
         print("✓ メモリ使用量分析完了")
-        
+
     def _save_results(self, test_name: str, results: Dict[str, Any]):
         """テスト結果をファイルに保存"""
         timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
         filename = f"performance_{test_name}_{timestamp}.json"
         filepath = f"C:/Users/User/Trae/ORCH-Next/data/test_results/{filename}"
-        
+
         # ディレクトリが存在しない場合は作成
         os.makedirs(os.path.dirname(filepath), exist_ok=True)
-        
-        with open(filepath, 'w', encoding='utf-8') as f:
-            json.dump({
-                "timestamp": timestamp,
-                "test_name": test_name,
-                "results": results,
-                "thresholds": PERFORMANCE_THRESHOLDS
-            }, f, indent=2, ensure_ascii=False)
-            
+
+        with open(filepath, "w", encoding="utf-8") as f:
+            json.dump(
+                {
+                    "timestamp": timestamp,
+                    "test_name": test_name,
+                    "results": results,
+                    "thresholds": PERFORMANCE_THRESHOLDS,
+                },
+                f,
+                indent=2,
+                ensure_ascii=False,
+            )
+
         print(f"結果を保存: {filepath}")
 
+
 if __name__ == "__main__":
     # 直接実行時のテスト
     suite = PerformanceTestSuite()
-    
+
     print("パフォーマンステストスイート実行開始")
     print("=" * 50)
-    
+
     # 基本的なパフォーマンステスト
     test_suite = TestPerformanceSuite()
-    
+
     try:
         test_suite.test_single_endpoint_performance(suite)
         test_suite.test_concurrent_load(suite)
         test_suite.test_stress_test(suite)
         test_suite.test_memory_usage_analysis()
-        
+
         print("\n" + "=" * 50)
         print("✓ 全パフォーマンステスト完了")
-        
+
     except Exception as e:
         print(f"\nテスト実行中にエラーが発生: {e}")
         import traceback
-        traceback.print_exc()
\ No newline at end of file
+
+        traceback.print_exc()
diff --git a/tests/test_security_integration.py b/tests/test_security_integration.py
index ba27408..d831b9c 100644
--- a/tests/test_security_integration.py
+++ b/tests/test_security_integration.py
@@ -12,11 +12,11 @@
 - セッション管理
 """
 
-import sys
 import os
-import unittest
-import tempfile
 import shutil
+import sys
+import tempfile
+import unittest
 from pathlib import Path
 
 # プロジェクトルートをパスに追加
@@ -40,7 +40,7 @@ class TestSecurityManagerIntegration(unittest.TestCase):
 
     def tearDown(self):
         """テスト後のクリーンアップ"""
-        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
+        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
             shutil.rmtree(self.temp_dir)
 
     def test_security_manager_initialization(self):
@@ -57,12 +57,12 @@ class TestSecurityManagerIntegration(unittest.TestCase):
         weak_passwords = ["123", "password", "abc"]
         for pwd in weak_passwords:
             self.assertFalse(self.security_manager.check_password_strength(pwd))
-        
+
         # 強いパスワード
         strong_passwords = ["StrongPass123!", "MySecure@Pass2024", "Complex#Password1"]
         for pwd in strong_passwords:
             self.assertTrue(self.security_manager.check_password_strength(pwd))
-        
+
         print("✓ パスワード強度検証テスト成功")
 
     def test_user_registration_and_authentication(self):
@@ -70,58 +70,58 @@ class TestSecurityManagerIntegration(unittest.TestCase):
         username = "testuser"
         password = "TestPassword123!"
         role = "user"
-        
+
         # ユーザー登録
         success = self.security_manager.register_user(username, password, role)
         self.assertTrue(success)
-        
+
         # 認証テスト
         token = self.security_manager.authenticate_user(username, password)
         self.assertIsNotNone(token)
         self.assertIsInstance(token, str)
-        
+
         # 間違ったパスワードでの認証
         invalid_token = self.security_manager.authenticate_user(username, "wrongpassword")
         self.assertIsNone(invalid_token)
-        
+
         print("✓ ユーザー登録と認証テスト成功")
 
     def test_jwt_token_operations(self):
         """JWTトークン操作テスト"""
         username = "jwtuser"
         password = "JWTPassword123!"
-        
+
         # ユーザー登録
         self.security_manager.register_user(username, password, "user")
-        
+
         # トークン生成
         token = self.security_manager.authenticate_user(username, password)
         self.assertIsNotNone(token)
-        
+
         # トークン検証
         payload = self.security_manager.verify_token(token)
         self.assertIsNotNone(payload)
         self.assertEqual(payload.get("username"), username)
-        
+
         # 無効なトークン検証
         invalid_payload = self.security_manager.verify_token("invalid.token.here")
         self.assertIsNone(invalid_payload)
-        
+
         print("✓ JWTトークン操作テスト成功")
 
     def test_encryption_decryption(self):
         """暗号化・復号化テスト"""
         test_data = "これは機密データです"
-        
+
         # 暗号化
         encrypted_data = self.security_manager.encrypt_data(test_data)
         self.assertIsNotNone(encrypted_data)
         self.assertNotEqual(encrypted_data, test_data)
-        
+
         # 復号化
         decrypted_data = self.security_manager.decrypt_data(encrypted_data)
         self.assertEqual(decrypted_data, test_data)
-        
+
         print("✓ 暗号化・復号化テスト成功")
 
     def test_access_control(self):
@@ -130,37 +130,37 @@ class TestSecurityManagerIntegration(unittest.TestCase):
         admin_user = "admin"
         admin_password = "AdminPass123!"
         self.security_manager.register_user(admin_user, admin_password, "admin")
-        
+
         # 一般ユーザー
         regular_user = "user"
         user_password = "UserPass123!"
         self.security_manager.register_user(regular_user, user_password, "user")
-        
+
         # 権限チェック
         self.assertTrue(self.security_manager.check_permission(admin_user, "admin"))
         self.assertTrue(self.security_manager.check_permission(admin_user, "user"))
         self.assertFalse(self.security_manager.check_permission(regular_user, "admin"))
         self.assertTrue(self.security_manager.check_permission(regular_user, "user"))
-        
+
         print("✓ アクセス制御テスト成功")
 
     def test_rate_limiting(self):
         """レート制限テスト"""
         client_ip = "192.168.1.100"
-        
+
         # 制限内のリクエスト
         for i in range(5):
             allowed = self.security_manager.check_rate_limit(client_ip)
             self.assertTrue(allowed)
-        
+
         # 制限を超えるリクエスト（デフォルト制限は10/分）
         for i in range(10):
             self.security_manager.check_rate_limit(client_ip)
-        
+
         # 制限を超えた場合
         blocked = self.security_manager.check_rate_limit(client_ip)
         # 注意: 実際の制限値によって結果が変わる可能性があります
-        
+
         print("✓ レート制限テスト成功")
 
     def test_session_management(self):
@@ -168,73 +168,73 @@ class TestSecurityManagerIntegration(unittest.TestCase):
         username = "sessionuser"
         password = "SessionPass123!"
         self.security_manager.register_user(username, password, "user")
-        
+
         # セッション作成
         session_id = self.security_manager.create_session(username)
         self.assertIsNotNone(session_id)
-        
+
         # セッション検証
         valid = self.security_manager.validate_session(session_id)
         self.assertTrue(valid)
-        
+
         # セッション削除
         self.security_manager.invalidate_session(session_id)
-        
+
         # 削除後の検証
         invalid = self.security_manager.validate_session(session_id)
         self.assertFalse(invalid)
-        
+
         print("✓ セッション管理テスト成功")
 
     def test_audit_logging(self):
         """監査ログテスト"""
         initial_log_count = len(self.security_manager.audit_logs)
-        
+
         # 監査ログ記録
         self.security_manager.log_security_event("test_event", "testuser", "テストイベント")
-        
+
         # ログが追加されたことを確認
         self.assertEqual(len(self.security_manager.audit_logs), initial_log_count + 1)
-        
+
         # ログ内容確認
         latest_log = self.security_manager.audit_logs[-1]
         self.assertEqual(latest_log["action"], "test_event")
         self.assertEqual(latest_log["user"], "testuser")
         self.assertEqual(latest_log["details"], "テストイベント")
-        
+
         print("✓ 監査ログテスト成功")
 
     def test_security_status_retrieval(self):
         """セキュリティステータス取得テスト"""
         status = self.security_manager.get_security_status()
-        
+
         self.assertIsInstance(status, dict)
         self.assertIn("overall_status", status)
         self.assertIn("active_sessions", status)
         self.assertIn("failed_login_attempts", status)
         self.assertIn("security_score", status)
         self.assertIn("timestamp", status)
-        
+
         print("✓ セキュリティステータス取得テスト成功")
 
     def test_ip_whitelist_management(self):
         """IPホワイトリスト管理テスト"""
         test_ip = "192.168.1.50"
-        
+
         # 初期状態（ホワイトリストが空の場合、すべて許可）
         initial_allowed = self.security_manager.is_ip_allowed(test_ip)
-        
+
         # IPをホワイトリストに追加
         self.security_manager.add_to_whitelist(test_ip)
-        
+
         # ホワイトリストに登録されたIPは許可される
         allowed = self.security_manager.is_ip_allowed(test_ip)
         self.assertTrue(allowed)
-        
+
         # 登録されていないIPは拒否される（ホワイトリストが有効な場合）
         not_allowed = self.security_manager.is_ip_allowed("10.0.0.1")
         # 注意: 実装によって動作が異なる可能性があります
-        
+
         print("✓ IPホワイトリスト管理テスト成功")
 
 
@@ -249,21 +249,29 @@ class TestSecurityIntegrationWithDashboard(unittest.TestCase):
         """ダッシュボード統合データ形式テスト"""
         # セキュリティステータス
         status = self.security_manager.get_security_status()
-        required_fields = ["overall_status", "active_sessions", "failed_login_attempts", "security_score", "timestamp"]
-        
+        required_fields = [
+            "overall_status",
+            "active_sessions",
+            "failed_login_attempts",
+            "security_score",
+            "timestamp",
+        ]
+
         for field in required_fields:
             self.assertIn(field, status, f"必須フィールド '{field}' がありません")
-        
+
         # 監査ログ
         logs = self.security_manager.get_audit_logs()
         self.assertIsInstance(logs, list)
-        
+
         if logs:
             log_entry = logs[0]
             log_required_fields = ["action", "user", "timestamp", "details"]
             for field in log_required_fields:
-                self.assertIn(field, log_entry, f"ログエントリに必須フィールド '{field}' がありません")
-        
+                self.assertIn(
+                    field, log_entry, f"ログエントリに必須フィールド '{field}' がありません"
+                )
+
         print("✓ ダッシュボード統合データ形式テスト成功")
 
     def test_error_handling(self):
@@ -271,18 +279,18 @@ class TestSecurityIntegrationWithDashboard(unittest.TestCase):
         # 存在しないユーザーでの認証
         token = self.security_manager.authenticate_user("nonexistent", "password")
         self.assertIsNone(token)
-        
+
         # 無効なデータでの暗号化
         try:
             encrypted = self.security_manager.encrypt_data(None)
             # Noneの場合の処理は実装依存
         except Exception:
             pass  # 例外が発生することも想定される
-        
+
         # 無効なセッションIDでの検証
         valid = self.security_manager.validate_session("invalid_session_id")
         self.assertFalse(valid)
-        
+
         print("✓ エラーハンドリングテスト成功")
 
 
@@ -291,20 +299,20 @@ def run_security_tests():
     print("=" * 60)
     print("セキュリティシステム統合テストスイート開始")
     print("=" * 60)
-    
+
     # テストスイート作成
     test_suite = unittest.TestSuite()
-    
+
     # SecurityManager統合テスト
     test_suite.addTest(unittest.makeSuite(TestSecurityManagerIntegration))
-    
+
     # ダッシュボード統合テスト
     test_suite.addTest(unittest.makeSuite(TestSecurityIntegrationWithDashboard))
-    
+
     # テスト実行
     runner = unittest.TextTestRunner(verbosity=2)
     result = runner.run(test_suite)
-    
+
     # 結果サマリー
     print("\n" + "=" * 60)
     print("テスト結果サマリー")
@@ -313,23 +321,27 @@ def run_security_tests():
     print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
     print(f"失敗: {len(result.failures)}")
     print(f"エラー: {len(result.errors)}")
-    
+
     if result.failures:
         print("\n失敗したテスト:")
         for test, traceback in result.failures:
             print(f"- {test}: {traceback}")
-    
+
     if result.errors:
         print("\nエラーが発生したテスト:")
         for test, traceback in result.errors:
             print(f"- {test}: {traceback}")
-    
-    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
+
+    success_rate = (
+        ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
+        if result.testsRun > 0
+        else 0
+    )
     print(f"\n成功率: {success_rate:.1f}%")
-    
+
     return result.wasSuccessful()
 
 
 if __name__ == "__main__":
     success = run_security_tests()
-    sys.exit(0 if success else 1)
\ No newline at end of file
+    sys.exit(0 if success else 1)
diff --git a/tests/test_sse_integration.py b/tests/test_sse_integration.py
index 9cc44f0..f340f0d 100644
--- a/tests/test_sse_integration.py
+++ b/tests/test_sse_integration.py
@@ -4,168 +4,170 @@ SSE (Server-Sent Events) 統合テスト
 リアルタイム通信機能の独立性と動作を検証
 """
 
-import pytest
-import requests
-import time
-import threading
 import json
-from unittest.mock import patch, MagicMock
-import sys
 import os
+import sys
+import threading
+import time
+from unittest.mock import MagicMock, patch
+
+import pytest
+import requests
 
 # プロジェクトルートをパスに追加
 sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
-from src.blueprints.sse_routes import SSEManager, sse_bp
 from orch_dashboard_refactored import OrchDashboardRefactored
 
+from src.blueprints.sse_routes import SSEManager, sse_bp
+
 
 class TestSSEIntegration:
     """SSE統合テストクラス"""
-    
+
     @pytest.fixture
     def dashboard(self):
         """テスト用ダッシュボードインスタンス"""
         dashboard = OrchDashboardRefactored()
-        dashboard.app.config['TESTING'] = True
+        dashboard.app.config["TESTING"] = True
         return dashboard
-    
+
     @pytest.fixture
     def client(self, dashboard):
         """テスト用Flaskクライアント"""
         return dashboard.app.test_client()
-    
+
     @pytest.fixture
     def sse_manager(self):
         """テスト用SSEマネージャー"""
         return SSEManager()
-    
+
     def test_sse_manager_initialization(self, sse_manager):
         """SSEマネージャーの初期化テスト"""
         assert sse_manager.clients == {}
         assert sse_manager.client_counter == 0
-    
+
     def test_sse_client_registration(self, sse_manager):
         """SSEクライアント登録テスト"""
         # モッククライアントを作成
         mock_client = MagicMock()
-        
+
         # クライアント登録
         client_id = sse_manager.add_client(mock_client)
-        
+
         assert client_id in sse_manager.clients
         assert sse_manager.clients[client_id] == mock_client
         assert sse_manager.client_counter == 1
-    
+
     def test_sse_client_removal(self, sse_manager):
         """SSEクライアント削除テスト"""
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         # クライアント削除
         sse_manager.remove_client(client_id)
-        
+
         assert client_id not in sse_manager.clients
-    
+
     def test_sse_broadcast_message(self, sse_manager):
         """SSEブロードキャストテスト"""
         # 複数のモッククライアントを登録
         mock_clients = []
         client_ids = []
-        
+
         for i in range(3):
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             mock_clients.append(mock_client)
             client_ids.append(client_id)
-        
+
         # メッセージをブロードキャスト
         test_message = {"type": "test", "data": "hello"}
         sse_manager.broadcast(test_message)
-        
+
         # 全クライアントにメッセージが送信されたことを確認
         for mock_client in mock_clients:
             mock_client.put.assert_called_once()
-    
+
     def test_sse_health_endpoint(self, client):
         """SSEヘルスエンドポイントテスト"""
-        response = client.get('/events/health')
+        response = client.get("/events/health")
         assert response.status_code == 200
-        
+
         data = json.loads(response.data)
-        assert data['status'] == 'healthy'
-        assert 'clients' in data
-        assert 'uptime' in data
-    
+        assert data["status"] == "healthy"
+        assert "clients" in data
+        assert "uptime" in data
+
     def test_sse_broadcast_endpoint(self, client):
         """SSEブロードキャストエンドポイントテスト"""
         test_data = {
             "type": "test_broadcast",
             "message": "テストメッセージ",
-            "timestamp": time.time()
+            "timestamp": time.time(),
         }
-        
-        response = client.post('/events/broadcast', 
-                             data=json.dumps(test_data),
-                             content_type='application/json')
-        
+
+        response = client.post(
+            "/events/broadcast", data=json.dumps(test_data), content_type="application/json"
+        )
+
         assert response.status_code == 200
         data = json.loads(response.data)
-        assert data['success'] is True
-    
+        assert data["success"] is True
+
     def test_sse_events_endpoint_structure(self, client):
         """SSEイベントエンドポイント構造テスト"""
         # SSEエンドポイントへのGETリクエスト
-        response = client.get('/events')
-        
+        response = client.get("/events")
+
         # SSEレスポンスの基本構造を確認
         assert response.status_code == 200
-        assert response.content_type.startswith('text/event-stream')
-        assert 'Cache-Control' in response.headers
-        assert response.headers['Cache-Control'] == 'no-cache'
-    
+        assert response.content_type.startswith("text/event-stream")
+        assert "Cache-Control" in response.headers
+        assert response.headers["Cache-Control"] == "no-cache"
+
     @pytest.mark.integration
     def test_sse_real_connection(self, dashboard):
         """実際のSSE接続テスト（統合テスト）"""
         # テスト用サーバーを別スレッドで起動
         server_thread = threading.Thread(
             target=lambda: dashboard.app.run(port=5002, debug=False, use_reloader=False),
-            daemon=True
+            daemon=True,
         )
         server_thread.start()
         time.sleep(2)  # サーバー起動待機
-        
+
         try:
             # SSEエンドポイントに接続
-            response = requests.get('http://localhost:5002/events', 
-                                  stream=True, timeout=5)
+            response = requests.get("http://localhost:5002/events", stream=True, timeout=5)
             assert response.status_code == 200
-            assert response.headers['content-type'].startswith('text/event-stream')
-            
+            assert response.headers["content-type"].startswith("text/event-stream")
+
             # ブロードキャストテスト
             broadcast_data = {"type": "integration_test", "message": "統合テスト"}
-            broadcast_response = requests.post('http://localhost:5002/events/broadcast',
-                                             json=broadcast_data, timeout=5)
+            broadcast_response = requests.post(
+                "http://localhost:5002/events/broadcast", json=broadcast_data, timeout=5
+            )
             assert broadcast_response.status_code == 200
-            
+
         except requests.exceptions.RequestException as e:
             pytest.skip(f"統合テストスキップ: サーバー接続エラー {e}")
-    
+
     def test_sse_error_handling(self, sse_manager):
         """SSEエラーハンドリングテスト"""
         # 無効なクライアントIDでの削除
         sse_manager.remove_client("invalid_id")  # エラーが発生しないことを確認
-        
+
         # ブロードキャスト時のクライアントエラー
         mock_client = MagicMock()
         mock_client.put.side_effect = Exception("クライアントエラー")
-        
+
         client_id = sse_manager.add_client(mock_client)
         sse_manager.broadcast({"type": "error_test"})
-        
+
         # エラーが発生してもクライアントが削除されることを確認
         assert client_id not in sse_manager.clients
-    
+
     def test_sse_concurrent_clients(self, sse_manager):
         """SSE同時接続クライアントテスト"""
         # 複数クライアントの同時登録
@@ -174,36 +176,36 @@ class TestSSEIntegration:
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             clients.append((client_id, mock_client))
-        
+
         assert len(sse_manager.clients) == 10
-        
+
         # 同時ブロードキャスト
         test_message = {"type": "concurrent_test", "data": f"message_{time.time()}"}
         sse_manager.broadcast(test_message)
-        
+
         # 全クライアントが呼び出されたことを確認
         for client_id, mock_client in clients:
             mock_client.put.assert_called_once()
-    
+
     def test_sse_message_formatting(self, sse_manager):
         """SSEメッセージフォーマットテスト"""
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         # 様々な形式のメッセージをテスト
         test_messages = [
             {"type": "string", "data": "simple string"},
             {"type": "object", "data": {"key": "value", "number": 123}},
             {"type": "array", "data": [1, 2, 3, "test"]},
-            {"type": "unicode", "data": "日本語メッセージ🚀"}
+            {"type": "unicode", "data": "日本語メッセージ🚀"},
         ]
-        
+
         for message in test_messages:
             sse_manager.broadcast(message)
             mock_client.put.assert_called()
             mock_client.reset_mock()
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     # テスト実行
-    pytest.main([__file__, '-v', '--tb=short'])
\ No newline at end of file
+    pytest.main([__file__, "-v", "--tb=short"])
diff --git a/tests/test_sse_longevity.py b/tests/test_sse_longevity.py
index 9e58e03..fc3de78 100644
--- a/tests/test_sse_longevity.py
+++ b/tests/test_sse_longevity.py
@@ -4,57 +4,59 @@ SSE (Server-Sent Events) 長時間接続テスト
 リアルタイム通信の安定性と耐久性を検証
 """
 
-import pytest
-import requests
-import time
-import threading
 import json
+import os
 import queue
-from unittest.mock import patch, MagicMock
 import sys
-import os
+import threading
+import time
+from unittest.mock import MagicMock, patch
+
+import pytest
+import requests
 
 # プロジェクトルートをパスに追加
 sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
-from src.blueprints.sse_routes import SSEManager
 from orch_dashboard_refactored import OrchDashboardRefactored
 
+from src.blueprints.sse_routes import SSEManager
+
 
 class TestSSELongevity:
     """SSE長時間接続テストクラス"""
-    
+
     @pytest.fixture
     def dashboard(self):
         """テスト用ダッシュボードインスタンス"""
         dashboard = OrchDashboardRefactored()
-        dashboard.app.config['TESTING'] = True
+        dashboard.app.config["TESTING"] = True
         return dashboard
-    
+
     @pytest.fixture
     def sse_manager(self):
         """テスト用SSEマネージャー"""
         return SSEManager()
-    
+
     def test_sse_manager_memory_leak(self, sse_manager):
         """SSEマネージャーのメモリリークテスト"""
         initial_clients = len(sse_manager.clients)
-        
+
         # 大量のクライアントを追加・削除
         client_ids = []
         for i in range(100):
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             client_ids.append(client_id)
-        
+
         assert len(sse_manager.clients) == initial_clients + 100
-        
+
         # 全クライアントを削除
         for client_id in client_ids:
             sse_manager.remove_client(client_id)
-        
+
         assert len(sse_manager.clients) == initial_clients
-    
+
     def test_sse_concurrent_broadcast_stress(self, sse_manager):
         """SSE同時ブロードキャストストレステスト"""
         # 複数クライアントを登録
@@ -63,7 +65,7 @@ class TestSSELongevity:
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             clients.append((client_id, mock_client))
-        
+
         # 複数スレッドから同時ブロードキャスト
         def broadcast_worker(worker_id):
             for i in range(10):
@@ -71,203 +73,189 @@ class TestSSELongevity:
                     "type": "stress_test",
                     "worker_id": worker_id,
                     "message_id": i,
-                    "data": f"message_{worker_id}_{i}"
+                    "data": f"message_{worker_id}_{i}",
                 }
                 sse_manager.broadcast(message)
                 time.sleep(0.01)  # 短い間隔
-        
+
         # 5つのワーカースレッドを起動
         threads = []
         for worker_id in range(5):
             thread = threading.Thread(target=broadcast_worker, args=(worker_id,))
             threads.append(thread)
             thread.start()
-        
+
         # 全スレッドの完了を待機
         for thread in threads:
             thread.join()
-        
+
         # 全クライアントが適切に呼び出されたことを確認
         for client_id, mock_client in clients:
             assert mock_client.put.call_count >= 10  # 最低10回は呼び出される
-    
+
     def test_sse_client_error_recovery(self, sse_manager):
         """SSEクライアントエラー回復テスト"""
         # 正常なクライアントと異常なクライアントを混在
         normal_clients = []
         error_clients = []
-        
+
         # 正常なクライアント
         for i in range(5):
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             normal_clients.append((client_id, mock_client))
-        
+
         # エラーを発生させるクライアント
         for i in range(3):
             mock_client = MagicMock()
             mock_client.put.side_effect = Exception("Client error")
             client_id = sse_manager.add_client(mock_client)
             error_clients.append((client_id, mock_client))
-        
+
         initial_client_count = len(sse_manager.clients)
-        
+
         # ブロードキャスト実行
         sse_manager.broadcast({"type": "error_test", "data": "test"})
-        
+
         # エラークライアントが削除され、正常クライアントは残ることを確認
         assert len(sse_manager.clients) == len(normal_clients)
-        
+
         # 正常クライアントは呼び出されている
         for client_id, mock_client in normal_clients:
             mock_client.put.assert_called_once()
-    
+
     def test_sse_high_frequency_messages(self, sse_manager):
         """SSE高頻度メッセージテスト"""
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         # 高頻度でメッセージを送信
         message_count = 1000
         start_time = time.time()
-        
+
         for i in range(message_count):
-            message = {
-                "type": "high_frequency",
-                "sequence": i,
-                "timestamp": time.time()
-            }
+            message = {"type": "high_frequency", "sequence": i, "timestamp": time.time()}
             sse_manager.broadcast(message)
-        
+
         end_time = time.time()
         duration = end_time - start_time
-        
+
         # パフォーマンス確認
         assert duration < 5.0  # 5秒以内に完了
         assert mock_client.put.call_count == message_count
-        
+
         print(f"高頻度メッセージテスト: {message_count}メッセージを{duration:.2f}秒で処理")
-    
+
     def test_sse_large_message_handling(self, sse_manager):
         """SSE大容量メッセージハンドリングテスト"""
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         # 大容量メッセージを作成
         large_data = {
             "type": "large_message",
             "data": {
                 "large_array": list(range(10000)),
                 "large_string": "x" * 50000,
-                "nested_data": {
-                    "level1": {
-                        "level2": {
-                            "level3": ["data"] * 1000
-                        }
-                    }
-                }
-            }
+                "nested_data": {"level1": {"level2": {"level3": ["data"] * 1000}}},
+            },
         }
-        
+
         # 大容量メッセージのブロードキャスト
         start_time = time.time()
         sse_manager.broadcast(large_data)
         end_time = time.time()
-        
+
         # パフォーマンスと正常性を確認
         assert end_time - start_time < 1.0  # 1秒以内に完了
         mock_client.put.assert_called_once()
-        
+
         # 呼び出されたメッセージの内容を確認
         called_message = mock_client.put.call_args[0][0]
-        assert called_message['type'] == 'large_message'
-        assert len(called_message['data']['large_array']) == 10000
-    
+        assert called_message["type"] == "large_message"
+        assert len(called_message["data"]["large_array"]) == 10000
+
     def test_sse_unicode_message_handling(self, sse_manager):
         """SSE Unicode メッセージハンドリングテスト"""
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         # 様々なUnicodeメッセージをテスト
         unicode_messages = [
             {"type": "japanese", "data": "こんにちは世界 🌍"},
             {"type": "chinese", "data": "你好世界 🇨🇳"},
             {"type": "arabic", "data": "مرحبا بالعالم 🌙"},
             {"type": "emoji", "data": "🚀🎉🔥💯⭐🌟✨🎯"},
-            {"type": "mixed", "data": "Hello 世界 🌍 مرحبا 你好"}
+            {"type": "mixed", "data": "Hello 世界 🌍 مرحبا 你好"},
         ]
-        
+
         for message in unicode_messages:
             sse_manager.broadcast(message)
             mock_client.put.assert_called()
-            
+
             # 呼び出されたメッセージの内容を確認
             called_message = mock_client.put.call_args[0][0]
-            assert called_message['type'] == message['type']
-            assert called_message['data'] == message['data']
-            
+            assert called_message["type"] == message["type"]
+            assert called_message["data"] == message["data"]
+
             mock_client.reset_mock()
-    
+
     @pytest.mark.slow
     def test_sse_extended_connection_simulation(self, sse_manager):
         """SSE拡張接続シミュレーションテスト"""
         # 長時間接続をシミュレート
         connection_duration = 30  # 30秒間のテスト
         message_interval = 1  # 1秒間隔
-        
+
         mock_client = MagicMock()
         client_id = sse_manager.add_client(mock_client)
-        
+
         start_time = time.time()
         message_count = 0
-        
+
         while time.time() - start_time < connection_duration:
-            message = {
-                "type": "heartbeat",
-                "timestamp": time.time(),
-                "sequence": message_count
-            }
+            message = {"type": "heartbeat", "timestamp": time.time(), "sequence": message_count}
             sse_manager.broadcast(message)
             message_count += 1
             time.sleep(message_interval)
-        
+
         # 接続が維持され、メッセージが正常に送信されたことを確認
         assert mock_client.put.call_count == message_count
         assert message_count >= connection_duration / message_interval - 1
-        
+
         print(f"拡張接続テスト: {connection_duration}秒間で{message_count}メッセージを送信")
-    
+
     def test_sse_stats_accuracy(self, sse_manager):
         """SSE統計情報精度テスト"""
         initial_stats = sse_manager.get_stats()
         initial_time = time.time()
-        
+
         # クライアントを追加
         clients = []
         for i in range(10):
             mock_client = MagicMock()
             client_id = sse_manager.add_client(mock_client)
             clients.append(client_id)
-        
+
         # 統計情報を確認
         stats = sse_manager.get_stats()
-        assert stats['connected_clients'] == 10
-        assert stats['status'] == 'healthy'
-        assert stats['uptime'] >= 0
-        
+        assert stats["connected_clients"] == 10
+        assert stats["status"] == "healthy"
+        assert stats["uptime"] >= 0
+
         # 時間経過を確実にするため少し待機
         time.sleep(0.1)
-        
+
         # 一部クライアントを削除
         for i in range(5):
             sse_manager.remove_client(clients[i])
-        
+
         # 統計情報の更新を確認
         updated_stats = sse_manager.get_stats()
-        assert updated_stats['connected_clients'] == 5
-        assert updated_stats['uptime'] >= stats['uptime']  # 等しいか大きい
+        assert updated_stats["connected_clients"] == 5
+        assert updated_stats["uptime"] >= stats["uptime"]  # 等しいか大きい
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     # テスト実行（slowマークのテストは除外）
-    pytest.main([__file__, '-v', '--tb=short', '-m', 'not slow'])
\ No newline at end of file
+    pytest.main([__file__, "-v", "--tb=short", "-m", "not slow"])
```

UI-Audit Pointers
-----------------
- Lighthouse & LCP/CLS reports: artifacts/ui_audit/ or observability/ui/report/
- Linkinator results: artifacts/ui_audit/links/ (if split) or artifacts/ui_audit/
- Playwright artifacts: screenshots/, traces/ and playwright-report/

Rollback Guidance
-----------------
- If this change was committed but not pushed:
  - git restore . && git clean -fd
- If this change was pushed in a single commit:
  - git revert <commit-sha>
- If multiple commits:
  - git revert --no-commit <oldest>^..<newest> && git commit -m "Revert range"

Notes
-----
- Ensure CI multi-layered guards (Playwright/Lighthouse/Linkinator) are green.
- Ensure Design-UI/Web-Verify approval before merging UI-affecting changes.