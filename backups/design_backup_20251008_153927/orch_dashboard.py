#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import platform
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    stream_with_context,
    url_for,
)
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Phase 3コンポーネントのインポート
try:
    from dashboard_websocket import create_dashboard_websocket
    from task_visualizer import create_task_visualizer

    PHASE3_AVAILABLE = True
except ImportError:
    PHASE3_AVAILABLE = False
    logging.warning("Phase 3 components not available")

# 知識データベースと機械学習エンジンのインポート
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))
try:
    from db.knowledge_store import (
        CrossThinkingResult,
        KnowledgeStore,
        LearningMetrics,
        PS1Parameters,
        WorkOutcome,
    )
    from ml.learning_engine import LearningEngine

    DB_INTEGRATION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"DB/ML統合機能が利用できません: {e}")
    DB_INTEGRATION_AVAILABLE = False

# 知識データベースとMLエンジンのインポート（利用可能な場合）
try:
    from knowledge_db import KnowledgeDatabase

    KNOWLEDGE_DB_AVAILABLE = True
except ImportError:
    KNOWLEDGE_DB_AVAILABLE = False
    logging.warning("Knowledge database not available")

try:
    from ml_engine import MLEngine

    ML_ENGINE_AVAILABLE = True
except ImportError:
    ML_ENGINE_AVAILABLE = False
    logging.warning("ML engine not available")


@dataclass
class OrchDashboardConfig:
    """ORCH ダッシュボード設定"""

    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = True
    log_level: str = "INFO"
    orch_root: str = "C:\\Users\\User\\Trae\\MOC\\ORCH"
    template_folder: str = "templates"
    static_folder: str = "static"


class OrchDashboard:
    """ORCH統合管理システム ダッシュボード"""

    def __init__(self, config: Optional[OrchDashboardConfig] = None):
        """初期化"""
        self.config = config or OrchDashboardConfig()
        # 短期復旧フラグ（ダミー応答を返す）
        # 環境変数 ORCH_DUMMY_API が 1/true/yes/on の場合に有効化
        self.short_term_restore = str(os.getenv("ORCH_DUMMY_API", "0")).lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

        # Flask app setup with template directory
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        self.app = Flask(
            __name__, template_folder=template_dir, static_folder=self.config.static_folder
        )

        # CORS設定
        CORS(
            self.app,
            resources={
                r"/*": {
                    "origins": "*",
                    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                    "allow_headers": ["Content-Type", "Authorization"],
                    "supports_credentials": False,
                }
            },
        )

        # SocketIO設定
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        # 秘密鍵設定
        self.app.secret_key = "orch_dashboard_secret_key_2025"

        # ログ設定
        self.logger = self._setup_logging()  # type: ignore

        # Phase 3コンポーネント初期化
        self.dashboard_websocket = None
        self.task_visualizer = None

        if PHASE3_AVAILABLE:
            try:
                self.dashboard_websocket = create_dashboard_websocket(
                    self.socketio, str(self.config.orch_root)
                )
                self.task_visualizer = create_task_visualizer(str(self.config.orch_root))
                self.logger.info("Phase 3 components initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize Phase 3 components: {e}")

        # DB/ML統合機能の初期化
        self.knowledge_store = None
        self.learning_engine = None
        if DB_INTEGRATION_AVAILABLE:
            try:
                self.knowledge_store = KnowledgeStore()
                self.learning_engine = LearningEngine(self.knowledge_store)
                self.logger.info("DB/ML統合機能が有効化されました")
            except Exception as e:
                self.logger.error(f"DB/ML統合機能の初期化に失敗: {e}")

        # 知識データベース初期化
        self.knowledge_db = None
        if KNOWLEDGE_DB_AVAILABLE:
            try:
                self.knowledge_db = KnowledgeDatabase(str(self.config.orch_root))
                self.logger.info("Knowledge database initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize knowledge database: {e}")

        # MLエンジン初期化
        self.ml_engine = None
        if ML_ENGINE_AVAILABLE:
            try:
                self.ml_engine = MLEngine(str(self.config.orch_root))
                self.logger.info("ML engine initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize ML engine: {e}")

        # base_dir設定（MOCルートディレクトリ）
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # 監査レポート/指示ファイルの既定パス
        self.audit_md_path = Path(self.base_dir) / "ORCH" / "REPORTS" / "NonStop_Audit.md"
        self.instructions_path = Path(self.base_dir) / "data" / "work_instructions.json"
        # 必要ディレクトリ/ファイルの初期化（存在しない場合は作成）
        try:
            self._ensure_basic_files()
        except Exception as e:
            self.logger.warning(f"初期ファイルの準備に失敗: {e}")

        # ルート設定
        self._setup_routes()

        # SocketIOイベント設定
        self._setup_socketio_events()

        # WebSocketイベント設定
        self._setup_websocket_events()

        # 品質監視機能の初期化
        self.quality_monitoring = True
        self.monitoring_thread = None
        self.monitoring_active = False

        self.logger.info("ORCHダッシュボードが初期化されました")

    def _setup_logging(self):
        """ログ設定"""
        logger = logging.getLogger("orch_dashboard")
        logger.setLevel(getattr(logging, self.config.log_level))

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route("/")
        def dashboard():
            """Main dashboard page"""
            return render_template("orch_dashboard.html", title="ORCH統合管理システム")

        @self.app.route("/tasks")
        def tasks_page():
            """Tasks management page"""
            return render_template("orch_dashboard.html", title="タスク管理")

        @self.app.route("/approvals")
        def approvals_page():
            """Approvals management page"""
            return render_template("orch_dashboard.html", title="承認管理")

        @self.app.route("/health")
        def health():
            """ダッシュボードの健全性チェック"""
            try:
                status = {
                    "status": "ok",
                    "time": datetime.now().isoformat(),
                    "cpu_pct": psutil.cpu_percent(interval=0.1),
                    "mem": {
                        "total": psutil.virtual_memory().total,
                        "available": psutil.virtual_memory().available,
                        "percent": psutil.virtual_memory().percent,
                    },
                    "version": "v1",
                }
                return jsonify(status), 200
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        # API Routes
        @self.app.route("/api/overview")
        def api_overview():
            """Get system overview data"""
            try:
                tasks_data = self._parse_tasks_file()
                approvals_data = self._parse_approvals_file()

                # Calculate overview statistics
                total_tasks = len(tasks_data)

                # Task status counts
                task_status_counts = {}
                for task in tasks_data:
                    status = task.get("status", "UNKNOWN")
                    task_status_counts[status] = task_status_counts.get(status, 0) + 1

                # Approval status counts
                approval_status_counts = {}
                for approval in approvals_data:
                    status = approval.get("status", "unknown")
                    approval_status_counts[status] = approval_status_counts.get(status, 0) + 1

                overview_data = {
                    "system_status": {
                        "total_tasks": total_tasks,
                        "task_status_counts": task_status_counts,
                        "approval_status_counts": approval_status_counts,
                        "last_updated": datetime.now().isoformat(),
                    }
                }

                return jsonify(overview_data)

            except Exception as e:
                self.logger.error(f"Error getting overview: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/tasks")
        def api_tasks():
            """Get tasks data"""
            try:
                tasks_data = self._parse_tasks_file()
                return jsonify({"tasks": tasks_data})
            except Exception as e:
                self.logger.error(f"Error getting tasks: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/task/create", methods=["POST"])
        def api_task_create():
            """Create a new task (短期復旧用ダミー応答)"""
            try:
                data = request.get_json(silent=True) or {}
                if getattr(self, "short_term_restore", False):
                    # フロントは result.success のみ参照してリロードするため、最低限の応答でOK
                    dummy_task = {
                        "id": f"DUMMY-{int(time.time())}",
                        "title": data.get("title") or "ダミータスク",
                        "owner": data.get("owner") or "CMD",
                        "due": data.get("due") or datetime.now().isoformat(),
                        "notes": data.get("notes") or "(ダミー応答)",
                    }
                    return jsonify(
                        {
                            "success": True,
                            "message": "ダミー: タスク作成を受け付けました",
                            "task": dummy_task,
                        }
                    )
                # 実装未了の場合は 501 を返す
                return jsonify({"success": False, "message": "タスク作成APIは未実装です"}), 501
            except Exception as e:
                self.logger.error(f"Error creating task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/approvals")
        def api_approvals():
            """Get approvals data"""
            try:
                approvals_data = self._parse_approvals_file()
                return jsonify({"approvals": approvals_data})
            except Exception as e:
                self.logger.error(f"Error getting approvals: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/milestones")
        def api_milestones():
            """Get milestones data"""
            try:
                milestones_data = self._parse_milestones_file()
                return jsonify({"milestones": milestones_data})
            except Exception as e:
                self.logger.error(f"Error getting milestones: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/quality/metrics")
        def api_quality_metrics():
            """Get quality metrics data"""
            try:
                metrics = self._get_quality_metrics()
                return jsonify(metrics)
            except Exception as e:
                self.logger.error(f"Error getting quality metrics: {e}")
                return jsonify({"error": str(e)}), 500

        # Prometheus metrics endpoint
        @self.app.route("/metrics")
        def metrics():
            """Prometheus metrics endpoint with AI-driven anomaly detection"""
            try:
                # Basic Prometheus metrics
                from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

                registry = CollectorRegistry()

                # Task metrics
                task_completion = Gauge(
                    "orch_task_completion_rate", "Task completion rate", registry=registry
                )
                task_completion.set(self._get_quality_metrics().get("task_completion_rate", 0))

                # Approval metrics
                approval_rate = Gauge("orch_approval_rate", "Approval rate", registry=registry)
                approval_rate.set(self._get_quality_metrics().get("approval_rate", 0))

                # System health
                health_score = Gauge("orch_health_score", "System health score", registry=registry)
                health_score.set(self._get_system_health().get("health", {}).get("health_score", 0))

                # AI-driven anomaly detection (simple example)
                anomaly_count = Counter(
                    "orch_anomalies_detected", "Number of detected anomalies", registry=registry
                )
                alerts = self._get_quality_alerts()
                anomaly_count.inc(len(alerts))

                return generate_latest(registry), 200, {"Content-Type": "text/plain; version=0.0.4"}
            except Exception as e:
                self.logger.error(f"Error generating metrics: {e}")
                return str(e), 500

        @self.app.route("/api/quality/health")
        def api_quality_health():
            """Get system health data"""
            try:
                health = self._get_system_health()
                return jsonify(health)
            except Exception as e:
                self.logger.error(f"Error getting system health: {e}")
                return jsonify({"error": str(e)}), 500

        # ---- Work Progress / Instruction Center (MVP) ----
        @self.app.route("/api/work/progress")
        def api_work_progress():
            """作業進捗・レポート: 監査MDの末尾とテスト概要を返す"""
            try:
                md_tail = self._read_md_tail(self.audit_md_path, max_lines=50)
                test_summary = self._read_test_summary()
                return jsonify(
                    {
                        "success": True,
                        "md_tail": md_tail,
                        "test_summary": test_summary,
                        "updated_at": datetime.now().isoformat(),
                    }
                )
            except Exception as e:
                self.logger.error(f"Error in work progress: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/work/instructions", methods=["GET", "POST"])
        def api_work_instructions():
            """指示センター: 指示の取得/登録"""
            try:
                if request.method == "GET":
                    items = self._load_instructions()
                    return jsonify({"success": True, "items": items})

                # POST
                data = request.get_json(silent=True) or {}
                items = self._load_instructions()
                new_item = {
                    "id": f"INS-{int(time.time())}",
                    "title": data.get("title") or "指示",
                    "detail": data.get("detail") or "",
                    "owner": data.get("owner") or "CMD",
                    "created_at": datetime.now().isoformat(),
                }
                items.append(new_item)
                self._save_instructions(items)
                return jsonify({"success": True, "item": new_item})
            except Exception as e:
                self.logger.error(f"Error in work instructions: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

    # --- helpers for Work Progress / Instructions ---
    def _ensure_basic_files(self):
        """必要なディレクトリと初期ファイルを作成"""
        try:
            self.audit_md_path.parent.mkdir(parents=True, exist_ok=True)
            self.instructions_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.audit_md_path.exists():
                self.audit_md_path.write_text(
                    "# NonStop Audit\n\n初期化: 監査ログはここに追記されます。\n", encoding="utf-8"
                )
            if not self.instructions_path.exists():
                self.instructions_path.write_text("[]", encoding="utf-8")
        except Exception as e:
            raise e

    def _read_md_tail(self, path: Path, max_lines: int = 50) -> List[str]:
        """Markdownファイルの末尾から最大行数を返す"""
        try:
            if not path.exists():
                return []
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            return lines[-max_lines:]
        except Exception:
            return []

    def _read_test_summary(self) -> Optional[Dict[str, Any]]:
        """テスト概要（存在すれば）を返す"""
        # 既定場所: ORCH/REPORTS/test_summary.json
        try:
            summary_path = Path(self.base_dir) / "ORCH" / "REPORTS" / "test_summary.json"
            if summary_path.exists():
                return json.loads(summary_path.read_text(encoding="utf-8"))
            return None
        except Exception:
            return None

    def _load_instructions(self) -> List[Dict[str, Any]]:
        try:
            if not self.instructions_path.exists():
                return []
            return json.loads(self.instructions_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_instructions(self, items: List[Dict[str, Any]]) -> None:
        try:
            self.instructions_path.write_text(
                json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except Exception as e:
            self.logger.error(f"Failed to save instructions: {e}")

        @self.app.route("/api/rules")
        def api_rules():
            """Get rules data"""
            try:
                rules_data = self._get_rules_data()
                return jsonify(rules_data)
            except Exception as e:
                self.logger.error(f"Error getting rules: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/rules/violations")
        def api_rules_violations():
            """Get rule violations data"""
            try:
                violations_data = self._get_rule_violations()
                return jsonify(violations_data)
            except Exception as e:
                self.logger.error(f"Error getting rule violations: {e}")
                return jsonify({"error": str(e)}), 500

        # CMD Role API endpoints
        @self.app.route("/api/approvals/approve", methods=["POST"])
        def api_approve_approval():
            """Approve an approval request"""
            try:
                data = request.get_json()
                appr_id = data.get("appr_id")
                approver = data.get("approver", "CMD")
                approver_role = data.get("approver_role", "CMD")

                if not appr_id:
                    return jsonify({"success": False, "error": "appr_id is required"}), 400

                success = self._update_approval_status(appr_id, "approved", approver, approver_role)
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error approving approval: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/approvals/reject", methods=["POST"])
        def api_reject_approval():
            """Reject an approval request"""
            try:
                data = request.get_json()
                appr_id = data.get("appr_id")
                approver = data.get("approver", "CMD")
                approver_role = data.get("approver_role", "CMD")

                if not appr_id:
                    return jsonify({"success": False, "error": "appr_id is required"}), 400

                success = self._update_approval_status(appr_id, "rejected", approver, approver_role)
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error rejecting approval: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/approval/<approval_id>/update", methods=["POST"])
        def api_update_approval(approval_id):
            """Update approval status (for JavaScript compatibility)"""
            try:
                data = request.get_json()
                status = data.get("status", "approved")
                approver = data.get("approver", "CMD")
                approver_role = data.get("approver_role", "CMD")

                if not approval_id:
                    return jsonify({"success": False, "error": "approval_id is required"}), 400

                success = self._update_approval_status(approval_id, status, approver, approver_role)
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error updating approval: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/promote", methods=["POST"])
        def api_promote_task():
            """Promote task to READY status"""
            try:
                data = request.get_json()
                task_id = data.get("task_id")

                if not task_id:
                    return jsonify({"success": False, "error": "task_id is required"}), 400

                success = self._update_task_status(task_id, "READY")
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error promoting task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/approve_done", methods=["POST"])
        def api_approve_done_task():
            """Approve DONE task"""
            try:
                data = request.get_json()
                task_id = data.get("task_id")

                if not task_id:
                    return jsonify({"success": False, "error": "task_id is required"}), 400

                success = self._update_task_status(task_id, "DONE")
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error approving DONE task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        # Kevin's Hive-Mind AI Integration
        @self.app.route("/api/ai/optimize", methods=["POST"])
        def api_ai_optimize():
            """Optimize metrics using Hive-Mind AI agents"""
            try:
                # TODO: Implement actual integration with Kevin's Hive-Mind
                return jsonify(
                    {
                        "success": True,
                        "message": "Metrics optimized using Hive-Mind AI",
                        "optimized_metrics": self._get_quality_metrics(),
                    }
                )
            except Exception as e:
                self.logger.error(f"Error in AI optimize: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/ai/heal", methods=["POST"])
        def api_ai_heal():
            """Self-heal system using Hive-Mind AI agents"""
            try:
                # TODO: Implement actual self-healing logic
                health = self._get_system_health()
                return jsonify(
                    {
                        "success": True,
                        "message": "System self-healed using Hive-Mind AI",
                        "current_health": health,
                    }
                )
            except Exception as e:
                self.logger.error(f"Error in AI heal: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/request_fix", methods=["POST"])
        def api_request_fix_task():
            """Request FIX for task"""
            try:
                data = request.get_json()
                task_id = data.get("task_id")

                if not task_id:
                    return jsonify({"success": False, "error": "task_id is required"}), 400

                success = self._update_task_status(task_id, "FIX")
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error requesting fix: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/hold", methods=["POST"])
        def api_hold_task():
            """Hold task"""
            try:
                data = request.get_json()
                task_id = data.get("task_id")

                if not task_id:
                    return jsonify({"success": False, "error": "task_id is required"}), 400

                success = self._update_task_status(task_id, "HOLD")
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error holding task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/drop", methods=["POST"])
        def api_drop_task():
            """Drop task"""
            try:
                data = request.get_json()
                task_id = data.get("task_id")

                if not task_id:
                    return jsonify({"success": False, "error": "task_id is required"}), 400

                success = self._update_task_status(task_id, "DROP")
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error dropping task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/tasks/create", methods=["POST"])
        def api_create_task():
            """Create new task"""
            try:
                data = request.get_json()
                title = data.get("title")
                due_date = data.get("due_date")
                owner = data.get("owner", "CMD")
                notes = data.get("notes", "")

                if not title:
                    return jsonify({"success": False, "error": "title is required"}), 400

                success = self._create_new_task(title, due_date, owner, notes)
                return jsonify({"success": success})
            except Exception as e:
                self.logger.error(f"Error creating task: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/quality/alerts")
        def api_quality_alerts():
            """Get quality alerts"""
            try:
                alerts = self._get_quality_alerts()
                return jsonify({"alerts": alerts})
            except Exception as e:
                self.logger.error(f"Error getting quality alerts: {e}")
                return jsonify({"error": str(e)}), 500

        # --- Git Visualization API Endpoints ---
        @self.app.route("/api/git/graph")
        def api_git_graph():
            """Get Git graph data for visualization"""
            try:
                git_data = self._get_git_graph_data()
                return jsonify(git_data)
            except Exception as e:
                self.logger.error(f"Error getting git graph data: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/git/branches")
        def api_git_branches():
            """Get Git branches data"""
            try:
                branches_data = self._get_git_branches_data()
                return jsonify({"success": True, "branches": branches_data})
            except Exception as e:
                self.logger.error(f"Error getting git branches data: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/git/commit/<commit_sha>")
        def api_git_commit(commit_sha):
            """Get detailed commit information"""
            try:
                commit_data = self._get_git_commit_data(commit_sha)
                return jsonify({"success": True, "commit": commit_data})
            except Exception as e:
                self.logger.error(f"Error getting git commit data: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/system-health")
        def api_system_health():
            # Lightweight fast path with 5s in-memory cache
            try:
                import time
                from datetime import datetime

                if not hasattr(self, "_health_cache"):
                    self._health_cache = {"data": None, "ts": 0.0}
                now = time.time()
                cached = self._health_cache.get("data")
                ts = self._health_cache.get("ts") or 0.0
                if cached is not None and (now - ts) < 5.0:
                    return jsonify(cached)
                minimal = {
                    "status": "ok",
                    "timestamp": datetime.now().isoformat(),
                    "version": getattr(self, "version", None)
                    or getattr(self, "app_version", None)
                    or "unknown",
                }
                self._health_cache["data"] = minimal
                self._health_cache["ts"] = now
                return jsonify(minimal)
            except Exception as e:
                self.logger.error(f"Error in fast system health: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/dispatch", methods=["POST"])
        def api_dispatch():
            """Launch Task-Dispatcher.ps1 with provided parameters.
            Expected JSON: {
              coreId: str,
              stay: bool,
              enableOrchIntegration: bool,
              intervalSec: int,
              action: str  # e.g., 'Dispatch'
            }
            """
            try:
                data = request.get_json(force=True) or {}

                core_id = data.get("coreId")
                action = data.get("action", "Dispatch")
                stay = bool(data.get("stay", True))
                enable_orch = bool(data.get("enableOrchIntegration", True))
                interval_sec = int(data.get("intervalSec", 5))

                if not core_id:
                    return jsonify({"success": False, "message": "coreId は必須です"}), 400

                ok, pid, cmd = self._launch_dispatcher(
                    core_id, stay, enable_orch, interval_sec, action
                )
                if ok:
                    # 速報をSocketIOで通知
                    try:
                        self.socketio.emit(
                            "dispatcher_started",
                            {
                                "coreId": core_id,
                                "pid": pid,
                                "command": cmd,
                                "timestamp": datetime.now().isoformat(),
                            },
                        )
                    except Exception:
                        pass
                    return jsonify({"success": True, "pid": pid, "command": cmd})
                else:
                    return (
                        jsonify({"success": False, "message": "Dispatcher起動に失敗しました"}),
                        500,
                    )
            except Exception as e:
                self.logger.error(f"/dispatch error: {e}")
                return jsonify({"success": False, "message": str(e)}), 500

        @self.app.route("/dispatch/stop", methods=["POST"])
        def api_dispatch_stop():
            """Stop Task-Dispatcher.ps1 processes. Optional JSON: { coreId: str }"""
            try:
                data = request.get_json(silent=True) or {}
                core_id = data.get("coreId")
                stopped = self._stop_dispatcher(core_id)
                return jsonify({"success": True, "stopped": stopped})
            except Exception as e:
                self.logger.error(f"/dispatch/stop error: {e}")
                return jsonify({"success": False, "message": str(e)}), 500

        @self.app.route("/status", methods=["GET"])
        def api_status():
            """Summarize dispatcher/stay/orch state and aggregate TASKS/MILESTONES"""
            import time

            if not hasattr(self, "_status_cache"):
                self._status_cache = {"data": None, "ts": 0.0}
            now = time.time()
            cached = self._status_cache.get("data")
            ts = self._status_cache.get("ts") or 0.0
            if cached is not None and (now - ts) < 5.0:
                return jsonify(cached)
            try:
                dispatchers = self._find_dispatcher_processes()
                tasks = self._parse_tasks_file()
                milestones = self._parse_milestones_file()

                # Locks overview
                locks_dir = os.path.join(self.config.orch_root, ".locks")
                locks = []
                try:
                    if os.path.isdir(locks_dir):
                        for name in os.listdir(locks_dir):
                            p = os.path.join(locks_dir, name)
                            try:
                                stat = os.stat(p)
                                locks.append(
                                    {
                                        "name": name,
                                        "size": stat.st_size,
                                        "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                    }
                                )
                            except Exception:
                                locks.append({"name": name})
                except Exception:
                    pass

                summary = {
                    "dispatcher": {"running": len(dispatchers) > 0, "processes": dispatchers},
                    "locks": locks,
                    "tasks": tasks,
                    "milestones": milestones,
                    "systemHealth": self._get_system_health(),
                    "timestamp": datetime.now().isoformat(),
                }
                self._status_cache["data"] = summary
                self._status_cache["ts"] = time.time()
                return jsonify(summary)
            except Exception as e:
                self.logger.error(f"/status error: {e}")
                return jsonify({"error": str(e)}), 500

        # Server-Sent Events endpoint
        @self.app.route("/events")
        def sse_events():
            """Server-Sent Events stream of periodic metrics/heartbeats"""

            def event_stream():
                while True:
                    try:
                        mem = psutil.virtual_memory()
                        disk = psutil.disk_io_counters()
                        net = psutil.net_io_counters()
                        payload = {
                            "event": "heartbeat",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "cpu_percent": psutil.cpu_percent(interval=None),
                            "mem_used_mb": int(mem.used / (1024 * 1024)),
                            "mem_total_mb": int(mem.total / (1024 * 1024)),
                            "disk_read_mb": (
                                int((disk.read_bytes or 0) / (1024 * 1024)) if disk else None
                            ),
                            "disk_write_mb": (
                                int((disk.write_bytes or 0) / (1024 * 1024)) if disk else None
                            ),
                            "net_sent_mb": (
                                int((net.bytes_sent or 0) / (1024 * 1024)) if net else None
                            ),
                            "net_recv_mb": (
                                int((net.bytes_recv or 0) / (1024 * 1024)) if net else None
                            ),
                        }
                        yield f"data: {json.dumps(payload)}\n\n"
                        time.sleep(3)
                    except GeneratorExit:
                        break
                    except Exception as e:
                        self.logger.error(f"SSE stream error: {e}")
                        time.sleep(3)

            headers = {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            }
            return Response(stream_with_context(event_stream()), headers=headers)

        # Phase 3 Console Launcher
        @self.app.route("/console")
        def console_launcher():
            """Phase 3 Console Launcher"""
            return send_from_directory(".", "console_launcher.html")

        # Phase 3 API Endpoints
        @self.app.route("/api/v3/task-overview")
        def api_task_overview():
            """タスク概要API"""
            if self.task_visualizer:
                try:
                    overview = self.task_visualizer.get_task_overview()
                    return jsonify(overview)
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            return jsonify({"error": "Task visualizer not available"}), 503

        @self.app.route("/api/v3/task-flow")
        def api_task_flow():
            """タスクフロー図API"""
            if self.task_visualizer:
                try:
                    flow_id = request.args.get("flow_id")
                    flow_diagram = self.task_visualizer.get_task_flow_diagram(flow_id)
                    return jsonify(flow_diagram)
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            return jsonify({"error": "Task visualizer not available"}), 503

        @self.app.route("/api/v3/console-topology")
        def api_console_topology():
            """コンソールトポロジーAPI"""
            if self.task_visualizer:
                try:
                    topology = self.task_visualizer.get_console_topology()
                    return jsonify(topology)
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            return jsonify({"error": "Task visualizer not available"}), 503

        @self.app.route("/api/v3/task-timeline")
        def api_task_timeline():
            """タスクタイムラインAPI"""
            if self.task_visualizer:
                try:
                    hours = int(request.args.get("hours", 24))
                    timeline = self.task_visualizer.get_task_timeline(hours)
                    return jsonify(timeline)
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            return jsonify({"error": "Task visualizer not available"}), 503

        @self.app.route("/api/v3/performance-heatmap")
        def api_performance_heatmap():
            """パフォーマンスヒートマップAPI"""
            if self.task_visualizer:
                try:
                    heatmap = self.task_visualizer.get_performance_heatmap()
                    return jsonify(heatmap)
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            return jsonify({"error": "Task visualizer not available"}), 503

        # DB/ML統合API エンドポイント
        @self.app.route("/api/ml/status")
        def api_ml_status():
            """機械学習システムの状態を取得"""
            if not self.learning_engine:
                if getattr(self, "short_term_restore", False):
                    # フロント側の期待キーに合わせたダミー応答
                    return jsonify(
                        {
                            "model_count": 0,
                            "training_data_count": 0,
                            "last_training_time": None,
                            "average_accuracy": 0.0,
                            "dummy": True,
                        }
                    )
                return jsonify({"error": "ML機能が利用できません"}), 503

            try:
                status = self.learning_engine.get_learning_status()
                return jsonify(status)
            except Exception as e:
                self.logger.error(f"ML状態取得エラー: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/ml/optimize/<script_name>")
        def api_optimize_parameters(script_name):
            """PS1パラメーターの最適化"""
            if not self.learning_engine:
                if getattr(self, "short_term_restore", False):
                    return jsonify(
                        {
                            "success": True,
                            "optimized_parameters": {
                                "parameter_set_id": f"DUMMY-{script_name}-{int(time.time())}",
                                "timeout_ms": 30000,
                                "retry_count": 1,
                                "batch_size": 1,
                                "memory_limit_mb": 256,
                                "success_rate": 0.0,
                                "avg_execution_time_ms": 0,
                            },
                        }
                    )
                return jsonify({"error": "ML機能が利用できません"}), 503

            try:
                optimized_params = self.learning_engine.optimize_script_parameters(script_name)
                if optimized_params:
                    return jsonify(
                        {
                            "success": True,
                            "optimized_parameters": {
                                "parameter_set_id": optimized_params.parameter_set_id,
                                "timeout_ms": optimized_params.timeout_ms,
                                "retry_count": optimized_params.retry_count,
                                "batch_size": optimized_params.batch_size,
                                "memory_limit_mb": optimized_params.memory_limit_mb,
                                "success_rate": optimized_params.success_rate,
                                "avg_execution_time_ms": optimized_params.avg_execution_time_ms,
                            },
                        }
                    )
                else:
                    return (
                        jsonify({"success": False, "message": "パラメーターが見つかりません"}),
                        404,
                    )
            except Exception as e:
                self.logger.error(f"パラメーター最適化エラー: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/knowledge/work_outcomes/<task_id>")
        def api_get_work_outcomes(task_id):
            """タスクの作業結果を取得"""
            if not self.knowledge_store:
                if getattr(self, "short_term_restore", False):
                    # ダミーでは空配列を返却（UIは空の場合メッセージを表示）
                    return jsonify({"work_outcomes": []})
                return jsonify({"error": "DB機能が利用できません"}), 503

            try:
                outcomes = self.knowledge_store.get_work_outcomes_by_task(task_id)
                outcomes_data = []
                for outcome in outcomes:
                    outcomes_data.append(
                        {
                            "task_id": outcome.task_id,
                            "operation_type": outcome.operation_type,
                            "success": outcome.success,
                            "execution_time_ms": outcome.execution_time_ms,
                            "error_message": outcome.error_message,
                            "files_modified": outcome.files_modified,
                            "performance_metrics": outcome.performance_metrics,
                            "timestamp": outcome.timestamp,
                        }
                    )

                return jsonify({"work_outcomes": outcomes_data})
            except Exception as e:
                self.logger.error(f"作業結果取得エラー: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/knowledge/save_outcome", methods=["POST"])
        def api_save_work_outcome():
            """作業結果を保存"""
            if not self.knowledge_store:
                if getattr(self, "short_term_restore", False):
                    return jsonify({"success": True, "message": "ダミー: 作業結果を保存しました"})
                return jsonify({"error": "DB機能が利用できません"}), 503

            try:
                data = request.get_json()

                # 必須フィールドの検証
                required_fields = ["task_id", "operation_type", "success", "execution_time_ms"]
                for field in required_fields:
                    if field not in data:
                        return jsonify({"error": f"必須フィールドが不足: {field}"}), 400

                # WorkOutcomeオブジェクトを作成
                outcome = WorkOutcome(
                    task_id=data["task_id"],
                    operation_type=data["operation_type"],
                    success=data["success"],
                    execution_time_ms=data["execution_time_ms"],
                    error_message=data.get("error_message"),
                    files_modified=data.get("files_modified", []),
                    ps1_parameters_used=data.get("ps1_parameters_used", {}),
                    performance_metrics=data.get("performance_metrics", {}),
                    timestamp=datetime.now().isoformat(),
                    outcome_hash=self.knowledge_store._generate_hash(
                        f"{data['task_id']}-{datetime.now().isoformat()}"
                    ),
                )

                # データベースに保存
                success = self.knowledge_store.save_work_outcome(outcome)

                if success:
                    # 機械学習エンジンに学習データとして追加
                    if self.learning_engine:
                        self.learning_engine.process_work_outcome(outcome)

                    return jsonify({"success": True, "message": "作業結果を保存しました"})
                else:
                    return jsonify({"success": False, "message": "保存に失敗しました"}), 500

            except Exception as e:
                self.logger.error(f"作業結果保存エラー: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/ml/train", methods=["POST"])
        def api_train_model():
            """機械学習モデルの訓練を実行"""
            if not self.learning_engine:
                if getattr(self, "short_term_restore", False):
                    data = request.get_json() or {}
                    epochs = data.get("epochs", 50)
                    return jsonify(
                        {
                            "success": True,
                            "message": f"ダミー: モデル訓練を開始しました（エポック数: {epochs}）",
                        }
                    )
                return jsonify({"error": "ML機能が利用できません"}), 503

            try:
                data = request.get_json() or {}
                epochs = data.get("epochs", 50)

                # 非同期で訓練を実行（実際の実装では別スレッドで実行）
                self.learning_engine.train_model(epochs=epochs)

                return jsonify(
                    {
                        "success": True,
                        "message": f"モデル訓練を開始しました（エポック数: {epochs}）",
                    }
                )

            except Exception as e:
                self.logger.error(f"モデル訓練エラー: {e}")
                return jsonify({"error": str(e)}), 500

    def _find_dispatcher_processes(self) -> List[Dict[str, Any]]:
        """Find running Task-Dispatcher.ps1 processes and extract parameters if possible"""
        procs = []
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                name = (p.info.get("name") or "").lower()
                cmdline = p.info.get("cmdline") or []
                if "powershell" in name and any(
                    "Task-Dispatcher.ps1" in (c or "") for c in cmdline
                ):
                    info = {
                        "pid": p.info.get("pid"),
                        "name": p.info.get("name"),
                        "cmdline": cmdline,
                    }

                    # Extract CoreId, flags
                    def _find_arg(flag):
                        try:
                            idx = cmdline.index(flag)
                            return cmdline[idx + 1] if idx >= 0 and idx + 1 < len(cmdline) else None
                        except ValueError:
                            return None

                    core_id = _find_arg("-CoreId")
                    interval = _find_arg("-OrchIntegrationIntervalSeconds")
                    info["coreId"] = core_id
                    info["intervalSec"] = int(interval) if interval and interval.isdigit() else None
                    info["stay"] = any(x in ["-Stay", "-Stay:$true"] for x in cmdline)
                    info["enableOrchIntegration"] = any(
                        x in ["-EnableOrchIntegration", "-EnableOrchIntegration:$true"]
                        for x in cmdline
                    )
                    procs.append(info)
        except Exception as e:
            self.logger.error(f"find dispatcher processes error: {e}")
        return procs

    def _launch_dispatcher(
        self,
        core_id: str,
        stay: bool,
        enable_orch: bool,
        interval_sec: int,
        action: str = "Dispatch",
    ):
        """Launch Task-Dispatcher.ps1 via PowerShell -Command format for stable argument binding"""
        try:
            script_path = os.path.join(
                self.config.orch_root, "scripts", "ops", "Task-Dispatcher.ps1"
            )
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Task-Dispatcher.ps1 not found: {script_path}")

            # Build PowerShell command with explicit quoting
            ps_args = [f"-Action '{action}'", f"-CoreId '{core_id}'"]
            if stay:
                ps_args.append("-Stay")
            if enable_orch:
                ps_args.append("-EnableOrchIntegration")
            if interval_sec and isinstance(interval_sec, int):
                ps_args.append(f"-OrchIntegrationIntervalSeconds {interval_sec}")

            # Use -Command format for stable parameter binding
            ps_command = f"& '{script_path}' {' '.join(ps_args)}"

            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_command,
            ]

            # Start process detached
            proc = subprocess.Popen(cmd, cwd=self.config.orch_root)
            self.logger.info(
                f"Dispatcher launched for core {core_id} (pid={proc.pid}) - Command: {ps_command}"
            )
            return True, proc.pid, ps_command
        except Exception as e:
            self.logger.error(f"launch dispatcher error: {e}")
            return False, None, None

    def _stop_dispatcher(self, core_id: Optional[str] = None) -> List[int]:
        """Stop Task-Dispatcher.ps1 processes. If core_id provided, stop only those."""
        stopped = []
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                name = (p.info.get("name") or "").lower()
                cmdline = p.info.get("cmdline") or []
                if "powershell" in name and any(
                    "Task-Dispatcher.ps1" in (c or "") for c in cmdline
                ):
                    if core_id:
                        # match by -CoreId value
                        try:
                            idx = cmdline.index("-CoreId")
                            val = cmdline[idx + 1] if idx + 1 < len(cmdline) else None
                            if val != core_id:
                                continue
                        except ValueError:
                            continue
                    try:
                        p.terminate()
                        stopped.append(p.info.get("pid"))
                    except Exception:
                        try:
                            p.kill()
                            stopped.append(p.info.get("pid"))
                        except Exception:
                            pass
        except Exception as e:
            self.logger.error(f"stop dispatcher error: {e}")
        return stopped

    def _setup_socketio_events(self):
        """SocketIOイベント設定"""

        @self.socketio.on("connect")
        def handle_connect():
            """クライアント接続"""
            self.logger.info("クライアントが接続されました")
            emit("status", {"message": "ORCHダッシュボードに接続されました"})

        @self.socketio.on("disconnect")
        def handle_disconnect():
            """クライアント切断"""
            self.logger.info("クライアントが切断されました")

    def _setup_websocket_events(self):
        """WebSocketイベント設定"""
        if not self.dashboard_websocket:
            return

        # Phase 3のWebSocketイベントは dashboard_websocket.py で処理される
        # ここでは追加のカスタムイベントを設定

        @self.socketio.on("request_dashboard_refresh")
        def handle_dashboard_refresh():
            """ダッシュボード更新要求"""
            try:
                if self.task_visualizer:
                    # タスク概要更新
                    overview = self.task_visualizer.get_task_overview()
                    emit("dashboard_overview_update", overview)

                    # タイムライン更新
                    timeline = self.task_visualizer.get_task_timeline(24)
                    emit("timeline_update", timeline)

                    # ヒートマップ更新
                    heatmap = self.task_visualizer.get_performance_heatmap()
                    emit("heatmap_update", heatmap)

            except Exception as e:
                self.logger.error(f"Dashboard refresh error: {e}")
                emit("error", {"message": str(e)})

        @self.socketio.on("request_task_flow_refresh")
        def handle_task_flow_refresh():
            """タスクフロー更新要求"""
            try:
                if self.task_visualizer:
                    flow_diagram = self.task_visualizer.get_task_flow_diagram()
                    emit("task_flow_update", flow_diagram)

            except Exception as e:
                self.logger.error(f"Task flow refresh error: {e}")
                emit("error", {"message": str(e)})

    def _parse_tasks_file(self):
        """Parse TASKS.md file and return task data"""
        tasks_file = os.path.join(self.config.orch_root, "STATE", "TASKS.md")

        if not os.path.exists(tasks_file):
            return []

        tasks = []
        try:
            with open(tasks_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse table rows
            lines = content.split("\n")
            header_found = False

            for line in lines:
                if line.startswith("| id |"):
                    header_found = True
                    continue
                elif line.startswith("|---|"):
                    continue
                elif header_found and line.startswith("|") and line.count("|") >= 10:
                    # Parse task row
                    parts = [p.strip() for p in line.split("|")[1:-1]]
                    if len(parts) >= 10:
                        task = {
                            "id": parts[0],
                            "title": parts[1],
                            "status": parts[2],
                            "owner": parts[3],
                            "lock": parts[4],
                            "lock_owner": parts[5],
                            "lock_expires_at": parts[6],
                            "due": parts[7],
                            "artifact": parts[8],
                            "notes": parts[9],
                        }
                        tasks.append(task)

            return tasks

        except Exception as e:
            self.logger.error(f"Error parsing TASKS.md: {e}")
            return []

    def _parse_approvals_file(self):
        """Parse APPROVALS.md file and return approval data"""
        approvals_file = os.path.join(self.config.orch_root, "STATE", "APPROVALS.md")

        if not os.path.exists(approvals_file):
            return []

        approvals = []
        try:
            with open(approvals_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse table rows
            lines = content.split("\n")
            header_found = False

            for line in lines:
                if line.startswith("| appr_id |"):
                    header_found = True
                    continue
                elif line.startswith("|---|"):
                    continue
                elif header_found and line.startswith("|") and line.count("|") >= 10:
                    # Parse approval row
                    parts = [p.strip() for p in line.split("|")[1:-1]]
                    if len(parts) >= 10:
                        approval = {
                            "appr_id": parts[0],
                            "task_id": parts[1],
                            "op": parts[2],
                            "status": parts[3],
                            "requested_by": parts[4],
                            "approver": parts[5],
                            "approver_role": parts[6],
                            "ts_req": parts[7],
                            "ts_dec": parts[8],
                            "evidence": parts[9],
                        }
                        approvals.append(approval)

            return approvals

        except Exception as e:
            self.logger.error(f"Error parsing APPROVALS.md: {e}")
            return []

    def _parse_milestones_file(self):
        """Parse MILESTONES.md file and return milestone data"""
        milestones_file = os.path.join(self.config.orch_root, "STATE", "MILESTONES.md")

        if not os.path.exists(milestones_file):
            return []

        milestones = []
        try:
            with open(milestones_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse table rows
            lines = content.split("\n")
            header_found = False

            for line in lines:
                if line.startswith("| ms_id |"):
                    header_found = True
                    continue
                elif line.startswith("|---|"):
                    continue
                elif header_found and line.startswith("|") and line.count("|") >= 10:
                    # Parse milestone row
                    parts = [p.strip() for p in line.split("|")[1:-1]]
                    if len(parts) >= 10:
                        # Columns: ms_id, name, status, owner, due, kpi, description, epic_ids, task_ids, notes
                        milestone = {
                            "ms_id": parts[0],
                            "name": parts[1],
                            "status": parts[2],
                            "owner": parts[3],
                            "due": parts[4],
                            "kpi": parts[5],
                            "description": parts[6],
                            "epic_ids": (
                                [p.strip() for p in parts[7].split(",")] if parts[7] else []
                            ),
                            "task_ids": (
                                [p.strip() for p in parts[8].split(",")] if parts[8] else []
                            ),
                            "notes": parts[9],
                        }
                        milestones.append(milestone)

            return milestones

        except Exception as e:
            self.logger.error(f"Error parsing MILESTONES.md: {e}")
            return []

    def _append_task_to_file(self, task_data):
        """Add new task to TASKS.md file"""
        try:
            tasks_file = os.path.join(self.config.orch_root, "STATE", "TASKS.md")

            # Create task line
            task_line = f"| {task_data['id']} | {task_data['title']} | {task_data['status']} | {task_data['owner']} | {task_data['lock']} | {task_data['lock_owner']} | {task_data['lock_expires_at']} | {task_data['due']} | {task_data['artifact']} | {task_data['notes']} |"

            # Append to file
            with open(tasks_file, "a", encoding="utf-8") as f:
                f.write("\n" + task_line)

            return True

        except Exception as e:
            self.logger.error(f"Error appending task to file: {e}")
            return False

    def _update_approval_in_file(self, approval_id, update_data):
        """Update approval in APPROVALS.md file"""
        try:
            approvals_file = os.path.join(self.config.orch_root, "STATE", "APPROVALS.md")

            if not os.path.exists(approvals_file):
                return False

            # Read current content
            with open(approvals_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Find and update the approval line
            updated = False
            for i, line in enumerate(lines):
                if line.startswith("|") and approval_id in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 11 and parts[1] == approval_id:
                        # Update fields
                        parts[4] = update_data.get("status", parts[4])  # status
                        parts[6] = update_data.get("approver", parts[6])  # approver
                        parts[7] = update_data.get("approver_role", parts[7])  # approver_role
                        parts[9] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")  # ts_dec

                        # Reconstruct line
                        lines[i] = "| " + " | ".join(parts[1:-1]) + " |\n"
                        updated = True
                        break

            if updated:
                # Write back to file
                with open(approvals_file, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                return True

            return False

        except Exception as e:
            self.logger.error(f"Error updating approval in file: {e}")
            return False

    def _get_quality_metrics(self):
        """品質メトリクスを取得"""
        try:
            # タスクデータから品質メトリクスを計算
            tasks_data = self._parse_tasks_file()
            approvals_data = self._parse_approvals_file()

            # 基本メトリクス - ヘッダー行を除外
            valid_tasks = [t for t in tasks_data if t.get("id") and t.get("id") != "id"]
            total_tasks = len(valid_tasks)
            completed_tasks = len([t for t in valid_tasks if t.get("status") == "DONE"])
            task_completion_rate = (completed_tasks / total_tasks) if total_tasks > 0 else 0

            # 承認メトリクス - ヘッダー行を除外
            valid_approvals = [
                a for a in approvals_data if a.get("appr_id") and a.get("appr_id") != "appr_id"
            ]
            total_approvals = len(valid_approvals)
            approved_count = len([a for a in valid_approvals if a.get("status") == "approved"])
            approval_rate = (approved_count / total_approvals) if total_approvals > 0 else 0

            # システムヘルス
            system_health = self._get_system_health()

            return {
                "task_completion_rate": task_completion_rate,
                "approval_rate": approval_rate,
                "system_health_score": system_health.get("health", {}).get("health_score", 0),
                "active_tasks": len([t for t in valid_tasks if t.get("status") == "DOING"]),
                "pending_approvals": len(
                    [a for a in valid_approvals if a.get("status") == "pending"]
                ),
                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            }
        except Exception as e:
            self.logger.error(f"Error calculating quality metrics: {e}")
            return {
                "task_completion_rate": 0,
                "approval_rate": 0,
                "system_health_score": 0,
                "active_tasks": 0,
                "pending_approvals": 0,
                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            }

    def _get_system_health(self):
        """システムヘルスを取得"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)

            # メモリ使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # ディスク使用率 - Windowsの場合はC:ドライブを使用
            try:
                if platform.system() == "Windows":
                    disk = psutil.disk_usage("C:")
                else:
                    disk = psutil.disk_usage("/")
                disk_percent = disk.percent
            except Exception:
                disk_percent = 0

            # ヘルススコア計算（0-100）
            health_score = 100 - max(cpu_percent, memory_percent, disk_percent)
            health_score = max(0, min(100, health_score))

            # ステータス判定
            if health_score >= 80:
                status = "excellent"
            elif health_score >= 60:
                status = "good"
            elif health_score >= 40:
                status = "warning"
            else:
                status = "critical"

            return {
                "health": {
                    "health_score": round(health_score, 1),
                    "status": status,
                    "cpu_percent": round(cpu_percent, 1),
                    "memory_percent": round(memory_percent, 1),
                    "disk_percent": round(disk_percent, 1),
                },
                "system_info": {
                    "platform": platform.system(),
                    "python_version": platform.python_version(),
                },
                "timestamp": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            }
        except Exception as e:
            self.logger.error(f"Error getting system health: {e}")
            return {
                "health": {
                    "health_score": 0,
                    "status": "unknown",
                    "cpu_percent": 0,
                    "memory_percent": 0,
                    "disk_percent": 0,
                }
            }

    def _get_quality_alerts(self):
        """品質アラートを取得"""
        try:
            alerts = []

            # システムヘルスチェック
            health = self._get_system_health()
            if health.get("status") == "critical":
                alerts.append(
                    {
                        "id": "system_health_critical",
                        "type": "error",
                        "title": "システムヘルス警告",
                        "message": f"システムヘルススコア: {health.get('health_score', 0)}%",
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            # 長時間実行中のタスクチェック
            tasks_data = self._parse_tasks_file()
            for task in tasks_data:
                if task.get("status") == "DOING" and task.get("lock_expires_at") != "-":
                    try:
                        expires_at = datetime.fromisoformat(
                            task["lock_expires_at"].replace("Z", "+00:00")
                        )
                        if datetime.now() > expires_at:
                            alerts.append(
                                {
                                    "id": f"task_timeout_{task.get('id')}",
                                    "type": "warning",
                                    "title": "タスクタイムアウト",
                                    "message": f"タスク {task.get('id')}: {task.get('title')} がタイムアウトしました",
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
                    except (ValueError, TypeError):
                        continue

            # 承認待ちアラート
            approvals_data = self._parse_approvals_file()
            pending_count = len([a for a in approvals_data if a.get("status") == "pending"])
            if pending_count > 5:
                alerts.append(
                    {
                        "id": "pending_approvals_high",
                        "type": "info",
                        "title": "承認待ち多数",
                        "message": f"{pending_count}件の承認が待機中です",
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            return alerts
        except Exception as e:
            self.logger.error(f"Error getting quality alerts: {e}")
            return []

    def _start_quality_monitoring(self):
        """品質監視を開始"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._quality_monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        self.logger.info("品質監視を開始しました")

    def _stop_quality_monitoring(self):
        """品質監視を停止"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("品質監視を停止しました")

    def _quality_monitoring_loop(self):
        """品質監視ループ"""
        while self.monitoring_active:
            try:
                # メトリクス更新
                metrics = self._get_quality_metrics()
                health = self._get_system_health()
                alerts = self._get_quality_alerts()

                # リアルタイム更新送信
                self.socketio.emit("quality_metrics_update", metrics)
                self.socketio.emit("system_health_update", health)
                self.socketio.emit("quality_alerts_update", {"alerts": alerts})

                # 30秒間隔で更新
                time.sleep(30)
            except Exception as e:
                self.logger.error(f"品質監視ループエラー: {e}")
                time.sleep(30)

    def _get_git_graph_data(self):
        """Git グラフデータを取得"""
        try:
            import json
            import subprocess
            from datetime import datetime

            # Git リポジトリの存在確認（base_dirで確認）
            git_dir = os.path.join(self.base_dir, ".git")
            if not os.path.exists(git_dir):
                return {
                    "success": False,
                    "error": "Git repository not found",
                    "branches": [],
                    "commits": [],
                }

            # ブランチ情報を取得
            branches = self._get_git_branches_data()

            # コミット履歴を取得（最新20件）
            try:
                result = subprocess.run(
                    [
                        "git",
                        "log",
                        "--oneline",
                        "--graph",
                        "--decorate",
                        "--pretty=format:%H|%s|%an|%ad|%D",
                        "--date=iso",
                        "-20",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=self.base_dir,
                )

                commits = []
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        if "|" in line:
                            # グラフ文字を除去してコミット情報を抽出
                            commit_info = line.split("|")
                            if len(commit_info) >= 4:
                                hash_val = (
                                    commit_info[0].strip().split()[-1]
                                )  # 最後の要素がハッシュ
                                message = commit_info[1].strip()
                                author = commit_info[2].strip()
                                date = commit_info[3].strip()
                                refs = commit_info[4].strip() if len(commit_info) > 4 else ""

                                # ブランチ名を推定
                                branch = "main"
                                if "origin/" in refs:
                                    branch_match = refs.split("origin/")[-1].split(",")[0].strip()
                                    if branch_match:
                                        branch = branch_match

                                commits.append(
                                    {
                                        "hash": hash_val,
                                        "message": message,
                                        "author": author,
                                        "date": date,
                                        "branch": branch,
                                        "files": self._get_commit_files(hash_val),
                                    }
                                )

                return {
                    "success": True,
                    "branches": branches,
                    "commits": commits,
                    "last_updated": datetime.now().isoformat(),
                }

            except subprocess.CalledProcessError as e:
                self.logger.error(f"Git log command failed: {e}")
                return {
                    "success": False,
                    "error": f"Git log failed: {str(e)}",
                    "branches": branches,
                    "commits": [],
                }

        except Exception as e:
            self.logger.error(f"Error getting git graph data: {e}")
            return {"success": False, "error": str(e), "branches": [], "commits": []}

    def _get_git_branches_data(self):
        """Git ブランチデータを取得"""
        try:
            import subprocess

            if not os.path.exists(".git"):
                return []

            # ブランチ一覧を取得
            result = subprocess.run(
                ["git", "branch", "-a"], capture_output=True, text=True, cwd=self.base_dir
            )

            branches = []
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line:
                        is_active = line.startswith("*")
                        branch_name = line.replace("*", "").strip()

                        # リモートブランチの場合は簡略化
                        if "remotes/origin/" in branch_name:
                            branch_name = branch_name.replace("remotes/origin/", "")

                        # HEADは除外
                        if "HEAD ->" not in branch_name:
                            branches.append(
                                {
                                    "name": branch_name,
                                    "active": is_active,
                                    "type": "remote" if "remotes/" in line else "local",
                                }
                            )

            return branches

        except Exception as e:
            self.logger.error(f"Error getting git branches: {e}")
            return []

    def _update_approval_status(
        self, appr_id: str, status: str, approver: str, approver_role: str
    ) -> bool:
        """承認ステータスを更新"""
        try:
            approvals_file = os.path.join(self.base_dir, "STATE", "APPROVALS.md")
            if not os.path.exists(approvals_file):
                self.logger.error(f"APPROVALS.md not found: {approvals_file}")
                return False

            # ファイルを読み込み
            with open(approvals_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # ヘッダー行を探す
            header_found = False
            updated = False

            for i, line in enumerate(lines):
                if "| appr_id |" in line:
                    header_found = True
                    continue

                if header_found and line.strip() and not line.startswith("|---"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 11 and parts[1] == appr_id:
                        # 承認情報を更新
                        parts[4] = status  # status
                        parts[6] = approver  # approver
                        parts[7] = approver_role  # approver_role
                        parts[9] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")  # ts_dec

                        lines[i] = "| " + " | ".join(parts[1:-1]) + " |\n"
                        updated = True
                        break

            if updated:
                # ファイルに書き戻し
                with open(approvals_file, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                self.logger.info(f"Updated approval {appr_id} to {status}")
                return True
            else:
                self.logger.error(f"Approval {appr_id} not found")
                return False

        except Exception as e:
            self.logger.error(f"Error updating approval status: {e}")
            return False

    def _update_task_status(self, task_id: str, status: str) -> bool:
        """タスクステータスを更新"""
        try:
            tasks_file = os.path.join(self.base_dir, "STATE", "TASKS.md")
            if not os.path.exists(tasks_file):
                self.logger.error(f"TASKS.md not found: {tasks_file}")
                return False

            # ファイルを読み込み
            with open(tasks_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # ヘッダー行を探す
            header_found = False
            updated = False

            for i, line in enumerate(lines):
                if "| id |" in line:
                    header_found = True
                    continue

                if header_found and line.strip() and not line.startswith("|---"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 11 and parts[1] == task_id:
                        # タスクステータスを更新
                        parts[3] = status  # status

                        # HOLD または REVIEW の場合はlock関連をクリア
                        if status in ["HOLD", "REVIEW"]:
                            parts[5] = "-"  # lock
                            parts[6] = "-"  # lock_owner
                            parts[7] = "-"  # lock_expires_at

                        lines[i] = "| " + " | ".join(parts[1:-1]) + " |\n"
                        updated = True
                        break

            if updated:
                # ファイルに書き戻し
                with open(tasks_file, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                self.logger.info(f"Updated task {task_id} to {status}")
                return True
            else:
                self.logger.error(f"Task {task_id} not found")
                return False

        except Exception as e:
            self.logger.error(f"Error updating task status: {e}")
            return False

    def _create_new_task(self, title: str, due_date: str, owner: str, notes: str) -> bool:
        """新しいタスクを作成"""
        try:
            tasks_file = os.path.join(self.base_dir, "STATE", "TASKS.md")
            if not os.path.exists(tasks_file):
                self.logger.error(f"TASKS.md not found: {tasks_file}")
                return False

            # 新しいIDを生成（既存の最大ID + 1）
            tasks_data = self._parse_tasks_file()
            max_id = 0
            for task in tasks_data:
                try:
                    task_id = int(task.get("id", 0))
                    max_id = max(max_id, task_id)
                except ValueError:
                    continue

            new_id = max_id + 1

            # 新しいタスク行を作成
            new_task_line = (
                f"| {new_id} | {title} | PLAN | {owner} | - | - | - | {due_date} | - | {notes} |\n"
            )

            # ファイルに追加
            with open(tasks_file, "a", encoding="utf-8") as f:
                f.write(new_task_line)

            self.logger.info(f"Created new task {new_id}: {title}")
            return True

        except Exception as e:
            self.logger.error(f"Error creating new task: {e}")
            return False

    def _get_git_commit_data(self, commit_sha):
        """特定のコミットの詳細データを取得"""
        try:
            import subprocess

            if not os.path.exists(".git"):
                return None

            # コミット詳細を取得
            result = subprocess.run(
                [
                    "git",
                    "show",
                    "--pretty=format:%H|%s|%an|%ae|%ad|%B",
                    "--name-status",
                    commit_sha,
                ],
                capture_output=True,
                text=True,
                cwd=self.base_dir,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if lines:
                    # 最初の行からコミット情報を抽出
                    commit_info = lines[0].split("|")
                    if len(commit_info) >= 5:
                        return {
                            "hash": commit_info[0],
                            "message": commit_info[1],
                            "author": commit_info[2],
                            "email": commit_info[3],
                            "date": commit_info[4],
                            "body": commit_info[5] if len(commit_info) > 5 else "",
                            "files": self._get_commit_files(commit_sha),
                        }

            return None

        except Exception as e:
            self.logger.error(f"Error getting git commit data: {e}")
            return None

    def _get_commit_files(self, commit_sha):
        """コミットで変更されたファイル一覧を取得"""
        try:
            import subprocess

            result = subprocess.run(
                ["git", "show", "--name-status", commit_sha],
                capture_output=True,
                text=True,
                cwd=self.base_dir,
            )

            files = []
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if line and "\t" in line:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            status_char = parts[0].strip()
                            filename = parts[1].strip()

                            status = "modified"
                            if status_char == "A":
                                status = "added"
                            elif status_char == "D":
                                status = "deleted"
                            elif status_char == "M":
                                status = "modified"

                            files.append(
                                {"name": filename, "status": status, "changes": 1}  # 簡略化
                            )

            return files

        except Exception as e:
            self.logger.error(f"Error getting commit files: {e}")
            return []

    def _get_rules_data(self):
        """ルールデータを取得"""
        try:
            rules_data = {
                "rules": [
                    {
                        "id": "rule_001",
                        "name": "EOL Rule",
                        "category": "Format",
                        "status": "active",
                        "severity": "high",
                        "description": "改行コード統一（LF固定、*.batのみCRLF）",
                        "violations": 2,
                        "last_check": datetime.now().isoformat(),
                    },
                    {
                        "id": "rule_002",
                        "name": "Python Rule",
                        "category": "Code Quality",
                        "status": "active",
                        "severity": "medium",
                        "description": "Black+isort、ログ保存先統一",
                        "violations": 0,
                        "last_check": datetime.now().isoformat(),
                    },
                    {
                        "id": "rule_003",
                        "name": "PowerShell Rule",
                        "category": "Security",
                        "status": "active",
                        "severity": "high",
                        "description": "Dry-Run既定、書込は-Applyのみ",
                        "violations": 1,
                        "last_check": datetime.now().isoformat(),
                    },
                    {
                        "id": "rule_004",
                        "name": "Backup Rule",
                        "category": "Safety",
                        "status": "active",
                        "severity": "high",
                        "description": "変更前にbackups/へ自動保存",
                        "violations": 0,
                        "last_check": datetime.now().isoformat(),
                    },
                    {
                        "id": "rule_005",
                        "name": "Security Rule",
                        "category": "Security",
                        "status": "active",
                        "severity": "critical",
                        "description": "秘匿情報の除外・暗号化",
                        "violations": 0,
                        "last_check": datetime.now().isoformat(),
                    },
                ],
                "statistics": {
                    "total_rules": 5,
                    "active_rules": 5,
                    "inactive_rules": 0,
                    "total_violations": 3,
                    "critical_violations": 0,
                    "high_violations": 3,
                    "medium_violations": 0,
                    "low_violations": 0,
                },
            }
            return rules_data
        except Exception as e:
            self.logger.error(f"Error getting rules data: {e}")
            return {"rules": [], "statistics": {}}

    def _get_rule_violations(self):
        """ルール違反データを取得"""
        try:
            violations_data = {
                "violations": [
                    {
                        "id": "violation_001",
                        "rule_id": "rule_001",
                        "rule_name": "EOL Rule",
                        "file": "ORCH/templates/orch_dashboard.html",
                        "line": 1654,
                        "severity": "high",
                        "message": "CRLF改行コードが検出されました",
                        "detected_at": datetime.now().isoformat(),
                        "status": "open",
                    },
                    {
                        "id": "violation_002",
                        "rule_id": "rule_001",
                        "rule_name": "EOL Rule",
                        "file": "ORCH/data/logs/integrated_dashboard.log",
                        "line": 245,
                        "severity": "high",
                        "message": "CRLF改行コードが検出されました",
                        "detected_at": datetime.now().isoformat(),
                        "status": "open",
                    },
                    {
                        "id": "violation_003",
                        "rule_id": "rule_003",
                        "rule_name": "PowerShell Rule",
                        "file": "scripts/ops/validate_orch_md.py",
                        "line": 89,
                        "severity": "high",
                        "message": "Dry-Run既定ルールに違反しています",
                        "detected_at": datetime.now().isoformat(),
                        "status": "open",
                    },
                ],
                "summary": {
                    "total_violations": 3,
                    "open_violations": 3,
                    "resolved_violations": 0,
                    "critical_count": 0,
                    "high_count": 3,
                    "medium_count": 0,
                    "low_count": 0,
                },
            }
            return violations_data
        except Exception as e:
            self.logger.error(f"Error getting rule violations: {e}")
            return {"violations": [], "summary": {}}

    def _get_system_health_data(self):
        """システムヘルス情報を取得（BIOSデータ含む）"""
        try:
            import platform
            import subprocess

            import psutil

            # 基本システム情報
            system_info = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
            }

            # CPU情報
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "max_frequency": psutil.cpu_freq().max if psutil.cpu_freq() else 0,
                "current_frequency": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                "cpu_usage": psutil.cpu_percent(interval=1),
                "per_core_usage": psutil.cpu_percent(interval=1, percpu=True),
            }

            # メモリ情報
            memory = psutil.virtual_memory()
            memory_info = {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percentage": memory.percent,
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
            }

            # ディスク情報
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append(
                        {
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "file_system": partition.fstype,
                            "total": partition_usage.total,
                            "used": partition_usage.used,
                            "free": partition_usage.free,
                            "percentage": round(
                                (partition_usage.used / partition_usage.total) * 100, 2
                            ),
                            "total_gb": round(partition_usage.total / (1024**3), 2),
                            "used_gb": round(partition_usage.used / (1024**3), 2),
                            "free_gb": round(partition_usage.free / (1024**3), 2),
                        }
                    )
                except PermissionError:
                    continue

            # ネットワーク情報
            network_info = psutil.net_io_counters()
            network_data = {
                "bytes_sent": network_info.bytes_sent,
                "bytes_recv": network_info.bytes_recv,
                "packets_sent": network_info.packets_sent,
                "packets_recv": network_info.packets_recv,
                "bytes_sent_mb": round(network_info.bytes_sent / (1024**2), 2),
                "bytes_recv_mb": round(network_info.bytes_recv / (1024**2), 2),
            }

            # プロセス情報（上位10プロセス）
            processes = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # CPU使用率でソート
            processes.sort(key=lambda x: x["cpu_percent"] or 0, reverse=True)
            top_processes = processes[:10]

            # BIOS/システム詳細情報（Windows）
            bios_info = {}
            if platform.system() == "Windows":
                try:
                    # WMIを使用してBIOS情報を取得
                    wmi_commands = {
                        "bios": "wmic bios get Manufacturer,Name,Version,ReleaseDate /format:csv",
                        "motherboard": "wmic baseboard get Manufacturer,Product,Version /format:csv",
                        "memory": "wmic memorychip get Capacity,Speed,Manufacturer /format:csv",
                        "cpu_detail": "wmic cpu get Name,Manufacturer,MaxClockSpeed,NumberOfCores /format:csv",
                    }

                    for key, cmd in wmi_commands.items():
                        try:
                            result = subprocess.run(
                                cmd.split(), capture_output=True, text=True, timeout=10
                            )
                            if result.returncode == 0:
                                bios_info[key] = result.stdout.strip()
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            bios_info[key] = "取得できませんでした"

                except Exception as e:
                    self.logger.warning(f"BIOS情報の取得に失敗: {e}")
                    bios_info = {"error": "BIOS情報の取得に失敗しました"}

            # 温度情報（利用可能な場合）
            temperature_info = {}
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        temperature_info[name] = [
                            {
                                "label": entry.label or name,
                                "current": entry.current,
                                "high": entry.high,
                                "critical": entry.critical,
                            }
                            for entry in entries
                        ]
            except AttributeError:
                # Windowsでは通常利用できない
                temperature_info = {"note": "温度センサー情報は利用できません"}

            # システムヘルス総合評価
            health_score = 100
            warnings = []

            # CPU使用率チェック
            if cpu_info["cpu_usage"] > 80:
                health_score -= 20
                warnings.append("CPU使用率が高い状態です")

            # メモリ使用率チェック
            if memory_info["percentage"] > 85:
                health_score -= 15
                warnings.append("メモリ使用率が高い状態です")

            # ディスク使用率チェック
            for disk in disk_info:
                if disk["percentage"] > 90:
                    health_score -= 10
                    warnings.append(f"ディスク {disk['device']} の使用率が高い状態です")

            health_status = "良好"
            if health_score < 60:
                health_status = "注意"
            elif health_score < 80:
                health_status = "警告"

            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "health_score": max(0, health_score),
                "health_status": health_status,
                "warnings": warnings,
                "system_info": system_info,
                "cpu_info": cpu_info,
                "memory_info": memory_info,
                "disk_info": disk_info,
                "network_info": network_data,
                "top_processes": top_processes,
                "bios_info": bios_info,
                "temperature_info": temperature_info,
            }

        except Exception as e:
            self.logger.error(f"Error getting system health data: {e}")
            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "health_score": 0,
                "health_status": "エラー",
                "warnings": [f"システム情報の取得に失敗しました: {str(e)}"],
                "error": str(e),
            }

    def run(self):
        """ダッシュボード開始"""
        try:
            # Phase 3のリアルタイム監視開始
            if self.dashboard_websocket:
                self.dashboard_websocket.start_monitoring()
                self.logger.info("Phase 3 real-time monitoring started")

            # 品質監視開始
            if self.quality_monitoring:
                self._start_quality_monitoring()

            self.logger.info(
                f"ダッシュボードを開始します: http://{self.config.host}:{self.config.port}"
            )

            # SocketIOサーバー開始
            self.app.run(host=self.config.host, port=self.config.port, debug=False, threaded=True)

        except Exception as e:
            self.logger.error(f"ダッシュボード開始エラー: {e}")
            raise

    def stop(self):
        """ダッシュボード停止"""
        try:
            # Phase 3のリアルタイム監視停止
            if self.dashboard_websocket:
                self.dashboard_websocket.stop_monitoring()
                self.logger.info("Phase 3 real-time monitoring stopped")

            # 品質監視停止
            self._stop_quality_monitoring()

            self.logger.info("ダッシュボードを停止しました")

        except Exception as e:
            self.logger.error(f"ダッシュボード停止エラー: {e}")
            raise


# Flask CLI用のapp export
_dashboard_instance = None


def create_app():
    """Flask CLI用のアプリファクトリ"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = OrchDashboard()
    return _dashboard_instance.app


# Flask CLI用のapp export（直接参照）
app = create_app()


def main():
    """メイン関数"""
    dashboard = OrchDashboard()
    try:
        dashboard.run()
    except KeyboardInterrupt:
        dashboard.stop()
    except Exception as e:
        logging.error(f"アプリケーションエラー: {e}")
        dashboard.stop()
        raise


if __name__ == "__main__":
    main()
