#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import re
import psutil
import platform
import subprocess

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_from_directory, Response, stream_with_context
from jinja2 import TemplateNotFound
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import hmac
import hashlib

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
    from db.knowledge_store import KnowledgeStore, CrossThinkingResult, WorkOutcome, PS1Parameters, LearningMetrics
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
    port: int = 5001
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
        
        # Flask app setup with template directory
        # 優先: MOC/ORCH/templates を使用。存在しない場合は MOC/templates をフォールバック
        base = Path(__file__).resolve().parent
        tpl_primary = (base / "ORCH" / "templates")
        tpl_fallback = (base / "templates")
        template_dir = str(tpl_primary if tpl_primary.exists() else tpl_fallback)

        # static は ORCH/static があればそれを優先、なければ従来設定
        static_primary = (base / "ORCH" / "static")
        static_dir = str(static_primary) if static_primary.exists() else self.config.static_folder

        self.app = Flask(
            __name__,
            template_folder=template_dir,
            static_folder=static_dir,
        )

        # 互換: 上位ORCHツリー（C:\Users\User\Trae\ORCH\templates）も探索パスに追加
        alt1 = (base.parent / "ORCH" / "templates")
        try:
            if alt1.exists():
                sp = getattr(self.app.jinja_loader, "searchpath", [])
                if str(alt1) not in sp:
                    self.app.jinja_loader.searchpath.append(str(alt1))
        except Exception:
            # ローダーが未定義でも処理継続
            pass
        
        # CORS設定
        CORS(self.app, resources={
            r"/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": False
            }
        })
        
        # SocketIO設定
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # 秘密鍵設定
        self.app.secret_key = 'orch_dashboard_secret_key_2025'
        
        # ログ設定
        self.logger = self._setup_logging()

        # Webhook用の冪等性キャッシュ（インメモリ、TTL秒）
        self._idempotency_cache: Dict[str, float] = {}
        self._idempotency_ttl: int = 3600
        
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
        logger = logging.getLogger('orch_dashboard')
        logger.setLevel(getattr(logging, self.config.log_level))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger

    def _verify_hmac_signature(self, raw_body: bytes, signature: str) -> bool:
        """X-Signature (HMAC-SHA256) を検証。環境変数 ORCH_WEBHOOK_SECRET を利用。"""
        try:
            secret = os.environ.get("ORCH_WEBHOOK_SECRET", "")
            if not secret:
                # シークレット未設定の場合は検証不可とする
                self.logger.warning("ORCH_WEBHOOK_SECRET が未設定のため署名検証に失敗")
                return False
            expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, (signature or ""))
        except Exception as e:
            self.logger.error(f"HMAC検証エラー: {e}")
            return False

    def _idempotency_seen(self, key: str) -> bool:
        """Idempotency-Key が既に処理済みか確認し、古いエントリをTTLに従いパージ"""
        now = time.time()
        # TTL超過のエントリをパージ
        try:
            for k, ts in list(self._idempotency_cache.items()):
                if now - ts > self._idempotency_ttl:
                    self._idempotency_cache.pop(k, None)
        except Exception:
            # キャッシュが壊れても処理継続
            self._idempotency_cache = {}
        return key in self._idempotency_cache

    def _mark_idempotency(self, key: str):
        """Idempotency-Key を処理済みとして記録"""
        self._idempotency_cache[key] = time.time()

    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            try:
                return render_template('orch_dashboard.html', title='ORCH統合管理システム')
            except TemplateNotFound:
                # 最小フォールバック（テンプレ未配置でも200で監視継続）
                return Response(
                    "<!doctype html><title>ORCH</title><h1>Template missing</h1>",
                    mimetype="text/html",
                )
        
        @self.app.route('/tasks')
        def tasks_page():
            """Tasks management page"""
            return render_template('orch_dashboard.html', 
                                 title='タスク管理')
        
        @self.app.route('/approvals')
        def approvals_page():
            """Approvals management page"""
            return render_template('orch_dashboard.html', 
                                 title='承認管理')
        
        # API Routes
        @self.app.route('/api/overview')
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
                    status = task.get('status', 'UNKNOWN')
                    task_status_counts[status] = task_status_counts.get(status, 0) + 1
                
                # Approval status counts
                approval_status_counts = {}
                for approval in approvals_data:
                    status = approval.get('status', 'unknown')
                    approval_status_counts[status] = approval_status_counts.get(status, 0) + 1
                
                overview_data = {
                    'system_status': {
                        'total_tasks': total_tasks,
                        'task_status_counts': task_status_counts,
                        'approval_status_counts': approval_status_counts,
                        'last_updated': datetime.now().isoformat()
                    }
                }
                
                return jsonify(overview_data)
                
            except Exception as e:
                self.logger.error(f"Error getting overview: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/tasks')
        def api_tasks():
            """Get tasks data"""
            try:
                tasks_data = self._parse_tasks_file()
                return jsonify({'tasks': tasks_data})
            except Exception as e:
                self.logger.error(f"Error getting tasks: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/approvals')
        def api_approvals():
            """Get approvals data"""
            try:
                approvals_data = self._parse_approvals_file()
                return jsonify({'approvals': approvals_data})
            except Exception as e:
                self.logger.error(f"Error getting approvals: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/milestones')
        def api_milestones():
            """Get milestones data"""
            try:
                milestones_data = self._parse_milestones_file()
                return jsonify({'milestones': milestones_data})
            except Exception as e:
                self.logger.error(f"Error getting milestones: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/quality/metrics')
        def api_quality_metrics():
            """Get quality metrics data"""
            try:
                metrics = self._get_quality_metrics()
                return jsonify(metrics)
            except Exception as e:
                self.logger.error(f"Error getting quality metrics: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/quality/health')
        def api_quality_health():
            """Get system health data"""
            try:
                health = self._get_system_health()
                return jsonify(health)
            except Exception as e:
                self.logger.error(f"Error getting system health: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/rules')
        def api_rules():
            """Get rules data"""
            try:
                rules_data = self._get_rules_data()
                return jsonify(rules_data)
            except Exception as e:
                self.logger.error(f"Error getting rules: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/rules/violations')
        def api_rules_violations():
            """Get rule violations data"""
            try:
                violations_data = self._get_rule_violations()
                return jsonify(violations_data)
            except Exception as e:
                self.logger.error(f"Error getting rule violations: {e}")
                return jsonify({'error': str(e)}), 500

        # CMD Role API endpoints
        @self.app.route('/api/approvals/approve', methods=['POST'])
        def api_approve_approval():
            """Approve an approval request"""
            try:
                data = request.get_json()
                appr_id = data.get('appr_id')
                approver = data.get('approver', 'CMD')
                approver_role = data.get('approver_role', 'CMD')
                
                if not appr_id:
                    return jsonify({'success': False, 'error': 'appr_id is required'}), 400
                
                success = self._update_approval_status(appr_id, 'approved', approver, approver_role)
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error approving approval: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/approvals/reject', methods=['POST'])
        def api_reject_approval():
            """Reject an approval request"""
            try:
                data = request.get_json()
                appr_id = data.get('appr_id')
                approver = data.get('approver', 'CMD')
                approver_role = data.get('approver_role', 'CMD')
                
                if not appr_id:
                    return jsonify({'success': False, 'error': 'appr_id is required'}), 400
                
                success = self._update_approval_status(appr_id, 'rejected', approver, approver_role)
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error rejecting approval: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/promote', methods=['POST'])
        def api_promote_task():
            """Promote task to READY status"""
            try:
                data = request.get_json()
                task_id = data.get('task_id')
                
                if not task_id:
                    return jsonify({'success': False, 'error': 'task_id is required'}), 400
                
                success = self._update_task_status(task_id, 'READY')
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error promoting task: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/approve_done', methods=['POST'])
        def api_approve_done_task():
            """Approve DONE task"""
            try:
                data = request.get_json()
                task_id = data.get('task_id')
                
                if not task_id:
                    return jsonify({'success': False, 'error': 'task_id is required'}), 400
                
                success = self._update_task_status(task_id, 'DONE')
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error approving done task: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/request_fix', methods=['POST'])
        def api_request_fix_task():
            """Request FIX for task"""
            try:
                data = request.get_json()
                task_id = data.get('task_id')
                
                if not task_id:
                    return jsonify({'success': False, 'error': 'task_id is required'}), 400
                
                success = self._update_task_status(task_id, 'FIX')
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error requesting fix: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/hold', methods=['POST'])
        def api_hold_task():
            """Hold task"""
            try:
                data = request.get_json()
                task_id = data.get('task_id')
                
                if not task_id:
                    return jsonify({'success': False, 'error': 'task_id is required'}), 400
                
                success = self._update_task_status(task_id, 'HOLD')
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error holding task: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/drop', methods=['POST'])
        def api_drop_task():
            """Drop task"""
            try:
                data = request.get_json()
                task_id = data.get('task_id')
                
                if not task_id:
                    return jsonify({'success': False, 'error': 'task_id is required'}), 400
                
                success = self._update_task_status(task_id, 'DROP')
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error dropping task: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/tasks/create', methods=['POST'])
        def api_create_task():
            """Create new task"""
            try:
                data = request.get_json()
                title = data.get('title')
                due_date = data.get('due_date')
                owner = data.get('owner', 'CMD')
                notes = data.get('notes', '')
                
                if not title:
                    return jsonify({'success': False, 'error': 'title is required'}), 400
                
                success = self._create_new_task(title, due_date, owner, notes)
                return jsonify({'success': success})
            except Exception as e:
                self.logger.error(f"Error creating task: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/quality/alerts')
        def api_quality_alerts():
            """Get quality alerts"""
            try:
                alerts = self._get_quality_alerts()
                return jsonify({'alerts': alerts})
            except Exception as e:
                self.logger.error(f"Error getting quality alerts: {e}")
                return jsonify({'error': str(e)}), 500

        # --- Git Visualization API Endpoints ---
        @self.app.route('/api/git/graph')
        def api_git_graph():
            """Get Git graph data for visualization"""
            try:
                git_data = self._get_git_graph_data()
                return jsonify(git_data)
            except Exception as e:
                self.logger.error(f"Error getting git graph data: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/git/branches')
        def api_git_branches():
            """Get Git branches data"""
            try:
                branches_data = self._get_git_branches_data()
                return jsonify({'success': True, 'branches': branches_data})
            except Exception as e:
                self.logger.error(f"Error getting git branches data: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/git/commit/<commit_sha>')
        def api_git_commit(commit_sha):
            """Get detailed commit information"""
            try:
                commit_data = self._get_git_commit_data(commit_sha)
                return jsonify({'success': True, 'commit': commit_data})
            except Exception as e:
                self.logger.error(f"Error getting git commit data: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        # --- System Health API Endpoint ---
        @self.app.route('/api/system-health')
        def api_system_health():
            """Get detailed system health information including BIOS data"""
            try:
                health_data = self._get_system_health_data()
                return jsonify(health_data)
            except Exception as e:
                self.logger.error(f"Error getting system health data: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/system/detailed')
        def api_system_detailed():
            """Get detailed system information"""
            try:
                health_data = self._get_system_health_data()
                return jsonify(health_data)
            except Exception as e:
                self.logger.error(f"Error getting detailed system data: {e}")
                return jsonify({'error': str(e)}), 500

        # --- Orchestration MVP Endpoints ---
        @self.app.route('/dispatch', methods=['POST'])
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

                core_id = data.get('coreId')
                action = data.get('action', 'Dispatch')
                stay = bool(data.get('stay', True))
                enable_orch = bool(data.get('enableOrchIntegration', True))
                interval_sec = int(data.get('intervalSec', 5))

                if not core_id:
                    return jsonify({'success': False, 'message': 'coreId は必須です'}), 400

                ok, pid, cmd = self._launch_dispatcher(core_id, stay, enable_orch, interval_sec, action)
                if ok:
                    # 速報をSocketIOで通知
                    try:
                        self.socketio.emit('dispatcher_started', {
                            'coreId': core_id,
                            'pid': pid,
                            'command': cmd,
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception:
                        pass
                    return jsonify({'success': True, 'pid': pid, 'command': cmd})
                else:
                    return jsonify({'success': False, 'message': 'Dispatcher起動に失敗しました'}), 500
            except Exception as e:
                self.logger.error(f"/dispatch error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/dispatch/stop', methods=['POST'])
        def api_dispatch_stop():
            """Stop Task-Dispatcher.ps1 processes. Optional JSON: { coreId: str }"""
            try:
                data = request.get_json(silent=True) or {}
                core_id = data.get('coreId')
                stopped = self._stop_dispatcher(core_id)
                return jsonify({'success': True, 'stopped': stopped})
            except Exception as e:
                self.logger.error(f"/dispatch/stop error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/status', methods=['GET'])
        def api_status():
            """Summarize dispatcher/stay/orch state and aggregate TASKS/MILESTONES"""
            try:
                dispatchers = self._find_dispatcher_processes()
                tasks = self._parse_tasks_file()
                milestones = self._parse_milestones_file()

                # Locks overview
                locks_dir = os.path.join(self.config.orch_root, '.locks')
                locks = []
                try:
                    if os.path.isdir(locks_dir):
                        for name in os.listdir(locks_dir):
                            p = os.path.join(locks_dir, name)
                            try:
                                stat = os.stat(p)
                                locks.append({
                                    'name': name,
                                    'size': stat.st_size,
                                    'mtime': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                })
                            except Exception:
                                locks.append({'name': name})
                except Exception:
                    pass

                summary = {
                    'dispatcher': {
                        'running': len(dispatchers) > 0,
                        'processes': dispatchers
                    },
                    'locks': locks,
                    'tasks': tasks,
                    'milestones': milestones,
                    'systemHealth': self._get_system_health(),
                    'timestamp': datetime.now().isoformat()
                }
                return jsonify(summary)
            except Exception as e:
                self.logger.error(f"/status error: {e}")
                return jsonify({'error': str(e)}), 500

        # --- Jobs API Endpoints (OpenAPI Extension) ---
        @self.app.route('/jobs', methods=['GET'])
        def api_list_jobs():
            """List all jobs (tasks with approval requirements)"""
            try:
                tasks = self._parse_tasks_file()
                approvals = self._parse_approvals_file()
                
                # Create jobs by combining tasks and approvals
                jobs = []
                for task in tasks:
                    task_id = task.get('id')
                    if not task_id:
                        continue
                    
                    # Find related approvals
                    task_approvals = [a for a in approvals if a.get('task_id') == task_id]
                    
                    job = {
                        'id': task_id,
                        'title': task.get('title', ''),
                        'status': task.get('status', 'UNKNOWN'),
                        'owner': task.get('owner', ''),
                        'due': task.get('due', ''),
                        'artifact': task.get('artifact', ''),
                        'notes': task.get('notes', ''),
                        'approvals': task_approvals
                    }
                    jobs.append(job)
                
                return jsonify({'items': jobs, 'next_page': None})
            except Exception as e:
                self.logger.error(f"Error listing jobs: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/jobs/<job_id>', methods=['GET'])
        def api_get_job(job_id):
            """Get specific job details"""
            try:
                tasks = self._parse_tasks_file()
                approvals = self._parse_approvals_file()
                
                # Find the task
                task = next((t for t in tasks if t.get('id') == job_id), None)
                if not task:
                    return jsonify({'error': 'Job not found'}), 404
                
                # Find related approvals
                task_approvals = [a for a in approvals if a.get('task_id') == job_id]
                
                job = {
                    'id': job_id,
                    'title': task.get('title', ''),
                    'status': task.get('status', 'UNKNOWN'),
                    'owner': task.get('owner', ''),
                    'due': task.get('due', ''),
                    'artifact': task.get('artifact', ''),
                    'notes': task.get('notes', ''),
                    'approvals': task_approvals
                }
                
                return jsonify(job)
            except Exception as e:
                self.logger.error(f"Error getting job {job_id}: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/jobs/<job_id>/approve', methods=['POST'])
        def api_approve_job(job_id):
            """Approve a job"""
            try:
                data = request.get_json() or {}
                approver = data.get('approver', 'AUDIT')
                comment = data.get('comment', '')
                
                # Find pending approval for this job
                approvals = self._parse_approvals_file()
                pending_approval = next((a for a in approvals 
                                       if a.get('task_id') == job_id and a.get('status') == 'pending'), None)
                
                if not pending_approval:
                    return jsonify({'error': 'No pending approval found for this job'}), 404
                
                # Update approval status
                success = self._update_approval_status(pending_approval.get('appr_id'), 'approved', approver, comment)
                
                if success:
                    return jsonify({'success': True, 'message': 'Job approved successfully'})
                else:
                    return jsonify({'error': 'Failed to approve job'}), 500
                    
            except Exception as e:
                self.logger.error(f"Error approving job {job_id}: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/jobs/<job_id>/reject', methods=['POST'])
        def api_reject_job(job_id):
            """Reject a job"""
            try:
                data = request.get_json() or {}
                approver = data.get('approver', 'AUDIT')
                reason = data.get('reason', '')
                
                # Find pending approval for this job
                approvals = self._parse_approvals_file()
                pending_approval = next((a for a in approvals 
                                       if a.get('task_id') == job_id and a.get('status') == 'pending'), None)
                
                if not pending_approval:
                    return jsonify({'error': 'No pending approval found for this job'}), 404
                
                # Update approval status
                success = self._update_approval_status(pending_approval.get('appr_id'), 'rejected', approver, reason)
                
                if success:
                    return jsonify({'success': True, 'message': 'Job rejected successfully'})
                else:
                    return jsonify({'error': 'Failed to reject job'}), 500
                    
            except Exception as e:
                self.logger.error(f"Error rejecting job {job_id}: {e}")
                return jsonify({'error': str(e)}), 500

        # --- Server-Sent Events (SSE): /jobs/{id}/events ---
        @self.app.route('/jobs/<job_id>/events', methods=['GET'])
        def sse_job_events(job_id):
            """ジョブの状態更新をSSEで配信。15秒ハートビート、Last-Event-IDヘッダ対応（簡易）。"""

            def event_stream():
                # クライアントの最終イベントID（簡易対応）
                _last_event_id = request.headers.get('Last-Event-ID')
                heartbeat_interval = 15
                last_heartbeat = time.time()

                # 初期状態の取得
                prev_status = None
                try:
                    task = next((t for t in self._parse_tasks_file() if t.get('id') == job_id), None)
                    if task:
                        prev_status = task.get('status')
                except Exception as e:
                    err = json.dumps({'error': f'init: {str(e)}'})
                    yield f"event: error\ndata: {err}\n\n"

                while True:
                    try:
                        task = next((t for t in self._parse_tasks_file() if t.get('id') == job_id), None)
                        status = task.get('status') if task else None
                        if status is not None and status != prev_status:
                            payload = {
                                'id': job_id,
                                'status': status,
                                'timestamp': datetime.utcnow().isoformat() + 'Z'
                            }
                            data = json.dumps(payload, ensure_ascii=False)
                            yield f"event: status\ndata: {data}\n\n"
                            prev_status = status
                    except Exception as e:
                        err = json.dumps({'error': str(e)})
                        yield f"event: error\ndata: {err}\n\n"

                    now = time.time()
                    if now - last_heartbeat >= heartbeat_interval:
                        hb = json.dumps({'ts': datetime.utcnow().isoformat() + 'Z'})
                        yield f"event: ping\ndata: {hb}\n\n"
                        last_heartbeat = now

                    time.sleep(1)

            resp = Response(stream_with_context(event_stream()), mimetype='text/event-stream')
            resp.headers['Cache-Control'] = 'no-cache'
            resp.headers['Connection'] = 'keep-alive'
            return resp

        # --- Webhook Callback: /callbacks/terminal ---
        @self.app.route('/callbacks/terminal', methods=['POST'])
        def webhook_terminal():
            """ターミナル（エージェント）からのWebhookコールバック。
            - X-Signature: HMAC-SHA256（body）
            - Idempotency-Key: 冪等性制御（重複は202で黙認）
            - 成功時: 202 Accepted
            - 監査ログ: audit_events に挿入（存在すれば）
            """

            raw_body = request.get_data() or b''
            signature = request.headers.get('X-Signature', '')
            idem_key = request.headers.get('Idempotency-Key')

            if not idem_key:
                return jsonify({'error': 'Idempotency-Key header required'}), 400

            # 重複抑止（冪等性）
            if self._idempotency_seen(idem_key):
                return jsonify({'status': 'duplicate'}), 202

            # 署名検証
            if not self._verify_hmac_signature(raw_body, signature):
                return jsonify({'error': 'invalid signature'}), 401

            # 処理済みとして記録
            self._mark_idempotency(idem_key)

            # ペイロード処理
            try:
                payload = request.get_json(force=True) or {}
            except Exception:
                payload = {}

            job_id = payload.get('job_id')
            status = payload.get('status')
            payload_sha256 = hashlib.sha256(raw_body).hexdigest()

            # 監査イベント追加（DBが存在する場合のみ）
            try:
                db_path = os.path.join(self.base_dir, 'data', 'orch.db')
                if os.path.exists(db_path):
                    import sqlite3
                    conn = sqlite3.connect(db_path)
                    ts = datetime.utcnow().isoformat() + 'Z'
                    details = json.dumps(payload, ensure_ascii=False)
                    conn.execute(
                        """
                        INSERT INTO audit_events (ts, actor, role, event, task_id, appr_id, payload_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ts, 'agent', 'WORK', 'terminal_callback', str(job_id or ''), None, payload_sha256)
                    )
                    conn.commit()
                    conn.close()
            except Exception as e:
                self.logger.warning(f"Failed to record audit event: {e}")

            return jsonify({'accepted': True, 'payload_sha256': payload_sha256}), 202

        # --- Audit Events API Endpoint ---
        @self.app.route('/audit/events', methods=['GET'])
        def api_audit_events():
            """Get audit events"""
            try:
                # Parse query parameters
                limit = request.args.get('limit', 100, type=int)
                event_type = request.args.get('type')
                
                events = self._get_audit_events(limit=limit, event_type=event_type)
                return jsonify(events)
            except Exception as e:
                self.logger.error(f"Error getting audit events: {e}")
                return jsonify({'error': str(e)}), 500

        # Phase 3 Console Launcher
        @self.app.route('/console')
        def console_launcher():
            """Phase 3 Console Launcher"""
            return send_from_directory('.', 'console_launcher.html')
        
        # Phase 3 API Endpoints
        @self.app.route('/api/v3/task-overview')
        def api_task_overview():
            """タスク概要API"""
            if self.task_visualizer:
                try:
                    overview = self.task_visualizer.get_task_overview()
                    return jsonify(overview)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            return jsonify({'error': 'Task visualizer not available'}), 503
        
        @self.app.route('/api/v3/task-flow')
        def api_task_flow():
            """タスクフロー図API"""
            if self.task_visualizer:
                try:
                    flow_id = request.args.get('flow_id')
                    flow_diagram = self.task_visualizer.get_task_flow_diagram(flow_id)
                    return jsonify(flow_diagram)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            return jsonify({'error': 'Task visualizer not available'}), 503
        
        @self.app.route('/api/v3/console-topology')
        def api_console_topology():
            """コンソールトポロジーAPI"""
            if self.task_visualizer:
                try:
                    topology = self.task_visualizer.get_console_topology()
                    return jsonify(topology)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            return jsonify({'error': 'Task visualizer not available'}), 503
        
        @self.app.route('/api/v3/task-timeline')
        def api_task_timeline():
            """タスクタイムラインAPI"""
            if self.task_visualizer:
                try:
                    hours = int(request.args.get('hours', 24))
                    timeline = self.task_visualizer.get_task_timeline(hours)
                    return jsonify(timeline)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            return jsonify({'error': 'Task visualizer not available'}), 503
        
        @self.app.route('/api/v3/performance-heatmap')
        def api_performance_heatmap():
            """パフォーマンスヒートマップAPI"""
            if self.task_visualizer:
                try:
                    heatmap = self.task_visualizer.get_performance_heatmap()
                    return jsonify(heatmap)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            return jsonify({'error': 'Task visualizer not available'}), 503

        # DB/ML統合API エンドポイント
        @self.app.route('/api/ml/status')
        def api_ml_status():
            """機械学習システムの状態を取得"""
            if not self.learning_engine:
                return jsonify({'error': 'ML機能が利用できません'}), 503
            
            try:
                status = self.learning_engine.get_learning_status()
                return jsonify(status)
            except Exception as e:
                self.logger.error(f"ML状態取得エラー: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/ml/optimize/<script_name>')
        def api_optimize_parameters(script_name):
            """PS1パラメーターの最適化"""
            if not self.learning_engine:
                return jsonify({'error': 'ML機能が利用できません'}), 503
            
            try:
                optimized_params = self.learning_engine.optimize_script_parameters(script_name)
                if optimized_params:
                    return jsonify({
                        'success': True,
                        'optimized_parameters': {
                            'parameter_set_id': optimized_params.parameter_set_id,
                            'timeout_ms': optimized_params.timeout_ms,
                            'retry_count': optimized_params.retry_count,
                            'batch_size': optimized_params.batch_size,
                            'memory_limit_mb': optimized_params.memory_limit_mb,
                            'success_rate': optimized_params.success_rate,
                            'avg_execution_time_ms': optimized_params.avg_execution_time_ms
                        }
                    })
                else:
                    return jsonify({'success': False, 'message': 'パラメーターが見つかりません'}), 404
            except Exception as e:
                self.logger.error(f"パラメーター最適化エラー: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/knowledge/work_outcomes/<task_id>')
        def api_get_work_outcomes(task_id):
            """タスクの作業結果を取得"""
            if not self.knowledge_store:
                return jsonify({'error': 'DB機能が利用できません'}), 503
            
            try:
                outcomes = self.knowledge_store.get_work_outcomes_by_task(task_id)
                outcomes_data = []
                for outcome in outcomes:
                    outcomes_data.append({
                        'task_id': outcome.task_id,
                        'operation_type': outcome.operation_type,
                        'success': outcome.success,
                        'execution_time_ms': outcome.execution_time_ms,
                        'error_message': outcome.error_message,
                        'files_modified': outcome.files_modified,
                        'performance_metrics': outcome.performance_metrics,
                        'timestamp': outcome.timestamp
                    })
                
                return jsonify({'work_outcomes': outcomes_data})
            except Exception as e:
                self.logger.error(f"作業結果取得エラー: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/knowledge/save_outcome', methods=['POST'])
        def api_save_work_outcome():
            """作業結果を保存"""
            if not self.knowledge_store:
                return jsonify({'error': 'DB機能が利用できません'}), 503
            
            try:
                data = request.get_json()
                
                # 必須フィールドの検証
                required_fields = ['task_id', 'operation_type', 'success', 'execution_time_ms']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'必須フィールドが不足: {field}'}), 400
                
                # WorkOutcomeオブジェクトを作成
                outcome = WorkOutcome(
                    task_id=data['task_id'],
                    operation_type=data['operation_type'],
                    success=data['success'],
                    execution_time_ms=data['execution_time_ms'],
                    error_message=data.get('error_message'),
                    files_modified=data.get('files_modified', []),
                    ps1_parameters_used=data.get('ps1_parameters_used', {}),
                    performance_metrics=data.get('performance_metrics', {}),
                    timestamp=datetime.now().isoformat(),
                    outcome_hash=self.knowledge_store._generate_hash(f"{data['task_id']}-{datetime.now().isoformat()}")
                )
                
                # データベースに保存
                success = self.knowledge_store.save_work_outcome(outcome)
                
                if success:
                    # 機械学習エンジンに学習データとして追加
                    if self.learning_engine:
                        self.learning_engine.process_work_outcome(outcome)
                    
                    return jsonify({'success': True, 'message': '作業結果を保存しました'})
                else:
                    return jsonify({'success': False, 'message': '保存に失敗しました'}), 500
                    
            except Exception as e:
                self.logger.error(f"作業結果保存エラー: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/ml/train', methods=['POST'])
        def api_train_model():
            """機械学習モデルの訓練を実行"""
            if not self.learning_engine:
                return jsonify({'error': 'ML機能が利用できません'}), 503
            
            try:
                data = request.get_json() or {}
                epochs = data.get('epochs', 50)
                
                # 非同期で訓練を実行（実際の実装では別スレッドで実行）
                self.learning_engine.train_model(epochs=epochs)
                
                return jsonify({'success': True, 'message': f'モデル訓練を開始しました（エポック数: {epochs}）'})
                
            except Exception as e:
                self.logger.error(f"モデル訓練エラー: {e}")
                return jsonify({'error': str(e)}), 500

    def _find_dispatcher_processes(self) -> List[Dict[str, Any]]:
        """Find running Task-Dispatcher.ps1 processes and extract parameters if possible"""
        procs = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                name = (p.info.get('name') or '').lower()
                cmdline = p.info.get('cmdline') or []
                if 'powershell' in name and any('Task-Dispatcher.ps1' in (c or '') for c in cmdline):
                    info = {
                        'pid': p.info.get('pid'),
                        'name': p.info.get('name'),
                        'cmdline': cmdline
                    }
                    # Extract CoreId, flags
                    def _find_arg(flag):
                        try:
                            idx = cmdline.index(flag)
                            return cmdline[idx+1] if idx >= 0 and idx+1 < len(cmdline) else None
                        except ValueError:
                            return None
                    core_id = _find_arg('-CoreId')
                    interval = _find_arg('-OrchIntegrationIntervalSeconds')
                    info['coreId'] = core_id
                    info['intervalSec'] = int(interval) if interval and interval.isdigit() else None
                    info['stay'] = any(x in ['-Stay', '-Stay:$true'] for x in cmdline)
                    info['enableOrchIntegration'] = any(x in ['-EnableOrchIntegration', '-EnableOrchIntegration:$true'] for x in cmdline)
                    procs.append(info)
        except Exception as e:
            self.logger.error(f"find dispatcher processes error: {e}")
        return procs

    def _launch_dispatcher(self, core_id: str, stay: bool, enable_orch: bool, interval_sec: int, action: str = 'Dispatch'):
        """Launch Task-Dispatcher.ps1 via PowerShell"""
        try:
            script_path = os.path.join(self.config.orch_root, 'scripts', 'ops', 'Task-Dispatcher.ps1')
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Task-Dispatcher.ps1 not found: {script_path}")

            cmd = [
                'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', script_path,
                '-Action', action,
                '-CoreId', core_id
            ]
            if stay:
                cmd.append('-Stay')
            if enable_orch:
                cmd.append('-EnableOrchIntegration')
            if interval_sec and isinstance(interval_sec, int):
                cmd += ['-OrchIntegrationIntervalSeconds', str(interval_sec)]

            # Start process detached
            proc = subprocess.Popen(cmd, cwd=self.config.orch_root)
            self.logger.info(f"Dispatcher launched for core {core_id} (pid={proc.pid})")
            return True, proc.pid, ' '.join(cmd)
        except Exception as e:
            self.logger.error(f"launch dispatcher error: {e}")
            return False, None, None

    def _stop_dispatcher(self, core_id: Optional[str] = None) -> List[int]:
        """Stop Task-Dispatcher.ps1 processes. If core_id provided, stop only those."""
        stopped = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                name = (p.info.get('name') or '').lower()
                cmdline = p.info.get('cmdline') or []
                if 'powershell' in name and any('Task-Dispatcher.ps1' in (c or '') for c in cmdline):
                    if core_id:
                        # match by -CoreId value
                        try:
                            idx = cmdline.index('-CoreId')
                            val = cmdline[idx+1] if idx+1 < len(cmdline) else None
                            if val != core_id:
                                continue
                        except ValueError:
                            continue
                    try:
                        p.terminate()
                        stopped.append(p.info.get('pid'))
                    except Exception:
                        try:
                            p.kill()
                            stopped.append(p.info.get('pid'))
                        except Exception:
                            pass
        except Exception as e:
            self.logger.error(f"stop dispatcher error: {e}")
        return stopped

    def _setup_socketio_events(self):
        """SocketIOイベント設定"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """クライアント接続"""
            self.logger.info("クライアントが接続されました")
            emit('status', {'message': 'ORCHダッシュボードに接続されました'})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            """クライアント切断"""
            self.logger.info("クライアントが切断されました")

    def _setup_websocket_events(self):
        """WebSocketイベント設定"""
        if not self.dashboard_websocket:
            return
        
        # Phase 3のWebSocketイベントは dashboard_websocket.py で処理される
        # ここでは追加のカスタムイベントを設定
        
        @self.socketio.on('request_dashboard_refresh')
        def handle_dashboard_refresh():
            """ダッシュボード更新要求"""
            try:
                if self.task_visualizer:
                    # タスク概要更新
                    overview = self.task_visualizer.get_task_overview()
                    emit('dashboard_overview_update', overview)
                    
                    # タイムライン更新
                    timeline = self.task_visualizer.get_task_timeline(24)
                    emit('timeline_update', timeline)
                    
                    # ヒートマップ更新
                    heatmap = self.task_visualizer.get_performance_heatmap()
                    emit('heatmap_update', heatmap)
            
            except Exception as e:
                self.logger.error(f"Dashboard refresh error: {e}")
                emit('error', {'message': str(e)})
        
        @self.socketio.on('request_task_flow_refresh')
        def handle_task_flow_refresh():
            """タスクフロー更新要求"""
            try:
                if self.task_visualizer:
                    flow_diagram = self.task_visualizer.get_task_flow_diagram()
                    emit('task_flow_update', flow_diagram)
            
            except Exception as e:
                self.logger.error(f"Task flow refresh error: {e}")
                emit('error', {'message': str(e)})

    def _parse_tasks_file(self):
        """Parse TASKS.md file and return task data"""
        tasks_file = os.path.join(self.config.orch_root, 'STATE', 'TASKS.md')
        
        if not os.path.exists(tasks_file):
            return []
        
        tasks = []
        try:
            with open(tasks_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse table rows
            lines = content.split('\n')
            header_found = False
            
            for line in lines:
                if line.startswith('| id |'):
                    header_found = True
                    continue
                elif line.startswith('|---|'):
                    continue
                elif header_found and line.startswith('|') and line.count('|') >= 10:
                    # Parse task row
                    parts = [p.strip() for p in line.split('|')[1:-1]]
                    if len(parts) >= 10:
                        task = {
                            'id': parts[0],
                            'title': parts[1],
                            'status': parts[2],
                            'owner': parts[3],
                            'lock': parts[4],
                            'lock_owner': parts[5],
                            'lock_expires_at': parts[6],
                            'due': parts[7],
                            'artifact': parts[8],
                            'notes': parts[9]
                        }
                        tasks.append(task)
            
            return tasks
            
        except Exception as e:
            self.logger.error(f"Error parsing TASKS.md: {e}")
            return []

    def _parse_approvals_file(self):
        """Parse APPROVALS.md file and return approval data"""
        approvals_file = os.path.join(self.config.orch_root, 'STATE', 'APPROVALS.md')
        
        if not os.path.exists(approvals_file):
            return []
        
        approvals = []
        try:
            with open(approvals_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse table rows
            lines = content.split('\n')
            header_found = False
            
            for line in lines:
                if line.startswith('| appr_id |'):
                    header_found = True
                    continue
                elif line.startswith('|---|'):
                    continue
                elif header_found and line.startswith('|') and line.count('|') >= 10:
                    # Parse approval row
                    parts = [p.strip() for p in line.split('|')[1:-1]]
                    if len(parts) >= 10:
                        approval = {
                            'appr_id': parts[0],
                            'task_id': parts[1],
                            'op': parts[2],
                            'status': parts[3],
                            'requested_by': parts[4],
                            'approver': parts[5],
                            'approver_role': parts[6],
                            'ts_req': parts[7],
                            'ts_dec': parts[8],
                            'evidence': parts[9]
                        }
                        approvals.append(approval)
            
            return approvals
            
        except Exception as e:
            self.logger.error(f"Error parsing APPROVALS.md: {e}")
            return []

    def _parse_milestones_file(self):
        """Parse MILESTONES.md file and return milestone data"""
        milestones_file = os.path.join(self.config.orch_root, 'STATE', 'MILESTONES.md')

        if not os.path.exists(milestones_file):
            return []

        milestones = []
        try:
            with open(milestones_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse table rows
            lines = content.split('\n')
            header_found = False

            for line in lines:
                if line.startswith('| ms_id |'):
                    header_found = True
                    continue
                elif line.startswith('|---|'):
                    continue
                elif header_found and line.startswith('|') and line.count('|') >= 10:
                    # Parse milestone row
                    parts = [p.strip() for p in line.split('|')[1:-1]]
                    if len(parts) >= 10:
                        # Columns: ms_id, name, status, owner, due, kpi, description, epic_ids, task_ids, notes
                        milestone = {
                            'ms_id': parts[0],
                            'name': parts[1],
                            'status': parts[2],
                            'owner': parts[3],
                            'due': parts[4],
                            'kpi': parts[5],
                            'description': parts[6],
                            'epic_ids': [p.strip() for p in parts[7].split(',')] if parts[7] else [],
                            'task_ids': [p.strip() for p in parts[8].split(',')] if parts[8] else [],
                            'notes': parts[9]
                        }
                        milestones.append(milestone)

            return milestones

        except Exception as e:
            self.logger.error(f"Error parsing MILESTONES.md: {e}")
            return []

    def _append_task_to_file(self, task_data):
        """Add new task to TASKS.md file"""
        try:
            tasks_file = os.path.join(self.config.orch_root, 'STATE', 'TASKS.md')
            
            # Create task line
            task_line = f"| {task_data['id']} | {task_data['title']} | {task_data['status']} | {task_data['owner']} | {task_data['lock']} | {task_data['lock_owner']} | {task_data['lock_expires_at']} | {task_data['due']} | {task_data['artifact']} | {task_data['notes']} |"
            
            # Append to file
            with open(tasks_file, 'a', encoding='utf-8') as f:
                f.write('\n' + task_line)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error appending task to file: {e}")
            return False
    
    def _update_approval_in_file(self, approval_id, update_data):
        """Update approval in APPROVALS.md file"""
        try:
            approvals_file = os.path.join(self.config.orch_root, 'STATE', 'APPROVALS.md')
            
            if not os.path.exists(approvals_file):
                return False
            
            # Read current content
            with open(approvals_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Find and update the approval line
            updated = False
            for i, line in enumerate(lines):
                if line.startswith('|') and approval_id in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 11 and parts[1] == approval_id:
                        # Update fields
                        parts[4] = update_data.get('status', parts[4])  # status
                        parts[6] = update_data.get('approver', parts[6])  # approver
                        parts[7] = update_data.get('approver_role', parts[7])  # approver_role
                        parts[9] = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')  # ts_dec
                        
                        # Reconstruct line
                        lines[i] = '| ' + ' | '.join(parts[1:-1]) + ' |\n'
                        updated = True
                        break
            
            if updated:
                # Write back to file
                with open(approvals_file, 'w', encoding='utf-8') as f:
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
            valid_tasks = [t for t in tasks_data if t.get('id') and t.get('id') != 'id']
            total_tasks = len(valid_tasks)
            completed_tasks = len([t for t in valid_tasks if t.get('status') == 'DONE'])
            task_completion_rate = (completed_tasks / total_tasks) if total_tasks > 0 else 0
            
            # 承認メトリクス - ヘッダー行を除外
            valid_approvals = [a for a in approvals_data if a.get('appr_id') and a.get('appr_id') != 'appr_id']
            total_approvals = len(valid_approvals)
            approved_count = len([a for a in valid_approvals if a.get('status') == 'approved'])
            approval_rate = (approved_count / total_approvals) if total_approvals > 0 else 0
            
            # システムヘルス
            system_health = self._get_system_health()
            
            return {
                'task_completion_rate': task_completion_rate,
                'approval_rate': approval_rate,
                'system_health_score': system_health.get('health', {}).get('health_score', 0),
                'active_tasks': len([t for t in valid_tasks if t.get('status') == 'DOING']),
                'pending_approvals': len([a for a in valid_approvals if a.get('status') == 'pending']),
                'last_updated': datetime.now().strftime('%Y/%m/%d %H:%M:%S')
            }
        except Exception as e:
            self.logger.error(f"Error calculating quality metrics: {e}")
            return {
                'task_completion_rate': 0,
                'approval_rate': 0,
                'system_health_score': 0,
                'active_tasks': 0,
                'pending_approvals': 0,
                'last_updated': datetime.now().strftime('%Y/%m/%d %H:%M:%S')
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
                if platform.system() == 'Windows':
                    disk = psutil.disk_usage('C:')
                else:
                    disk = psutil.disk_usage('/')
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
                'health': {
                    'health_score': round(health_score, 1),
                    'status': status,
                    'cpu_percent': round(cpu_percent, 1),
                    'memory_percent': round(memory_percent, 1),
                    'disk_percent': round(disk_percent, 1)
                },
                'system_info': {
                    'platform': platform.system(),
                    'python_version': platform.python_version()
                },
                'timestamp': datetime.now().strftime('%Y/%m/%d %H:%M:%S')
            }
        except Exception as e:
            self.logger.error(f"Error getting system health: {e}")
            return {
                'health': {
                    'health_score': 0, 
                    'status': 'unknown',
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'disk_percent': 0
                }
            }
    
    def _get_quality_alerts(self):
        """品質アラートを取得"""
        try:
            alerts = []
            
            # システムヘルスチェック
            health = self._get_system_health()
            if health.get('status') == 'critical':
                alerts.append({
                    'id': 'system_health_critical',
                    'type': 'error',
                    'title': 'システムヘルス警告',
                    'message': f"システムヘルススコア: {health.get('health_score', 0)}%",
                    'timestamp': datetime.now().isoformat()
                })
            
            # 長時間実行中のタスクチェック
            tasks_data = self._parse_tasks_file()
            for task in tasks_data:
                if task.get('status') == 'DOING' and task.get('lock_expires_at') != '-':
                    try:
                        expires_at = datetime.fromisoformat(task['lock_expires_at'].replace('Z', '+00:00'))
                        if datetime.now() > expires_at:
                            alerts.append({
                                'id': f"task_timeout_{task.get('id')}",
                                'type': 'warning',
                                'title': 'タスクタイムアウト',
                                'message': f"タスク {task.get('id')}: {task.get('title')} がタイムアウトしました",
                                'timestamp': datetime.now().isoformat()
                            })
                    except (ValueError, TypeError):
                        continue
            
            # 承認待ちアラート
            approvals_data = self._parse_approvals_file()
            pending_count = len([a for a in approvals_data if a.get('status') == 'pending'])
            if pending_count > 5:
                alerts.append({
                    'id': 'pending_approvals_high',
                    'type': 'info',
                    'title': '承認待ち多数',
                    'message': f"{pending_count}件の承認が待機中です",
                    'timestamp': datetime.now().isoformat()
                })
            
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
                self.socketio.emit('quality_metrics_update', metrics)
                self.socketio.emit('system_health_update', health)
                self.socketio.emit('quality_alerts_update', {'alerts': alerts})
                
                # 30秒間隔で更新
                time.sleep(30)
            except Exception as e:
                self.logger.error(f"品質監視ループエラー: {e}")
                time.sleep(30)

    def _get_git_graph_data(self):
        """Git グラフデータを取得"""
        try:
            import subprocess
            import json
            from datetime import datetime
            
            # Git リポジトリの存在確認（base_dirで確認）
            git_dir = os.path.join(self.base_dir, '.git')
            if not os.path.exists(git_dir):
                return {
                    'success': False,
                    'error': 'Git repository not found',
                    'branches': [],
                    'commits': []
                }
            
            # ブランチ情報を取得
            branches = self._get_git_branches_data()
            
            # コミット履歴を取得（最新20件）
            try:
                result = subprocess.run([
                    'git', 'log', '--oneline', '--graph', '--decorate', 
                    '--pretty=format:%H|%s|%an|%ad|%D', '--date=iso', '-20'
                ], capture_output=True, text=True, cwd=self.base_dir)
                
                commits = []
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if '|' in line:
                            # グラフ文字を除去してコミット情報を抽出
                            commit_info = line.split('|')
                            if len(commit_info) >= 4:
                                hash_val = commit_info[0].strip().split()[-1]  # 最後の要素がハッシュ
                                message = commit_info[1].strip()
                                author = commit_info[2].strip()
                                date = commit_info[3].strip()
                                refs = commit_info[4].strip() if len(commit_info) > 4 else ''
                                
                                # ブランチ名を推定
                                branch = 'main'
                                if 'origin/' in refs:
                                    branch_match = refs.split('origin/')[-1].split(',')[0].strip()
                                    if branch_match:
                                        branch = branch_match
                                
                                commits.append({
                                    'hash': hash_val,
                                    'message': message,
                                    'author': author,
                                    'date': date,
                                    'branch': branch,
                                    'files': self._get_commit_files(hash_val)
                                })
                
                return {
                    'success': True,
                    'branches': branches,
                    'commits': commits,
                    'last_updated': datetime.now().isoformat()
                }
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Git log command failed: {e}")
                return {
                    'success': False,
                    'error': f'Git log failed: {str(e)}',
                    'branches': branches,
                    'commits': []
                }
                
        except Exception as e:
            self.logger.error(f"Error getting git graph data: {e}")
            return {
                'success': False,
                'error': str(e),
                'branches': [],
                'commits': []
            }

    def _get_git_branches_data(self):
        """Git ブランチデータを取得"""
        try:
            import subprocess
            
            if not os.path.exists('.git'):
                return []
            
            # ブランチ一覧を取得
            result = subprocess.run([
                'git', 'branch', '-a'
            ], capture_output=True, text=True, cwd=self.base_dir)
            
            branches = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if line:
                        is_active = line.startswith('*')
                        branch_name = line.replace('*', '').strip()
                        
                        # リモートブランチの場合は簡略化
                        if 'remotes/origin/' in branch_name:
                            branch_name = branch_name.replace('remotes/origin/', '')
                        
                        # HEADは除外
                        if 'HEAD ->' not in branch_name:
                            branches.append({
                                'name': branch_name,
                                'active': is_active,
                                'type': 'remote' if 'remotes/' in line else 'local'
                            })
            
            return branches
            
        except Exception as e:
            self.logger.error(f"Error getting git branches: {e}")
            return []

    def _update_approval_status(self, appr_id: str, status: str, approver: str, approver_role: str) -> bool:
        """承認ステータスを更新"""
        try:
            approvals_file = os.path.join(self.base_dir, 'STATE', 'APPROVALS.md')
            if not os.path.exists(approvals_file):
                self.logger.error(f"APPROVALS.md not found: {approvals_file}")
                return False
            
            # ファイルを読み込み
            with open(approvals_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # ヘッダー行を探す
            header_found = False
            updated = False
            
            for i, line in enumerate(lines):
                if '| appr_id |' in line:
                    header_found = True
                    continue
                
                if header_found and line.strip() and not line.startswith('|---'):
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 11 and parts[1] == appr_id:
                        # 承認情報を更新
                        parts[4] = status  # status
                        parts[6] = approver  # approver
                        parts[7] = approver_role  # approver_role
                        parts[9] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ts_dec
                        
                        lines[i] = '| ' + ' | '.join(parts[1:-1]) + ' |\n'
                        updated = True
                        break
            
            if updated:
                # ファイルに書き戻し
                with open(approvals_file, 'w', encoding='utf-8') as f:
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
            tasks_file = os.path.join(self.base_dir, 'STATE', 'TASKS.md')
            if not os.path.exists(tasks_file):
                self.logger.error(f"TASKS.md not found: {tasks_file}")
                return False
            
            # ファイルを読み込み
            with open(tasks_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # ヘッダー行を探す
            header_found = False
            updated = False
            
            for i, line in enumerate(lines):
                if '| id |' in line:
                    header_found = True
                    continue
                
                if header_found and line.strip() and not line.startswith('|---'):
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 11 and parts[1] == task_id:
                        # タスクステータスを更新
                        parts[3] = status  # status
                        
                        # HOLD または REVIEW の場合はlock関連をクリア
                        if status in ['HOLD', 'REVIEW']:
                            parts[5] = '-'  # lock
                            parts[6] = '-'  # lock_owner
                            parts[7] = '-'  # lock_expires_at
                        
                        lines[i] = '| ' + ' | '.join(parts[1:-1]) + ' |\n'
                        updated = True
                        break
            
            if updated:
                # ファイルに書き戻し
                with open(tasks_file, 'w', encoding='utf-8') as f:
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
            tasks_file = os.path.join(self.base_dir, 'STATE', 'TASKS.md')
            if not os.path.exists(tasks_file):
                self.logger.error(f"TASKS.md not found: {tasks_file}")
                return False
            
            # 新しいIDを生成（既存の最大ID + 1）
            tasks_data = self._parse_tasks_file()
            max_id = 0
            for task in tasks_data:
                try:
                    task_id = int(task.get('id', 0))
                    max_id = max(max_id, task_id)
                except ValueError:
                    continue
            
            new_id = max_id + 1
            
            # 新しいタスク行を作成
            new_task_line = f"| {new_id} | {title} | PLAN | {owner} | - | - | - | {due_date} | - | {notes} |\n"
            
            # ファイルに追加
            with open(tasks_file, 'a', encoding='utf-8') as f:
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
            
            if not os.path.exists('.git'):
                return None
            
            # コミット詳細を取得
            result = subprocess.run([
                'git', 'show', '--pretty=format:%H|%s|%an|%ae|%ad|%B', 
                '--name-status', commit_sha
            ], capture_output=True, text=True, cwd=self.base_dir)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines:
                    # 最初の行からコミット情報を抽出
                    commit_info = lines[0].split('|')
                    if len(commit_info) >= 5:
                        return {
                            'hash': commit_info[0],
                            'message': commit_info[1],
                            'author': commit_info[2],
                            'email': commit_info[3],
                            'date': commit_info[4],
                            'body': commit_info[5] if len(commit_info) > 5 else '',
                            'files': self._get_commit_files(commit_sha)
                        }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting git commit data: {e}")
            return None

    def _get_commit_files(self, commit_sha):
        """コミットで変更されたファイル一覧を取得"""
        try:
            import subprocess
            
            result = subprocess.run([
                'git', 'show', '--name-status', commit_sha
            ], capture_output=True, text=True, cwd=self.base_dir)
            
            files = []
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            status_char = parts[0].strip()
                            filename = parts[1].strip()
                            
                            status = 'modified'
                            if status_char == 'A':
                                status = 'added'
                            elif status_char == 'D':
                                status = 'deleted'
                            elif status_char == 'M':
                                status = 'modified'
                            
                            files.append({
                                'name': filename,
                                'status': status,
                                'changes': 1  # 簡略化
                            })
            
            return files
            
        except Exception as e:
            self.logger.error(f"Error getting commit files: {e}")
            return []

    def _get_rules_data(self):
        """ルールデータを取得"""
        try:
            rules_data = {
                'rules': [
                    {
                        'id': 'rule_001',
                        'name': 'EOL Rule',
                        'category': 'Format',
                        'status': 'active',
                        'severity': 'high',
                        'description': '改行コード統一（LF固定、*.batのみCRLF）',
                        'violations': 2,
                        'last_check': datetime.now().isoformat()
                    },
                    {
                        'id': 'rule_002',
                        'name': 'Python Rule',
                        'category': 'Code Quality',
                        'status': 'active',
                        'severity': 'medium',
                        'description': 'Black+isort、ログ保存先統一',
                        'violations': 0,
                        'last_check': datetime.now().isoformat()
                    },
                    {
                        'id': 'rule_003',
                        'name': 'PowerShell Rule',
                        'category': 'Security',
                        'status': 'active',
                        'severity': 'high',
                        'description': 'Dry-Run既定、書込は-Applyのみ',
                        'violations': 1,
                        'last_check': datetime.now().isoformat()
                    },
                    {
                        'id': 'rule_004',
                        'name': 'Backup Rule',
                        'category': 'Safety',
                        'status': 'active',
                        'severity': 'high',
                        'description': '変更前にbackups/へ自動保存',
                        'violations': 0,
                        'last_check': datetime.now().isoformat()
                    },
                    {
                        'id': 'rule_005',
                        'name': 'Security Rule',
                        'category': 'Security',
                        'status': 'active',
                        'severity': 'critical',
                        'description': '秘匿情報の除外・暗号化',
                        'violations': 0,
                        'last_check': datetime.now().isoformat()
                    }
                ],
                'statistics': {
                    'total_rules': 5,
                    'active_rules': 5,
                    'inactive_rules': 0,
                    'total_violations': 3,
                    'critical_violations': 0,
                    'high_violations': 3,
                    'medium_violations': 0,
                    'low_violations': 0
                }
            }
            return rules_data
        except Exception as e:
            self.logger.error(f"Error getting rules data: {e}")
            return {'rules': [], 'statistics': {}}

    def _get_rule_violations(self):
        """ルール違反データを取得"""
        try:
            violations_data = {
                'violations': [
                    {
                        'id': 'violation_001',
                        'rule_id': 'rule_001',
                        'rule_name': 'EOL Rule',
                        'file': 'ORCH/templates/orch_dashboard.html',
                        'line': 1654,
                        'severity': 'high',
                        'message': 'CRLF改行コードが検出されました',
                        'detected_at': datetime.now().isoformat(),
                        'status': 'open'
                    },
                    {
                        'id': 'violation_002',
                        'rule_id': 'rule_001',
                        'rule_name': 'EOL Rule',
                        'file': 'ORCH/data/logs/integrated_dashboard.log',
                        'line': 245,
                        'severity': 'high',
                        'message': 'CRLF改行コードが検出されました',
                        'detected_at': datetime.now().isoformat(),
                        'status': 'open'
                    },
                    {
                        'id': 'violation_003',
                        'rule_id': 'rule_003',
                        'rule_name': 'PowerShell Rule',
                        'file': 'scripts/ops/validate_orch_md.py',
                        'line': 89,
                        'severity': 'high',
                        'message': 'Dry-Run既定ルールに違反しています',
                        'detected_at': datetime.now().isoformat(),
                        'status': 'open'
                    }
                ],
                'summary': {
                    'total_violations': 3,
                    'open_violations': 3,
                    'resolved_violations': 0,
                    'critical_count': 0,
                    'high_count': 3,
                    'medium_count': 0,
                    'low_count': 0
                }
            }
            return violations_data
        except Exception as e:
            self.logger.error(f"Error getting rule violations: {e}")
            return {'violations': [], 'summary': {}}

    def _get_system_health_data(self):
        """システムヘルス情報を取得（BIOSデータ含む）"""
        try:
            import psutil
            import platform
            import subprocess
            
            # 基本システム情報
            system_info = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'processor': platform.processor()
            }
            
            # CPU情報
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
                'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                'cpu_usage': psutil.cpu_percent(interval=1),
                'per_core_usage': psutil.cpu_percent(interval=1, percpu=True)
            }
            
            # メモリ情報
            memory = psutil.virtual_memory()
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percentage': memory.percent,
                'total_gb': round(memory.total / (1024**3), 2),
                'available_gb': round(memory.available / (1024**3), 2),
                'used_gb': round(memory.used / (1024**3), 2)
            }
            
            # ディスク情報
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'file_system': partition.fstype,
                        'total': partition_usage.total,
                        'used': partition_usage.used,
                        'free': partition_usage.free,
                        'percentage': round((partition_usage.used / partition_usage.total) * 100, 2),
                        'total_gb': round(partition_usage.total / (1024**3), 2),
                        'used_gb': round(partition_usage.used / (1024**3), 2),
                        'free_gb': round(partition_usage.free / (1024**3), 2)
                    })
                except PermissionError:
                    continue
            
            # ネットワーク情報
            network_info = psutil.net_io_counters()
            network_data = {
                'bytes_sent': network_info.bytes_sent,
                'bytes_recv': network_info.bytes_recv,
                'packets_sent': network_info.packets_sent,
                'packets_recv': network_info.packets_recv,
                'bytes_sent_mb': round(network_info.bytes_sent / (1024**2), 2),
                'bytes_recv_mb': round(network_info.bytes_recv / (1024**2), 2)
            }
            
            # プロセス情報（上位10プロセス）
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # CPU使用率でソート
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            top_processes = processes[:10]
            
            # BIOS/システム詳細情報（Windows）
            bios_info = {}
            if platform.system() == 'Windows':
                try:
                    # WMIを使用してBIOS情報を取得
                    wmi_commands = {
                        'bios': 'wmic bios get Manufacturer,Name,Version,ReleaseDate /format:csv',
                        'motherboard': 'wmic baseboard get Manufacturer,Product,Version /format:csv',
                        'memory': 'wmic memorychip get Capacity,Speed,Manufacturer /format:csv',
                        'cpu_detail': 'wmic cpu get Name,Manufacturer,MaxClockSpeed,NumberOfCores /format:csv'
                    }
                    
                    for key, cmd in wmi_commands.items():
                        try:
                            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
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
                                'label': entry.label or name,
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical
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
            if cpu_info['cpu_usage'] > 80:
                health_score -= 20
                warnings.append("CPU使用率が高い状態です")
            
            # メモリ使用率チェック
            if memory_info['percentage'] > 85:
                health_score -= 15
                warnings.append("メモリ使用率が高い状態です")
            
            # ディスク使用率チェック
            for disk in disk_info:
                if disk['percentage'] > 90:
                    health_score -= 10
                    warnings.append(f"ディスク {disk['device']} の使用率が高い状態です")
            
            health_status = "良好"
            if health_score < 60:
                health_status = "注意"
            elif health_score < 80:
                health_status = "警告"
            
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'health_score': max(0, health_score),
                'health_status': health_status,
                'warnings': warnings,
                'system_info': system_info,
                'cpu_info': cpu_info,
                'memory_info': memory_info,
                'disk_info': disk_info,
                'network_info': network_data,
                'top_processes': top_processes,
                'bios_info': bios_info,
                'temperature_info': temperature_info
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system health data: {e}")
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'health_score': 0,
                'health_status': "エラー",
                'warnings': [f"システム情報の取得に失敗しました: {str(e)}"],
                'error': str(e)
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
            
            self.logger.info(f"ダッシュボードを開始します: http://{self.config.host}:{self.config.port}")
            
            # SocketIOサーバー開始
            self.socketio.run(
                self.app,
                host=self.config.host,
                port=self.config.port,
                debug=self.config.debug,
                allow_unsafe_werkzeug=True
            )
        
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

    def _get_audit_events(self, limit: int = 100, event_type: str = None) -> list:
        """監査イベントを取得"""
        try:
            events = []
            
            # SQLiteデータベースから監査イベントを取得
            db_path = os.path.join(self.base_dir, 'data', 'orch.db')
            if os.path.exists(db_path):
                import sqlite3
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM audit_events"
                params = []
                
                if event_type:
                    query += " WHERE event_type = ?"
                    params.append(event_type)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                
                for row in rows:
                    events.append({
                        'id': row['id'],
                        'event_type': row['event_type'],
                        'user_id': row['user_id'],
                        'resource_type': row['resource_type'],
                        'resource_id': row['resource_id'],
                        'action': row['action'],
                        'details': row['details'],
                        'timestamp': row['timestamp'],
                        'ip_address': row['ip_address']
                    })
                
                conn.close()
            
            # ログファイルからも監査イベントを取得（フォールバック）
            logs_dir = os.path.join(self.base_dir, 'LOGS')
            if os.path.exists(logs_dir):
                # 最新のログファイルを探す
                for root, dirs, files in os.walk(logs_dir):
                    for file in files:
                        if file.endswith('.md') and 'APPROVALS' in file:
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    # ログエントリをパース（簡易実装）
                                    for line in content.split('\n'):
                                        if line.startswith('[') and 'by=' in line:
                                            # ログエントリをイベントとして追加
                                            events.append({
                                                'id': f"log_{len(events)}",
                                                'event_type': 'approval_log',
                                                'user_id': 'system',
                                                'resource_type': 'approval',
                                                'resource_id': '',
                                                'action': 'log_entry',
                                                'details': line,
                                                'timestamp': datetime.utcnow().isoformat(),
                                                'ip_address': '127.0.0.1'
                                            })
                            except Exception as e:
                                self.logger.warning(f"Error reading log file {file_path}: {e}")
            
            return events[:limit]
            
        except Exception as e:
            self.logger.error(f"Error getting audit events: {e}")
            return []

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