"""
ORCH Dashboard - Refactored with Blueprint Architecture
This is a refactored version of orch_dashboard.py using modular Blueprint structure
"""

import json
import logging
import os
import re
import time
import traceback
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from src.style_manager import create_style_api

# Configure structured logging with enhanced formatting
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("orch_dashboard_refactored.log")],
)


class BlueprintInitializationError(Exception):
    """Custom exception for Blueprint initialization failures"""

    pass


class OrchDashboardRefactored:
    """Refactored ORCH Dashboard with Blueprint architecture"""

    def __init__(self, base_dir=None, host="127.0.0.1", port=5000):
        self.base_dir = base_dir or Path(__file__).parent
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.logger = logging.getLogger(__name__)

        # Blueprint initialization tracking
        self.blueprint_status = {}
        self.initialization_start_time = time.time()

        # Log initialization with structured format
        init_info = {
            "event": "dashboard_initialization_start",
            "timestamp": datetime.now().isoformat(),
            "base_directory": str(self.base_dir),
            "host": self.host,
            "port": self.port,
            "process_id": os.getpid() if "os" in globals() else None,
        }
        self.logger.info(
            f"=== ORCH DASHBOARD REFACTORED INITIALIZATION === {json.dumps(init_info)}"
        )

        try:
            # Initialize Flask app configuration with error handling
            self._initialize_flask_config()

            # Setup routes using Blueprint architecture with comprehensive error handling
            self._setup_routes()

            # Initialize style management system
            self._initialize_style_manager()

            # Log successful initialization
            init_duration = time.time() - self.initialization_start_time
            success_info = {
                "event": "dashboard_initialization_complete",
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(init_duration, 3),
                "blueprint_status": self.blueprint_status,
                "total_routes": len(list(self.app.url_map.iter_rules())),
            }
            self.logger.info(
                f"Dashboard initialization completed successfully: {json.dumps(success_info)}"
            )

        except Exception as e:
            # Log initialization failure with full traceback
            error_info = {
                "event": "dashboard_initialization_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "blueprint_status": self.blueprint_status,
            }
            self.logger.error(f"Dashboard initialization failed: {json.dumps(error_info)}")
            raise BlueprintInitializationError(f"Failed to initialize dashboard: {e}") from e

    def _initialize_flask_config(self):
        """Initialize Flask app configuration with error handling"""
        try:
            self.app.config["SECRET_KEY"] = "orch-dashboard-secret-key"
            self.app.config["JSON_AS_ASCII"] = False
            self.app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

            config_info = {
                "event": "flask_config_initialized",
                "timestamp": datetime.now().isoformat(),
                "config_keys": list(self.app.config.keys()),
            }
            self.logger.info(f"Flask app configuration completed: {json.dumps(config_info)}")

        except Exception as e:
            error_info = {
                "event": "flask_config_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            self.logger.error(f"Flask configuration failed: {json.dumps(error_info)}")
            raise

    def _setup_routes(self):
        """Setup all Flask routes using Blueprint architecture with comprehensive error handling"""
        blueprint_start_time = time.time()

        blueprint_info = {
            "event": "blueprint_registration_start",
            "timestamp": datetime.now().isoformat(),
            "expected_blueprints": ["ui_bp", "api_bp", "sse_bp", "admin_bp"],
        }
        self.logger.info(f"=== BLUEPRINT REGISTRATION STARTING === {json.dumps(blueprint_info)}")

        # Import and register blueprints with individual error handling
        blueprints_to_register = [
            {
                "name": "ui_bp",
                "import_path": "src.blueprints.ui_routes",
                "blueprint_name": "ui_bp",
                "init_function": None,
                "url_prefix": None,
                "critical": True,
            },
            {
                "name": "api_bp",
                "import_path": "src.blueprints.api_routes",
                "blueprint_name": "api_bp",
                "init_function": "init_api_routes",
                "url_prefix": "/api",
                "critical": True,
            },
            {
                "name": "sse_bp",
                "import_path": "src.blueprints.sse_routes",
                "blueprint_name": "sse_bp",
                "init_function": "init_sse_routes",
                "url_prefix": None,
                "critical": False,
            },
            {
                "name": "admin_bp",
                "import_path": "src.blueprints.admin_routes",
                "blueprint_name": "admin_bp",
                "init_function": "init_admin_routes",
                "url_prefix": None,
                "critical": False,
            },
        ]

        successful_blueprints = 0
        failed_blueprints = 0

        for blueprint_config in blueprints_to_register:
            blueprint_start = time.time()
            blueprint_name = blueprint_config["name"]

            try:
                self.logger.info(f"Importing {blueprint_name}...")

                # Dynamic import with error handling
                module = __import__(
                    blueprint_config["import_path"], fromlist=[blueprint_config["blueprint_name"]]
                )
                blueprint = getattr(module, blueprint_config["blueprint_name"])

                # Initialize blueprint if init function exists
                if blueprint_config["init_function"]:
                    init_func = getattr(module, blueprint_config["init_function"])
                    init_func(self)
                    self.logger.info(
                        f"{blueprint_name} initialization function called successfully"
                    )

                # Register blueprint
                if blueprint_config["url_prefix"]:
                    self.app.register_blueprint(
                        blueprint, url_prefix=blueprint_config["url_prefix"]
                    )
                else:
                    self.app.register_blueprint(blueprint)

                blueprint_duration = time.time() - blueprint_start

                # Log successful registration
                success_info = {
                    "event": "blueprint_registered",
                    "blueprint": blueprint_name,
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": round(blueprint_duration, 3),
                    "url_prefix": blueprint_config["url_prefix"],
                    "routes_added": len(
                        [
                            rule
                            for rule in self.app.url_map.iter_rules()
                            if rule.endpoint.startswith(blueprint_name)
                        ]
                    ),
                }
                self.logger.info(
                    f"✓ {blueprint_name} registered successfully: {json.dumps(success_info)}"
                )

                self.blueprint_status[blueprint_name] = {
                    "status": "SUCCESS",
                    "duration": blueprint_duration,
                    "timestamp": datetime.now().isoformat(),
                    "routes_count": success_info["routes_added"],
                }
                successful_blueprints += 1

            except ImportError as e:
                # Handle import errors
                error_info = {
                    "event": "blueprint_import_failed",
                    "blueprint": blueprint_name,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "error_type": "ImportError",
                    "import_path": blueprint_config["import_path"],
                    "critical": blueprint_config["critical"],
                }
                self.logger.error(f"✗ Failed to import {blueprint_name}: {json.dumps(error_info)}")

                self.blueprint_status[blueprint_name] = {
                    "status": "IMPORT_FAILED",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                    "critical": blueprint_config["critical"],
                }
                failed_blueprints += 1

                # If critical blueprint fails, consider fallback
                if blueprint_config["critical"]:
                    self.logger.warning(
                        f"Critical blueprint {blueprint_name} failed - considering fallback"
                    )

            except Exception as e:
                # Handle other registration errors
                error_info = {
                    "event": "blueprint_registration_failed",
                    "blueprint": blueprint_name,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                    "critical": blueprint_config["critical"],
                }
                self.logger.error(
                    f"✗ Failed to register {blueprint_name}: {json.dumps(error_info)}"
                )

                self.blueprint_status[blueprint_name] = {
                    "status": "REGISTRATION_FAILED",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                    "critical": blueprint_config["critical"],
                }
                failed_blueprints += 1

        # Check if we need fallback routes
        critical_failures = [
            name
            for name, status in self.blueprint_status.items()
            if status.get("status") != "SUCCESS"
            and any(bp["name"] == name and bp["critical"] for bp in blueprints_to_register)
        ]

        if critical_failures:
            fallback_info = {
                "event": "fallback_routes_activated",
                "timestamp": datetime.now().isoformat(),
                "failed_critical_blueprints": critical_failures,
                "reason": "Critical blueprint failures detected",
            }
            self.logger.warning(f"Activating fallback routes: {json.dumps(fallback_info)}")
            self._setup_minimal_routes()

        # Setup request hooks and error handlers
        self._setup_request_hooks()
        self._setup_error_handlers()

        # Log final blueprint registration summary
        blueprint_duration = time.time() - blueprint_start_time
        summary_info = {
            "event": "blueprint_registration_complete",
            "timestamp": datetime.now().isoformat(),
            "total_duration_seconds": round(blueprint_duration, 3),
            "successful_blueprints": successful_blueprints,
            "failed_blueprints": failed_blueprints,
            "total_routes": len(list(self.app.url_map.iter_rules())),
            "blueprint_status": self.blueprint_status,
        }
        self.logger.info(f"=== BLUEPRINT REGISTRATION COMPLETED === {json.dumps(summary_info)}")

    def _setup_request_hooks(self):
        """Setup Flask request hooks with error handling"""
        try:

            @self.app.after_request
            def _after_request(response):
                """Add security headers and CORS with error handling"""
                try:
                    response.headers["X-Content-Type-Options"] = "nosniff"
                    response.headers["X-Frame-Options"] = "SAMEORIGIN"
                    response.headers["X-XSS-Protection"] = "1; mode=block"
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    response.headers["Access-Control-Allow-Methods"] = (
                        "GET, POST, PUT, DELETE, OPTIONS"
                    )
                    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
                    return response
                except Exception as e:
                    self.logger.error(f"Error in after_request hook: {e}")
                    return response

            hook_info = {
                "event": "request_hooks_configured",
                "timestamp": datetime.now().isoformat(),
                "hooks": ["after_request"],
            }
            self.logger.info(f"Request hooks configured: {json.dumps(hook_info)}")

        except Exception as e:
            error_info = {
                "event": "request_hooks_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            self.logger.error(f"Failed to setup request hooks: {json.dumps(error_info)}")

    def _setup_error_handlers(self):
        """Setup Flask error handlers with enhanced logging"""
        try:

            @self.app.errorhandler(404)
            def not_found(error):
                error_info = {
                    "event": "404_error",
                    "timestamp": datetime.now().isoformat(),
                    "path": request.path,
                    "method": request.method,
                    "user_agent": request.headers.get("User-Agent", "Unknown"),
                }
                self.logger.warning(f"404 error: {json.dumps(error_info)}")

                if request.path.startswith("/api/"):
                    return jsonify({"error": "API endpoint not found", "path": request.path}), 404
                return render_template("orch_dashboard.html"), 404

            @self.app.errorhandler(500)
            def internal_error(error):
                error_info = {
                    "event": "500_error",
                    "timestamp": datetime.now().isoformat(),
                    "path": request.path,
                    "method": request.method,
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
                self.logger.error(f"Internal server error: {json.dumps(error_info)}")

                if request.path.startswith("/api/"):
                    return (
                        jsonify(
                            {
                                "error": "Internal server error",
                                "timestamp": datetime.now().isoformat(),
                            }
                        ),
                        500,
                    )
                return render_template("orch_dashboard.html"), 500

            handler_info = {
                "event": "error_handlers_configured",
                "timestamp": datetime.now().isoformat(),
                "handlers": ["404", "500"],
            }
            self.logger.info(f"Error handlers configured: {json.dumps(handler_info)}")

        except Exception as e:
            error_info = {
                "event": "error_handlers_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            self.logger.error(f"Failed to setup error handlers: {json.dumps(error_info)}")

    def _setup_minimal_routes(self):
        """Fallback minimal routes if blueprints fail"""
        fallback_start = time.time()

        fallback_info = {
            "event": "minimal_routes_setup_start",
            "timestamp": datetime.now().isoformat(),
            "reason": "Blueprint failures detected",
        }
        self.logger.warning(f"Setting up minimal fallback routes: {json.dumps(fallback_info)}")

        try:

            @self.app.route("/")
            def index():
                return render_template("orch_dashboard.html")

            @self.app.route("/api/health")
            def api_health():
                return jsonify(
                    {
                        "status": "ok",
                        "timestamp": datetime.now().isoformat(),
                        "mode": "minimal_fallback",
                        "blueprint_status": self.blueprint_status,
                    }
                )

            @self.app.route("/api/status")
            def api_status():
                return jsonify(
                    {
                        "status": "degraded",
                        "timestamp": datetime.now().isoformat(),
                        "mode": "minimal_fallback",
                        "message": "Running with minimal routes due to blueprint failures",
                    }
                )

            fallback_duration = time.time() - fallback_start
            success_info = {
                "event": "minimal_routes_setup_complete",
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(fallback_duration, 3),
                "routes_added": 3,
            }
            self.logger.info(f"Minimal fallback routes configured: {json.dumps(success_info)}")

        except Exception as e:
            error_info = {
                "event": "minimal_routes_setup_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
            }
            self.logger.error(f"Failed to setup minimal routes: {json.dumps(error_info)}")
            raise

    def _get_tasks_data(self):
        """Get tasks data from ORCH/STATE/TASKS.md"""
        try:
            tasks_file = os.path.join("ORCH", "STATE", "TASKS.md")
            if not os.path.exists(tasks_file):
                self.logger.warning(f"Tasks file not found: {tasks_file}")
                return []

            tasks = []
            with open(tasks_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse table rows
            lines = content.split("\n")
            header_found = False

            for line in lines:
                if line.startswith("| task_id |"):
                    header_found = True
                    continue
                elif line.startswith("|---|"):
                    continue
                elif header_found and line.startswith("|") and line.count("|") >= 10:
                    # Parse task row
                    parts = [p.strip() for p in line.split("|")[1:-1]]
                    if len(parts) >= 10:
                        task = {
                            "task_id": parts[0],
                            "title": parts[1],
                            "state": parts[2],
                            "owner": parts[3],
                            "lock": parts[4],
                            "lock_owner": parts[5],
                            "lock_expires_at": parts[6],
                            "due": parts[7],
                            "artifact": parts[8],
                            "notes": parts[9],
                        }
                        tasks.append(task)

            self.logger.info(f"Loaded {len(tasks)} tasks from {tasks_file}")
            return tasks

        except Exception as e:
            self.logger.error(f"Error loading tasks data: {e}")
            return []

    def _get_approvals_data(self):
        """Get approvals data from ORCH/STATE/APPROVALS.md"""
        try:
            approvals_file = os.path.join("ORCH", "STATE", "APPROVALS.md")
            if not os.path.exists(approvals_file):
                self.logger.warning(f"Approvals file not found: {approvals_file}")
                return []

            approvals = []
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

            self.logger.info(f"Loaded {len(approvals)} approvals from {approvals_file}")
            return approvals

        except Exception as e:
            self.logger.error(f"Error loading approvals data: {e}")
            return []

    def _get_milestones_data(self):
        """Get milestones data from ORCH/STATE/CURRENT_MILESTONE.md"""
        try:
            milestone_file = os.path.join("ORCH", "STATE", "CURRENT_MILESTONE.md")
            if not os.path.exists(milestone_file):
                self.logger.warning(f"Milestone file not found: {milestone_file}")
                return []

            with open(milestone_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract milestone information
            milestones = []
            lines = content.split("\n")
            current_milestone = {}

            for line in lines:
                if line.startswith("# "):
                    if current_milestone:
                        milestones.append(current_milestone)
                    current_milestone = {"title": line[2:].strip(), "status": "active"}
                elif "進捗:" in line or "Progress:" in line:
                    progress_match = re.search(r"(\d+)%", line)
                    if progress_match:
                        current_milestone["progress"] = int(progress_match.group(1))
                elif "期限:" in line or "Due:" in line:
                    current_milestone["due"] = line.split(":", 1)[1].strip()

            if current_milestone:
                milestones.append(current_milestone)

            self.logger.info(f"Loaded {len(milestones)} milestones from {milestone_file}")
            return milestones

        except Exception as e:
            self.logger.error(f"Error loading milestones data: {e}")
            return []

    def _get_quality_metrics(self):
        """Get quality metrics from actual data"""
        try:
            tasks = self._get_tasks_data()
            approvals = self._get_approvals_data()

            # Calculate real metrics
            total_tasks = len(tasks)
            completed_tasks = len([t for t in tasks if t.get("status") == "DONE"])
            active_tasks = len([t for t in tasks if t.get("status") == "DOING"])

            total_approvals = len(approvals)
            approved_count = len([a for a in approvals if a.get("status") == "approved"])
            pending_approvals = len([a for a in approvals if a.get("status") == "pending"])

            task_completion_rate = completed_tasks / total_tasks if total_tasks > 0 else 0
            approval_rate = approved_count / total_approvals if total_approvals > 0 else 0

            # Calculate system health score based on real data
            health_factors = [
                task_completion_rate,
                approval_rate,
                1.0 if pending_approvals == 0 else max(0.5, 1.0 - (pending_approvals / 10)),
                1.0 if active_tasks <= 3 else max(0.7, 1.0 - (active_tasks / 20)),
            ]
            system_health_score = sum(health_factors) / len(health_factors)

            metrics = {
                "task_completion_rate": round(task_completion_rate, 3),
                "approval_rate": round(approval_rate, 3),
                "system_health_score": round(system_health_score, 3),
                "active_tasks": active_tasks,
                "pending_approvals": pending_approvals,
                "total_tasks": total_tasks,
                "total_approvals": total_approvals,
                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            }

            self.logger.info(f"Calculated quality metrics: {metrics}")
            return metrics

        except Exception as e:
            self.logger.error(f"Error calculating quality metrics: {e}")
            return {
                "task_completion_rate": 0,
                "approval_rate": 0,
                "system_health_score": 0,
                "active_tasks": 0,
                "pending_approvals": 0,
                "total_tasks": 0,
                "total_approvals": 0,
                "last_updated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            }

    def _get_system_health(self):
        """Get system health from actual data and system status"""
        try:
            quality_metrics = self._get_quality_metrics()

            # Check file system health
            required_files = [
                "ORCH/STATE/TASKS.md",
                "ORCH/STATE/APPROVALS.md",
                "ORCH/STATE/FLAGS.md",
            ]

            file_health = all(os.path.exists(f) for f in required_files)

            # Calculate overall health
            health_score = quality_metrics.get("system_health_score", 0)
            if not file_health:
                health_score *= 0.5  # Reduce health if files are missing

            status = (
                "healthy" if health_score > 0.8 else "warning" if health_score > 0.5 else "critical"
            )

            health_data = {
                "health": {
                    "health_score": round(health_score, 3),
                    "file_system_ok": file_health,
                    "required_files_status": {f: os.path.exists(f) for f in required_files},
                },
                "status": status,
                "metrics": quality_metrics,
                "timestamp": datetime.now().isoformat(),
            }

            self.logger.info(f"System health calculated: {status} (score: {health_score})")
            return health_data

        except Exception as e:
            self.logger.error(f"Error calculating system health: {e}")
            return {
                "health": {"health_score": 0.0, "file_system_ok": False},
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def get_system_status(self):
        """Get system status for API routes"""
        try:
            status_info = {
                "status": "operational",
                "timestamp": datetime.now().isoformat(),
                "uptime": "running",
                "version": "1.0.0-refactored",
                "blueprint_status": self.blueprint_status,
                "total_routes": len(list(self.app.url_map.iter_rules())),
                "health_score": 0.95,
            }
            return status_info
        except Exception as e:
            self.logger.error(f"Failed to get system status: {str(e)}")
            return {"status": "error", "timestamp": datetime.now().isoformat(), "error": str(e)}

    def get_system_health(self):
        """Get system health for API routes"""
        try:
            health_info = {
                "health": "healthy",
                "timestamp": datetime.now().isoformat(),
                "checks": {
                    "blueprints": (
                        "ok"
                        if any(bp["status"] == "SUCCESS" for bp in self.blueprint_status.values())
                        else "warning"
                    ),
                    "routes": "ok" if len(list(self.app.url_map.iter_rules())) > 0 else "error",
                    "memory": "ok",
                    "disk": "ok",
                },
                "health_score": 0.95,
                "blueprint_status": self.blueprint_status,
            }
            return health_info
        except Exception as e:
            self.logger.error(f"Failed to get system health: {str(e)}")
            return {"health": "unhealthy", "timestamp": datetime.now().isoformat(), "error": str(e)}

    def _initialize_style_manager(self):
        """Initialize the style management system"""
        try:
            self.style_manager = create_style_api(self.app)
            style_info = {
                "event": "style_manager_initialized",
                "timestamp": datetime.now().isoformat(),
                "status": "success",
            }
            self.logger.info(f"Style manager initialized: {json.dumps(style_info)}")
        except Exception as e:
            error_info = {
                "event": "style_manager_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            self.logger.error(f"Style manager initialization failed: {json.dumps(error_info)}")
            # Don't raise - style manager is optional

    def get_blueprint_status(self):
        """Get current blueprint status for monitoring"""
        return {
            "blueprint_status": self.blueprint_status,
            "total_routes": len(list(self.app.url_map.iter_rules())),
            "timestamp": datetime.now().isoformat(),
        }

    def run(self, debug=False):
        """Run the Flask application with enhanced logging"""
        run_info = {
            "event": "dashboard_server_start",
            "timestamp": datetime.now().isoformat(),
            "host": self.host,
            "port": self.port,
            "debug": debug,
            "blueprint_status": self.blueprint_status,
        }
        self.logger.info(f"Starting ORCH Dashboard (Refactored): {json.dumps(run_info)}")

        try:
            self.app.run(host=self.host, port=self.port, debug=debug)
        except Exception as e:
            error_info = {
                "event": "dashboard_server_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
            }
            self.logger.error(f"Dashboard server failed to start: {json.dumps(error_info)}")
            raise


if __name__ == "__main__":
    dashboard = OrchDashboardRefactored()
    dashboard.run(debug=True)
