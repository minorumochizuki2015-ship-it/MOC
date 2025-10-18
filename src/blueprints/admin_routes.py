"""
Admin Routes Blueprint for ORCH Dashboard
Handles administrative endpoints with enhanced error handling and monitoring
"""

import json
import logging
import platform
import time
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

import psutil
from flask import Blueprint, Response, jsonify, request

# Configure structured logging
logger = logging.getLogger(__name__)


class AdminInitializationError(Exception):
    """Custom exception for Admin initialization failures"""

    pass


class AdminRouteError(Exception):
    """Custom exception for Admin route failures"""

    pass


# Create Blueprint with error handling
try:
    admin_bp = Blueprint("admin", __name__)
    blueprint_info = {
        "event": "admin_blueprint_created",
        "timestamp": datetime.now().isoformat(),
        "blueprint_name": "admin",
    }
    logger.info(f"Admin Blueprint created: {json.dumps(blueprint_info)}")
except Exception as e:
    error_info = {
        "event": "admin_blueprint_creation_failed",
        "timestamp": datetime.now().isoformat(),
        "error": str(e),
        "error_type": type(e).__name__,
    }
    logger.error(f"Failed to create Admin Blueprint: {json.dumps(error_info)}")
    raise


def init_admin_routes(dashboard_instance):
    """Initialize Admin routes with enhanced error handling and monitoring"""
    init_start = time.time()

    try:
        # Log initialization start
        init_info = {
            "event": "admin_routes_init_start",
            "timestamp": datetime.now().isoformat(),
            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
        }
        logger.info(f"Admin routes initialization starting: {json.dumps(init_info)}")

        # Validate dashboard instance
        if dashboard_instance is None:
            raise ValueError("Dashboard instance is required for Admin initialization")

        # Validate dashboard instance type and required methods
        required_methods = ["get_system_status", "get_system_health"]
        optional_methods = ["get_quality_metrics", "get_work_progress"]
        missing_required = []
        missing_optional = []

        for method in required_methods:
            if not hasattr(dashboard_instance, method):
                missing_required.append(method)

        for method in optional_methods:
            if not hasattr(dashboard_instance, method):
                missing_optional.append(method)

        if missing_required:
            validation_error = {
                "event": "admin_dashboard_instance_validation_failed",
                "timestamp": datetime.now().isoformat(),
                "missing_required_methods": missing_required,
                "missing_optional_methods": missing_optional,
                "instance_type": type(dashboard_instance).__name__,
            }
            logger.error(f"Dashboard instance validation failed: {json.dumps(validation_error)}")
            raise ValueError(f"Dashboard instance missing required methods: {missing_required}")

        if missing_optional:
            optional_warning = {
                "event": "admin_dashboard_instance_optional_methods_missing",
                "timestamp": datetime.now().isoformat(),
                "missing_optional_methods": missing_optional,
                "instance_type": type(dashboard_instance).__name__,
            }
            logger.warning(
                f"Dashboard instance missing optional methods: {json.dumps(optional_warning)}"
            )

        # Store dashboard instance reference with error handling
        try:
            admin_bp.dashboard_instance = dashboard_instance
            instance_info = {
                "event": "admin_dashboard_instance_injected",
                "timestamp": datetime.now().isoformat(),
                "instance_type": type(dashboard_instance).__name__,
                "instance_id": id(dashboard_instance),
                "available_methods": [
                    method for method in dir(dashboard_instance) if not method.startswith("_")
                ],
                "required_methods_available": all(
                    hasattr(dashboard_instance, method) for method in required_methods
                ),
                "optional_methods_available": [
                    method for method in optional_methods if hasattr(dashboard_instance, method)
                ],
            }
            logger.info(
                f"Dashboard instance injected into Admin Blueprint: {json.dumps(instance_info)}"
            )
        except Exception as e:
            error_info = {
                "event": "admin_dashboard_instance_injection_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
            raise

        # Initialize Prometheus metrics if available
        try:
            import prometheus_client

            prometheus_available = True
            prometheus_info = {
                "event": "admin_prometheus_available",
                "timestamp": datetime.now().isoformat(),
                "prometheus_version": getattr(prometheus_client, "__version__", "unknown"),
            }
            logger.info(f"Prometheus client available: {json.dumps(prometheus_info)}")
        except ImportError as e:
            prometheus_available = False
            prometheus_warning = {
                "event": "admin_prometheus_unavailable",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
            }
            logger.warning(f"Prometheus client not available: {json.dumps(prometheus_warning)}")

        admin_bp.prometheus_available = prometheus_available

        # Log successful initialization
        init_duration = time.time() - init_start
        success_info = {
            "event": "admin_routes_init_complete",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "dashboard_instance_validated": True,
            "prometheus_available": prometheus_available,
        }
        logger.info(f"Admin routes initialized successfully: {json.dumps(success_info)}")

    except Exception as e:
        # Log initialization failure
        init_duration = time.time() - init_start
        error_info = {
            "event": "admin_routes_init_failed",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"Admin routes initialization failed: {json.dumps(error_info)}")
        raise AdminInitializationError(f"Failed to initialize Admin routes: {e}") from e


@admin_bp.route("/metrics")
def get_metrics():
    """Get Prometheus metrics with enhanced error handling"""
    request_start = time.time()
    request_id = f"metrics_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "admin_metrics_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }
        logger.info(f"Admin metrics request started: {json.dumps(request_info)}")

        # Check if Prometheus is available
        if not getattr(admin_bp, "prometheus_available", False):
            raise AdminRouteError("Prometheus metrics not available")

        # Check if dashboard instance is available
        if not hasattr(admin_bp, "dashboard_instance") or admin_bp.dashboard_instance is None:
            raise AdminRouteError("Dashboard instance not available")

        try:
            import prometheus_client

            # Generate metrics with error handling
            try:
                metrics_output = prometheus_client.generate_latest()

                metrics_info = {
                    "event": "admin_prometheus_metrics_generated",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "metrics_size_bytes": len(metrics_output),
                }
                logger.info(f"Prometheus metrics generated: {json.dumps(metrics_info)}")

                # Log successful response
                request_duration = time.time() - request_start
                success_info = {
                    "event": "admin_metrics_request_complete",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": round(request_duration, 3),
                    "metrics_size_bytes": len(metrics_output),
                }
                logger.info(f"Admin metrics request completed: {json.dumps(success_info)}")

                return Response(metrics_output, mimetype="text/plain")

            except Exception as e:
                # Fallback metrics if generation fails
                fallback_info = {
                    "event": "admin_prometheus_metrics_fallback",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
                logger.warning(
                    f"Using fallback metrics due to generation error: {json.dumps(fallback_info)}"
                )

                fallback_metrics = f"""# HELP admin_request_total Total admin requests
# TYPE admin_request_total counter
admin_request_total{{endpoint="metrics",status="fallback"}} 1
# HELP admin_request_duration_seconds Admin request duration
# TYPE admin_request_duration_seconds histogram
admin_request_duration_seconds_bucket{{endpoint="metrics",le="+Inf"}} 1
admin_request_duration_seconds_sum{{endpoint="metrics"}} {round(time.time() - request_start, 3)}
admin_request_duration_seconds_count{{endpoint="metrics"}} 1
# HELP admin_error_total Total admin errors
# TYPE admin_error_total counter
admin_error_total{{endpoint="metrics",error_type="{type(e).__name__}"}} 1
"""
                return Response(fallback_metrics, mimetype="text/plain")

        except ImportError as e:
            raise AdminRouteError(f"Prometheus client import failed: {e}")

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "admin_metrics_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"Admin metrics request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve metrics",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@admin_bp.route("/system-info")
def get_system_info():
    """Get comprehensive system information with enhanced monitoring"""
    request_start = time.time()
    request_id = f"sysinfo_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "admin_system_info_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }
        logger.info(f"Admin system info request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(admin_bp, "dashboard_instance") or admin_bp.dashboard_instance is None:
            raise AdminRouteError("Dashboard instance not available")

        # Collect comprehensive system information
        system_info = {}

        # Platform information
        try:
            system_info["platform"] = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "timestamp": datetime.now().isoformat(),
            }

            platform_info = {
                "event": "admin_platform_info_collected",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "platform_system": platform.system(),
            }
            logger.info(f"Platform information collected: {json.dumps(platform_info)}")

        except Exception as e:
            system_info["platform"] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

            platform_error_info = {
                "event": "admin_platform_info_error",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(
                f"Platform information collection failed: {json.dumps(platform_error_info)}"
            )

        # System resources
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            system_info["resources"] = {
                "cpu": {
                    "count": psutil.cpu_count(),
                    "count_logical": psutil.cpu_count(logical=True),
                    "percent": round(cpu_percent, 2),
                    "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                },
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "percent_used": round(memory.percent, 2),
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "used_gb": round(disk.used / (1024**3), 2),
                    "percent_used": round((disk.used / disk.total) * 100, 2),
                },
                "timestamp": datetime.now().isoformat(),
            }

            resources_info = {
                "event": "admin_resources_info_collected",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
            }
            logger.info(f"System resources collected: {json.dumps(resources_info)}")

        except Exception as e:
            system_info["resources"] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

            resources_error_info = {
                "event": "admin_resources_info_error",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"System resources collection failed: {json.dumps(resources_error_info)}")

        # Dashboard status
        try:
            dashboard_status = admin_bp.dashboard_instance.get_system_status()
            system_info["dashboard"] = dashboard_status

            dashboard_status_info = {
                "event": "admin_dashboard_status_collected",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "status": (
                    dashboard_status.get("status", "unknown")
                    if isinstance(dashboard_status, dict)
                    else "non_dict_response"
                ),
            }
            logger.info(f"Dashboard status collected: {json.dumps(dashboard_status_info)}")

        except Exception as e:
            system_info["dashboard"] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

            dashboard_error_info = {
                "event": "admin_dashboard_status_error",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Dashboard status collection failed: {json.dumps(dashboard_error_info)}")

        # Compile final response
        response_data = {
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "system_info": system_info,
            "response_time_ms": round((time.time() - request_start) * 1000, 3),
        }

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "admin_system_info_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "info_sections": list(system_info.keys()),
        }
        logger.info(f"Admin system info request completed: {json.dumps(success_info)}")

        return jsonify(response_data)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "admin_system_info_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"Admin system info request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve system information",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@admin_bp.route("/health")
def admin_health_check():
    """Simple Admin health check endpoint"""
    try:
        health_start = time.time()

        # Basic health check
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "admin_version": "1.0.0",
            "dashboard_instance_available": hasattr(admin_bp, "dashboard_instance")
            and admin_bp.dashboard_instance is not None,
            "prometheus_available": getattr(admin_bp, "prometheus_available", False),
            "response_time_ms": round((time.time() - health_start) * 1000, 3),
        }

        # Log health check
        health_info = {
            "event": "admin_health_check",
            "timestamp": datetime.now().isoformat(),
            "status": "healthy",
        }
        logger.info(f"Admin health check completed: {json.dumps(health_info)}")

        return jsonify(health_data)

    except Exception as e:
        # Log health check failure
        error_info = {
            "event": "admin_health_check_failed",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "error_type": type(e).__name__,
        }
        logger.error(f"Admin health check failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}
            ),
            500,
        )


@admin_bp.errorhandler(AdminRouteError)
def handle_admin_route_error(error):
    """Handle Admin route specific errors"""
    error_info = {
        "event": "admin_route_error_handled",
        "timestamp": datetime.now().isoformat(),
        "error": str(error),
        "error_type": type(error).__name__,
    }
    logger.error(f"Admin route error handled: {json.dumps(error_info)}")

    return (
        jsonify(
            {
                "error": "Admin route error",
                "message": str(error),
                "timestamp": datetime.now().isoformat(),
            }
        ),
        500,
    )


@admin_bp.errorhandler(Exception)
def handle_general_error(error):
    """Handle general Admin errors"""
    error_info = {
        "event": "admin_general_error_handled",
        "timestamp": datetime.now().isoformat(),
        "error": str(error),
        "error_type": type(error).__name__,
        "traceback": traceback.format_exc(),
    }
    logger.error(f"Admin general error handled: {json.dumps(error_info)}")

    return (
        jsonify(
            {
                "error": "Internal server error",
                "message": "An unexpected error occurred",
                "timestamp": datetime.now().isoformat(),
            }
        ),
        500,
    )


__all__ = ["admin_bp", "init_admin_routes"]
