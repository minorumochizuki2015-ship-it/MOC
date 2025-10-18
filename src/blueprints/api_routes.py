"""
API Routes Blueprint for ORCH Dashboard
Handles all API endpoints with enhanced error handling and monitoring
"""

import json
import logging
import platform
import time
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

import psutil
from flask import Blueprint, jsonify, request

# Configure structured logging
logger = logging.getLogger(__name__)


class APIInitializationError(Exception):
    """Custom exception for API initialization failures"""

    pass


class APIRouteError(Exception):
    """Custom exception for API route failures"""

    pass


# Create Blueprint with error handling
try:
    api_bp = Blueprint("api", __name__)
    blueprint_info = {
        "event": "api_blueprint_created",
        "timestamp": datetime.now().isoformat(),
        "blueprint_name": "api",
    }
    logger.info(f"API Blueprint created: {json.dumps(blueprint_info)}")
except Exception as e:
    error_info = {
        "event": "api_blueprint_creation_failed",
        "timestamp": datetime.now().isoformat(),
        "error": str(e),
        "error_type": type(e).__name__,
    }
    logger.error(f"Failed to create API Blueprint: {json.dumps(error_info)}")
    raise


def init_api_routes(dashboard_instance):
    """Initialize API routes with enhanced error handling and monitoring"""
    init_start = time.time()

    try:
        # Log initialization start
        init_info = {
            "event": "api_routes_init_start",
            "timestamp": datetime.now().isoformat(),
            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
        }
        logger.info(f"API routes initialization starting: {json.dumps(init_info)}")

        # Validate dashboard instance
        if dashboard_instance is None:
            raise ValueError("Dashboard instance is required for API initialization")

        # Validate dashboard instance type and required methods
        required_methods = ["get_system_status", "get_system_health"]
        missing_methods = []

        for method in required_methods:
            if not hasattr(dashboard_instance, method):
                missing_methods.append(method)

        if missing_methods:
            validation_error = {
                "event": "api_dashboard_instance_validation_failed",
                "timestamp": datetime.now().isoformat(),
                "missing_methods": missing_methods,
                "instance_type": type(dashboard_instance).__name__,
            }
            logger.error(f"Dashboard instance validation failed: {json.dumps(validation_error)}")
            raise ValueError(f"Dashboard instance missing required methods: {missing_methods}")

        # Store dashboard instance reference with error handling
        try:
            api_bp.dashboard_instance = dashboard_instance
            instance_info = {
                "event": "api_dashboard_instance_injected",
                "timestamp": datetime.now().isoformat(),
                "instance_type": type(dashboard_instance).__name__,
                "instance_id": id(dashboard_instance),
                "available_methods": [
                    method for method in dir(dashboard_instance) if not method.startswith("_")
                ],
            }
            logger.info(
                f"Dashboard instance injected into API Blueprint: {json.dumps(instance_info)}"
            )
        except Exception as e:
            error_info = {
                "event": "api_dashboard_instance_injection_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
            raise

        # Log successful initialization
        init_duration = time.time() - init_start
        success_info = {
            "event": "api_routes_init_complete",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "dashboard_instance_validated": True,
        }
        logger.info(f"API routes initialized successfully: {json.dumps(success_info)}")

    except Exception as e:
        # Log initialization failure
        init_duration = time.time() - init_start
        error_info = {
            "event": "api_routes_init_failed",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API routes initialization failed: {json.dumps(error_info)}")
        raise APIInitializationError(f"Failed to initialize API routes: {e}") from e


@api_bp.route("/status")
def get_status():
    """Get system status with comprehensive error handling"""
    request_start = time.time()
    request_id = f"status_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "api_status_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }
        logger.info(f"API status request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
            raise APIRouteError("Dashboard instance not available")

        # Get status from dashboard instance with error handling
        try:
            dashboard_status = api_bp.dashboard_instance.get_system_status()
            status_retrieval_info = {
                "event": "api_dashboard_status_retrieved",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "status_keys": (
                    list(dashboard_status.keys())
                    if isinstance(dashboard_status, dict)
                    else "non_dict_response"
                ),
            }
            logger.info(f"Dashboard status retrieved: {json.dumps(status_retrieval_info)}")
        except Exception as e:
            # Fallback status if dashboard method fails
            fallback_info = {
                "event": "api_dashboard_status_fallback",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.warning(
                f"Using fallback status due to dashboard error: {json.dumps(fallback_info)}"
            )

            dashboard_status = {
                "status": "degraded",
                "message": "Dashboard status method failed",
                "error": str(e),
                "fallback": True,
            }

        # Enhance status with additional system information
        try:
            enhanced_status = {
                **dashboard_status,
                "api_info": {
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "response_time_ms": round((time.time() - request_start) * 1000, 3),
                },
                "system_info": {
                    "platform": platform.system(),
                    "python_version": platform.python_version(),
                    "cpu_count": psutil.cpu_count(),
                    "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                },
            }
        except Exception as e:
            # Log enhancement failure but continue with basic status
            enhancement_error = {
                "event": "api_status_enhancement_failed",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.warning(f"Status enhancement failed: {json.dumps(enhancement_error)}")
            enhanced_status = dashboard_status

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "api_status_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "status_type": enhanced_status.get("status", "unknown"),
        }
        logger.info(f"API status request completed: {json.dumps(success_info)}")

        return jsonify(enhanced_status)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "api_status_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API status request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve system status",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@api_bp.route("/system-health")
def get_system_health():
    """Get comprehensive system health with enhanced monitoring"""
    request_start = time.time()
    request_id = f"health_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "api_health_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }
        logger.info(f"API health request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
            raise APIRouteError("Dashboard instance not available")

        # Collect comprehensive health metrics
        health_metrics = {}

        # Get dashboard health
        try:
            dashboard_health = api_bp.dashboard_instance.get_system_health()
            health_metrics["dashboard"] = dashboard_health

            dashboard_health_info = {
                "event": "api_dashboard_health_retrieved",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "health_status": (
                    dashboard_health.get("status", "unknown")
                    if isinstance(dashboard_health, dict)
                    else "non_dict_response"
                ),
            }
            logger.info(f"Dashboard health retrieved: {json.dumps(dashboard_health_info)}")
        except Exception as e:
            health_metrics["dashboard"] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

            dashboard_error_info = {
                "event": "api_dashboard_health_error",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Dashboard health retrieval failed: {json.dumps(dashboard_error_info)}")

        # Get system metrics
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            health_metrics["system"] = {
                "cpu_percent": round(cpu_percent, 2),
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "percent_used": round(memory.percent, 2),
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "percent_used": round((disk.used / disk.total) * 100, 2),
                },
                "timestamp": datetime.now().isoformat(),
            }

            system_metrics_info = {
                "event": "api_system_metrics_collected",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
            }
            logger.info(f"System metrics collected: {json.dumps(system_metrics_info)}")

        except Exception as e:
            health_metrics["system"] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

            system_error_info = {
                "event": "api_system_metrics_error",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"System metrics collection failed: {json.dumps(system_error_info)}")

        # Determine overall health status
        overall_status = "healthy"
        if health_metrics.get("dashboard", {}).get("status") == "error":
            overall_status = "degraded"
        if health_metrics.get("system", {}).get("status") == "error":
            overall_status = "critical" if overall_status == "degraded" else "degraded"

        # Compile final health response
        health_response = {
            "overall_status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "metrics": health_metrics,
            "response_time_ms": round((time.time() - request_start) * 1000, 3),
        }

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "api_health_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "overall_status": overall_status,
        }
        logger.info(f"API health request completed: {json.dumps(success_info)}")

        return jsonify(health_response)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "api_health_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API health request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve system health",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@api_bp.route("/tasks")
def get_tasks():
    """Get tasks data from ORCH/STATE/TASKS.md"""
    request_start = time.time()
    request_id = f"tasks_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "api_tasks_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
        }
        logger.info(f"API tasks request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
            raise APIRouteError("Dashboard instance not available")

        # Get tasks data from dashboard instance
        try:
            tasks_data = api_bp.dashboard_instance._get_tasks_data()

            tasks_info = {
                "event": "api_tasks_data_retrieved",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0,
            }
            logger.info(f"Tasks data retrieved: {json.dumps(tasks_info)}")
        except Exception as e:
            raise APIRouteError(f"Failed to retrieve tasks data: {e}")

        # Prepare response
        response_data = {
            "tasks": tasks_data,
            "count": len(tasks_data) if isinstance(tasks_data, list) else 0,
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "response_time_ms": round((time.time() - request_start) * 1000, 3),
        }

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "api_tasks_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "tasks_count": len(tasks_data) if isinstance(tasks_data, list) else 0,
        }
        logger.info(f"API tasks request completed: {json.dumps(success_info)}")

        return jsonify(response_data)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "api_tasks_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API tasks request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve tasks",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@api_bp.route("/approvals")
def get_approvals():
    """Get approvals data from ORCH/STATE/APPROVALS.md"""
    request_start = time.time()
    request_id = f"approvals_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "api_approvals_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
        }
        logger.info(f"API approvals request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
            raise APIRouteError("Dashboard instance not available")

        # Get approvals data from dashboard instance
        try:
            approvals_data = api_bp.dashboard_instance._get_approvals_data()

            approvals_info = {
                "event": "api_approvals_data_retrieved",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0,
            }
            logger.info(f"Approvals data retrieved: {json.dumps(approvals_info)}")
        except Exception as e:
            raise APIRouteError(f"Failed to retrieve approvals data: {e}")

        # Prepare response
        response_data = {
            "approvals": approvals_data,
            "count": len(approvals_data) if isinstance(approvals_data, list) else 0,
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "response_time_ms": round((time.time() - request_start) * 1000, 3),
        }

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "api_approvals_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "approvals_count": len(approvals_data) if isinstance(approvals_data, list) else 0,
        }
        logger.info(f"API approvals request completed: {json.dumps(success_info)}")

        return jsonify(response_data)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "api_approvals_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API approvals request failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {
                    "error": "Failed to retrieve approvals",
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "details": str(e),
                }
            ),
            500,
        )


@api_bp.route("/metrics")
def get_metrics():
    """Get quality metrics from actual data"""
    request_start = time.time()
    request_id = f"metrics_{int(time.time() * 1000)}"

    try:
        # Log request start
        request_info = {
            "event": "api_metrics_request_start",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
        }
        logger.info(f"API metrics request started: {json.dumps(request_info)}")

        # Check if dashboard instance is available
        if not hasattr(api_bp, "dashboard_instance") or api_bp.dashboard_instance is None:
            raise APIRouteError("Dashboard instance not available")

        # Get metrics data from dashboard instance
        try:
            metrics_data = api_bp.dashboard_instance._get_quality_metrics()

            metrics_info = {
                "event": "api_metrics_data_retrieved",
                "request_id": request_id,
                "timestamp": datetime.now().isoformat(),
                "metrics_keys": (
                    list(metrics_data.keys())
                    if isinstance(metrics_data, dict)
                    else "non_dict_response"
                ),
            }
            logger.info(f"Metrics data retrieved: {json.dumps(metrics_info)}")
        except Exception as e:
            raise APIRouteError(f"Failed to retrieve metrics data: {e}")

        # Prepare response
        response_data = {
            "metrics": metrics_data,
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "response_time_ms": round((time.time() - request_start) * 1000, 3),
        }

        # Log successful response
        request_duration = time.time() - request_start
        success_info = {
            "event": "api_metrics_request_complete",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
        }
        logger.info(f"API metrics request completed: {json.dumps(success_info)}")

        return jsonify(response_data)

    except Exception as e:
        # Log request failure
        request_duration = time.time() - request_start
        error_info = {
            "event": "api_metrics_request_failed",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(request_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"API metrics request failed: {json.dumps(error_info)}")

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


@api_bp.route("/health")
def api_health_check():
    """Simple API health check endpoint"""
    try:
        health_start = time.time()

        # Basic health check
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "api_version": "1.0.0",
            "dashboard_instance_available": hasattr(api_bp, "dashboard_instance")
            and api_bp.dashboard_instance is not None,
            "response_time_ms": round((time.time() - health_start) * 1000, 3),
        }

        # Log health check
        health_info = {
            "event": "api_health_check",
            "timestamp": datetime.now().isoformat(),
            "status": "healthy",
        }
        logger.info(f"API health check completed: {json.dumps(health_info)}")

        return jsonify(health_data)

    except Exception as e:
        # Log health check failure
        error_info = {
            "event": "api_health_check_failed",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "error_type": type(e).__name__,
        }
        logger.error(f"API health check failed: {json.dumps(error_info)}")

        return (
            jsonify(
                {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}
            ),
            500,
        )


@api_bp.errorhandler(APIRouteError)
def handle_api_route_error(error):
    """Handle API route specific errors"""
    error_info = {
        "event": "api_route_error_handled",
        "timestamp": datetime.now().isoformat(),
        "error": str(error),
        "error_type": type(error).__name__,
    }
    logger.error(f"API route error handled: {json.dumps(error_info)}")

    return (
        jsonify(
            {
                "error": "API route error",
                "message": str(error),
                "timestamp": datetime.now().isoformat(),
            }
        ),
        500,
    )


@api_bp.errorhandler(Exception)
def handle_general_error(error):
    """Handle general API errors"""
    error_info = {
        "event": "api_general_error_handled",
        "timestamp": datetime.now().isoformat(),
        "error": str(error),
        "error_type": type(error).__name__,
        "traceback": traceback.format_exc(),
    }
    logger.error(f"API general error handled: {json.dumps(error_info)}")

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


__all__ = ["api_bp", "init_api_routes"]
