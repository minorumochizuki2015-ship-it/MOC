"""
SSE (Server-Sent Events) Blueprint for ORCH Dashboard
Handles real-time communication with enhanced error handling and monitoring
"""

import json
import logging
import threading
import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional

from flask import Blueprint, Response, jsonify, request

# Note: CORS/Expose headers are applied globally via app.after_request
# (see src/utils/headers.py). Avoid per-route duplication here.

# Configure structured logging
logger = logging.getLogger(__name__)


class SSEConnectionError(Exception):
    """Custom exception for SSE connection failures"""

    pass


class SSEManager:
    """Enhanced SSE Manager with comprehensive error handling and monitoring"""

    def __init__(self):
        self.clients: Dict[str, dict] = {}
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0,
            "total_messages_sent": 0,
            "last_activity": None,
        }
        self.lock = threading.Lock()

        # Log SSE Manager initialization
        init_info = {
            "event": "sse_manager_initialized",
            "timestamp": datetime.now().isoformat(),
            "initial_stats": self.connection_stats,
        }
        logger.info(f"SSE Manager initialized: {json.dumps(init_info)}")

    def add_client(self, client_id: str, request_info: dict = None) -> bool:
        """Add a client with enhanced error handling and monitoring"""
        try:
            with self.lock:
                if client_id in self.clients:
                    # Handle existing client reconnection
                    existing_info = {
                        "event": "sse_client_reconnection",
                        "client_id": client_id,
                        "timestamp": datetime.now().isoformat(),
                        "previous_connection": self.clients[client_id].get("connected_at"),
                        "request_info": request_info,
                    }
                    logger.warning(f"Client reconnection detected: {json.dumps(existing_info)}")

                # Create client record with comprehensive metadata
                client_record = {
                    "connected_at": datetime.now().isoformat(),
                    "last_activity": datetime.now().isoformat(),
                    "message_count": 0,
                    "user_agent": request_info.get("user_agent") if request_info else "Unknown",
                    "remote_addr": request_info.get("remote_addr") if request_info else "Unknown",
                    "connection_id": f"{client_id}_{int(time.time())}",
                }

                self.clients[client_id] = client_record
                self.connection_stats["total_connections"] += 1
                self.connection_stats["active_connections"] = len(self.clients)
                self.connection_stats["last_activity"] = datetime.now().isoformat()

                # Log successful client addition
                success_info = {
                    "event": "sse_client_added",
                    "client_id": client_id,
                    "timestamp": datetime.now().isoformat(),
                    "connection_stats": self.connection_stats,
                    "client_record": client_record,
                }
                logger.info(f"SSE client added successfully: {json.dumps(success_info)}")
                return True

        except Exception as e:
            # Log client addition failure
            error_info = {
                "event": "sse_client_add_failed",
                "client_id": client_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "request_info": request_info,
            }
            logger.error(f"Failed to add SSE client: {json.dumps(error_info)}")
            self.connection_stats["failed_connections"] += 1
            return False

    def remove_client(self, client_id: str, reason: str = "normal_disconnect") -> bool:
        """Remove a client with enhanced logging and cleanup"""
        try:
            with self.lock:
                if client_id in self.clients:
                    client_record = self.clients[client_id]

                    # Calculate connection duration
                    connected_at = datetime.fromisoformat(client_record["connected_at"])
                    duration = (datetime.now() - connected_at).total_seconds()

                    # Log client removal with statistics
                    removal_info = {
                        "event": "sse_client_removed",
                        "client_id": client_id,
                        "timestamp": datetime.now().isoformat(),
                        "reason": reason,
                        "connection_duration_seconds": round(duration, 3),
                        "messages_sent": client_record.get("message_count", 0),
                        "connection_stats_before": dict(self.connection_stats),
                    }

                    del self.clients[client_id]
                    self.connection_stats["active_connections"] = len(self.clients)
                    self.connection_stats["last_activity"] = datetime.now().isoformat()

                    removal_info["connection_stats_after"] = dict(self.connection_stats)
                    logger.info(f"SSE client removed: {json.dumps(removal_info)}")
                    return True
                else:
                    # Log attempt to remove non-existent client
                    warning_info = {
                        "event": "sse_client_remove_not_found",
                        "client_id": client_id,
                        "timestamp": datetime.now().isoformat(),
                        "reason": reason,
                        "active_clients": list(self.clients.keys()),
                    }
                    logger.warning(
                        f"Attempted to remove non-existent SSE client: {json.dumps(warning_info)}"
                    )
                    return False

        except Exception as e:
            # Log client removal failure
            error_info = {
                "event": "sse_client_remove_failed",
                "client_id": client_id,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "reason": reason,
            }
            logger.error(f"Failed to remove SSE client: {json.dumps(error_info)}")
            return False

    def broadcast_message(self, message: dict, target_clients: Optional[List[str]] = None) -> dict:
        """Broadcast message with comprehensive error handling and delivery tracking"""
        broadcast_start = time.time()
        delivery_stats = {"attempted": 0, "successful": 0, "failed": 0, "failed_clients": []}

        try:
            with self.lock:
                # Determine target clients
                if target_clients is None:
                    target_clients = list(self.clients.keys())

                delivery_stats["attempted"] = len(target_clients)

                # Log broadcast start
                broadcast_info = {
                    "event": "sse_broadcast_start",
                    "timestamp": datetime.now().isoformat(),
                    "message_type": message.get("type", "unknown"),
                    "target_clients": target_clients,
                    "total_active_clients": len(self.clients),
                }
                logger.info(f"SSE broadcast starting: {json.dumps(broadcast_info)}")

                # Broadcast to each target client
                for client_id in target_clients:
                    try:
                        if client_id in self.clients:
                            # Update client activity and message count
                            self.clients[client_id]["last_activity"] = datetime.now().isoformat()
                            self.clients[client_id]["message_count"] += 1
                            delivery_stats["successful"] += 1
                        else:
                            delivery_stats["failed"] += 1
                            delivery_stats["failed_clients"].append(
                                {"client_id": client_id, "reason": "client_not_found"}
                            )

                    except Exception as e:
                        delivery_stats["failed"] += 1
                        delivery_stats["failed_clients"].append(
                            {
                                "client_id": client_id,
                                "reason": str(e),
                                "error_type": type(e).__name__,
                            }
                        )

                # Update global statistics
                self.connection_stats["total_messages_sent"] += delivery_stats["successful"]
                self.connection_stats["last_activity"] = datetime.now().isoformat()

                # Log broadcast completion
                broadcast_duration = time.time() - broadcast_start
                completion_info = {
                    "event": "sse_broadcast_complete",
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": round(broadcast_duration, 3),
                    "delivery_stats": delivery_stats,
                    "message_type": message.get("type", "unknown"),
                    "updated_connection_stats": dict(self.connection_stats),
                }
                logger.info(f"SSE broadcast completed: {json.dumps(completion_info)}")

                return {
                    "success": True,
                    "delivery_stats": delivery_stats,
                    "duration_seconds": round(broadcast_duration, 3),
                }

        except Exception as e:
            # Log broadcast failure
            error_info = {
                "event": "sse_broadcast_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "message_type": message.get("type", "unknown"),
                "delivery_stats": delivery_stats,
            }
            logger.error(f"SSE broadcast failed: {json.dumps(error_info)}")

            return {"success": False, "error": str(e), "delivery_stats": delivery_stats}

    def get_connection_stats(self) -> dict:
        """Get comprehensive connection statistics"""
        try:
            with self.lock:
                stats = {
                    "connection_stats": dict(self.connection_stats),
                    "active_clients": {
                        client_id: {
                            "connected_at": client_data["connected_at"],
                            "last_activity": client_data["last_activity"],
                            "message_count": client_data["message_count"],
                            "connection_duration_seconds": round(
                                (
                                    datetime.now()
                                    - datetime.fromisoformat(client_data["connected_at"])
                                ).total_seconds(),
                                3,
                            ),
                        }
                        for client_id, client_data in self.clients.items()
                    },
                    "timestamp": datetime.now().isoformat(),
                }
                return stats

        except Exception as e:
            error_info = {
                "event": "sse_stats_retrieval_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Failed to retrieve SSE stats: {json.dumps(error_info)}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}

    def cleanup_stale_connections(self, max_idle_seconds: int = 300) -> dict:
        """Clean up stale connections with detailed logging"""
        cleanup_start = time.time()
        cleanup_stats = {"checked": 0, "removed": 0, "stale_clients": []}

        try:
            with self.lock:
                current_time = datetime.now()
                clients_to_remove = []

                for client_id, client_data in self.clients.items():
                    cleanup_stats["checked"] += 1
                    last_activity = datetime.fromisoformat(client_data["last_activity"])
                    idle_seconds = (current_time - last_activity).total_seconds()

                    if idle_seconds > max_idle_seconds:
                        clients_to_remove.append(client_id)
                        cleanup_stats["stale_clients"].append(
                            {
                                "client_id": client_id,
                                "idle_seconds": round(idle_seconds, 3),
                                "last_activity": client_data["last_activity"],
                            }
                        )

                # Remove stale clients
                for client_id in clients_to_remove:
                    if self.remove_client(client_id, "stale_connection_cleanup"):
                        cleanup_stats["removed"] += 1

                cleanup_duration = time.time() - cleanup_start

                # Log cleanup results
                cleanup_info = {
                    "event": "sse_stale_cleanup_complete",
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": round(cleanup_duration, 3),
                    "max_idle_seconds": max_idle_seconds,
                    "cleanup_stats": cleanup_stats,
                }
                logger.info(f"SSE stale connection cleanup completed: {json.dumps(cleanup_info)}")

                return cleanup_stats

        except Exception as e:
            error_info = {
                "event": "sse_stale_cleanup_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "cleanup_stats": cleanup_stats,
            }
            logger.error(f"SSE stale connection cleanup failed: {json.dumps(error_info)}")
            return {"error": str(e), "cleanup_stats": cleanup_stats}


# Global SSE manager instance with initialization error handling
try:
    sse_manager = SSEManager()
    manager_init_info = {
        "event": "global_sse_manager_created",
        "timestamp": datetime.now().isoformat(),
        "manager_id": id(sse_manager),
    }
    logger.info(f"Global SSE manager created successfully: {json.dumps(manager_init_info)}")
except Exception as e:
    error_info = {
        "event": "global_sse_manager_creation_failed",
        "timestamp": datetime.now().isoformat(),
        "error": str(e),
        "error_type": type(e).__name__,
        "traceback": traceback.format_exc(),
    }
    logger.error(f"Failed to create global SSE manager: {json.dumps(error_info)}")
    raise SSEConnectionError(f"Failed to initialize SSE manager: {e}") from e

# Create Blueprint with error handling
try:
    sse_bp = Blueprint("sse", __name__)
    blueprint_info = {
        "event": "sse_blueprint_created",
        "timestamp": datetime.now().isoformat(),
        "blueprint_name": "sse",
    }
    logger.info(f"SSE Blueprint created: {json.dumps(blueprint_info)}")
except Exception as e:
    error_info = {
        "event": "sse_blueprint_creation_failed",
        "timestamp": datetime.now().isoformat(),
        "error": str(e),
        "error_type": type(e).__name__,
    }
    logger.error(f"Failed to create SSE Blueprint: {json.dumps(error_info)}")
    raise


def init_sse_routes(dashboard_instance):
    """Initialize SSE routes with enhanced error handling and monitoring"""
    init_start = time.time()

    try:
        # Log initialization start
        init_info = {
            "event": "sse_routes_init_start",
            "timestamp": datetime.now().isoformat(),
            "dashboard_instance_id": id(dashboard_instance) if dashboard_instance else None,
        }
        logger.info(f"SSE routes initialization starting: {json.dumps(init_info)}")

        # Validate dashboard instance
        if dashboard_instance is None:
            raise ValueError("Dashboard instance is required for SSE initialization")

        # Store dashboard instance reference with error handling
        try:
            sse_bp.dashboard_instance = dashboard_instance
            instance_info = {
                "event": "sse_dashboard_instance_injected",
                "timestamp": datetime.now().isoformat(),
                "instance_type": type(dashboard_instance).__name__,
                "instance_id": id(dashboard_instance),
            }
            logger.info(
                f"Dashboard instance injected into SSE Blueprint: {json.dumps(instance_info)}"
            )
        except Exception as e:
            error_info = {
                "event": "sse_dashboard_instance_injection_failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            logger.error(f"Failed to inject dashboard instance: {json.dumps(error_info)}")
            raise

        # Log successful initialization
        init_duration = time.time() - init_start
        success_info = {
            "event": "sse_routes_init_complete",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "manager_stats": sse_manager.get_connection_stats(),
        }
        logger.info(f"SSE routes initialized successfully: {json.dumps(success_info)}")

    except Exception as e:
        # Log initialization failure
        init_duration = time.time() - init_start
        error_info = {
            "event": "sse_routes_init_failed",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(init_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"SSE routes initialization failed: {json.dumps(error_info)}")
        raise SSEConnectionError(f"Failed to initialize SSE routes: {e}") from e


@sse_bp.route("/events")
def events():
    """SSE endpoint with comprehensive error handling and monitoring"""
    connection_start = time.time()
    client_id = f"client_{int(time.time() * 1000)}_{request.remote_addr}"

    try:
        # Log connection attempt
        connection_info = {
            "event": "sse_connection_attempt",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "headers": dict(request.headers),
        }
        logger.info(f"SSE connection attempt: {json.dumps(connection_info)}")

        # Prepare request info for client registration
        request_info = {
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "timestamp": datetime.now().isoformat(),
        }

        # Add client to SSE manager
        if not sse_manager.add_client(client_id, request_info):
            raise SSEConnectionError("Failed to register SSE client")

        def generate():
            """Generate SSE events with error handling"""
            try:
                # Send initial connection confirmation
                initial_message = {
                    "type": "connection_established",
                    "client_id": client_id,
                    "timestamp": datetime.now().isoformat(),
                    "server_info": "ORCH Dashboard SSE",
                }
                yield f"data: {json.dumps(initial_message)}\n\n"

                # Send periodic heartbeat and data
                while True:
                    try:
                        # Check if client still exists
                        if client_id not in sse_manager.clients:
                            break

                        # Send heartbeat
                        heartbeat_message = {
                            "type": "heartbeat",
                            "timestamp": datetime.now().isoformat(),
                            "client_id": client_id,
                            "connection_stats": sse_manager.get_connection_stats(),
                        }
                        yield f"data: {json.dumps(heartbeat_message)}\n\n"

                        time.sleep(30)  # 30-second heartbeat interval

                    except GeneratorExit:
                        # Client disconnected
                        disconnect_info = {
                            "event": "sse_client_generator_exit",
                            "client_id": client_id,
                            "timestamp": datetime.now().isoformat(),
                            "reason": "generator_exit",
                        }
                        logger.info(f"SSE client generator exit: {json.dumps(disconnect_info)}")
                        break
                    except Exception as e:
                        # Log generation error
                        error_info = {
                            "event": "sse_generation_error",
                            "client_id": client_id,
                            "timestamp": datetime.now().isoformat(),
                            "error": str(e),
                            "error_type": type(e).__name__,
                        }
                        logger.error(f"SSE generation error: {json.dumps(error_info)}")
                        break

            except Exception as e:
                # Log generator failure
                error_info = {
                    "event": "sse_generator_failed",
                    "client_id": client_id,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                }
                logger.error(f"SSE generator failed: {json.dumps(error_info)}")
            finally:
                # Clean up client connection
                sse_manager.remove_client(client_id, "generator_cleanup")

        # Create SSE response
        response = Response(generate(), mimetype="text/event-stream")
        # SSE 推奨ヘッダ: ブラウザキャッシュ抑止・プロキシバッファ無効化・持続接続
        response.headers["Cache-Control"] = "no-cache"
        # (WSGI) Do not set hop-by-hop header here
        # response.headers["Connection"] = "keep-alive"
        response.headers["X-Accel-Buffering"] = "no"
        # CORS/Expose はグローバル after_request で適用（重複防止）

        # Log successful connection establishment
        connection_duration = time.time() - connection_start
        success_info = {
            "event": "sse_connection_established",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat(),
            "setup_duration_seconds": round(connection_duration, 3),
            "response_headers": dict(response.headers),
        }
        logger.info(f"SSE connection established: {json.dumps(success_info)}")

        return response

    except Exception as e:
        # Log connection failure
        connection_duration = time.time() - connection_start
        error_info = {
            "event": "sse_connection_failed",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat(),
            "setup_duration_seconds": round(connection_duration, 3),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"SSE connection failed: {json.dumps(error_info)}")

        # Clean up any partial client registration
        sse_manager.remove_client(client_id, "connection_failure")

        return (
            jsonify(
                {
                    "error": "Failed to establish SSE connection",
                    "client_id": client_id,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            500,
        )


@sse_bp.route("/events/health", methods=["GET", "HEAD"])
def events_health():
    """SSE health check endpoint with comprehensive monitoring
    Return a single SSE frame to validate headers in tests and monitoring.
    """
    try:
        health_start = time.time()

        # Collect stats for logging
        stats = sse_manager.get_connection_stats()

        # Compose a single SSE-style message
        payload = {
            "event": "health",
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "active_connections": stats.get("connection_stats", {}).get("active_connections", 0),
        }
        body = f"data: {json.dumps(payload)}\n\n"

        # Build SSE response with recommended headers
        # NOTE: Explicitly set mimetype to ensure correct Content-Type under Waitress
        # and to avoid HEAD handling inconsistencies.
        resp = Response(body, mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-cache"
        # (WSGI) Do not set hop-by-hop header here
        # resp.headers["Connection"] = "keep-alive"
        resp.headers["X-Accel-Buffering"] = "no"
        # CORS/Expose はグローバル after_request で適用（重複防止）

        # Log health check
        health_duration = time.time() - health_start
        health_info = {
            "event": "sse_health_check",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(health_duration, 3),
            "active_connections": payload["active_connections"],
        }
        logger.info(f"SSE health check completed: {json.dumps(health_info)}")

        return resp

    except Exception as e:
        # Log failure and return JSON error for easier debugging
        error_info = {
            "event": "sse_health_check_failed",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.error(f"SSE health check failed: {json.dumps(error_info)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@sse_bp.route("/events/stats")
def events_stats():
    """Get detailed SSE statistics"""
    try:
        stats = sse_manager.get_connection_stats()

        stats_info = {
            "event": "sse_stats_requested",
            "timestamp": datetime.now().isoformat(),
            "active_connections": stats.get("connection_stats", {}).get("active_connections", 0),
        }
        logger.info(f"SSE stats requested: {json.dumps(stats_info)}")

        return jsonify(stats)

    except Exception as e:
        error_info = {
            "event": "sse_stats_request_failed",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "error_type": type(e).__name__,
        }
        logger.error(f"SSE stats request failed: {json.dumps(error_info)}")

        return jsonify({"error": str(e), "timestamp": datetime.now().isoformat()}), 500
