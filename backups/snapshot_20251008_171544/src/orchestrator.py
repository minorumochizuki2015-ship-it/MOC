#!/usr/bin/env python3
"""
ORCH-Next Orchestrator API
FastAPI-based orchestration service with metrics and webhook support
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .dispatcher import DispatchRequest, TaskDispatcher, TaskPriority, TaskStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("data/logs/orchestrator.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


# Pydantic models
class DispatchRequestModel(BaseModel):
    core_id: str = Field(..., description="Core ID for task assignment")
    stay: bool = Field(False, description="Keep dispatcher lock after dispatch")
    priority: str = Field("medium", description="Task priority: low, medium, high, critical")
    timeout: int = Field(1800, description="Lock timeout in seconds")


class WebhookPayload(BaseModel):
    event: str
    data: Dict[str, Any]
    timestamp: Optional[str] = None


class TaskUpdateModel(BaseModel):
    status: str
    artifact: Optional[str] = None
    notes: Optional[str] = None


# Global metrics storage
metrics_data = {
    "http_requests_total": {},
    "sse_connections_active": 0,
    "webhook_signatures_verified_total": 0,
    "task_duration_seconds": {},
    "dispatch_duration_seconds": {},
    "tasks_dispatched_total": {},
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: replaces deprecated startup/shutdown on_event handlers"""
    # Initialize services on startup
    logger.info("ORCH-Next Orchestrator starting up...")

    # Create data directories
    Path("data/logs").mkdir(parents=True, exist_ok=True)
    Path("data/config").mkdir(parents=True, exist_ok=True)
    Path("data/backups").mkdir(parents=True, exist_ok=True)
    Path("data/metrics").mkdir(parents=True, exist_ok=True)

    # Start background cleanup task
    asyncio.create_task(cleanup_task())

    logger.info("ORCH-Next Orchestrator ready")
    try:
        yield
    finally:
        # Cleanup on shutdown
        logger.info("ORCH-Next Orchestrator shutting down...")


# FastAPI app (with lifespan)
app = FastAPI(
    title="ORCH-Next Orchestrator",
    description="AI-driven orchestration service with Python-first architecture",
    version="1.0.0",
    lifespan=lifespan,
)


def _load_cors_settings():
    """Load CORS settings from config/production.json with safe defaults.

    Returns:
        (enabled, allowed_origins, allow_methods, allow_headers)
    """
    try:
        cfg_path = Path("config/production.json")
        if cfg_path.exists():
            with cfg_path.open("r", encoding="utf-8") as f:
                cfg = json.load(f)
            cors_cfg = cfg.get("security", {}).get("cors", {}) if isinstance(cfg, dict) else {}
            enabled = cors_cfg.get("enabled", True)
            allowed_origins = cors_cfg.get("allowed_origins") or ["*"]
            allow_methods = cors_cfg.get("allowed_methods") or ["*"]
            allow_headers = cors_cfg.get("allowed_headers") or ["*"]
            return enabled, allowed_origins, allow_methods, allow_headers
    except Exception as e:
        logger.warning(f"Failed to load CORS config, using defaults: {e}")

    # Safe defaults (development-friendly). Consider restricting in production.
    return True, ["*"], ["*"], ["*"]


# Apply CORS from config (or fall back to permissive defaults)
_cors_enabled, _origins, _methods, _headers = _load_cors_settings()
if _cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=_methods,
        allow_headers=_headers,
    )

# Global dispatcher instance
dispatcher = TaskDispatcher()


def get_dispatcher() -> TaskDispatcher:
    """Dependency to get dispatcher instance"""
    return dispatcher


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC signature for webhook security"""
    if not signature.startswith("sha256="):
        return False

    expected_signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    received_signature = signature[7:]  # Remove 'sha256=' prefix
    return hmac.compare_digest(expected_signature, received_signature)


def record_http_metric(method: str, endpoint: str, status_code: int):
    """Record HTTP request metrics"""
    key = f"{method}_{endpoint}_{status_code}"
    metrics_data["http_requests_total"][key] = metrics_data["http_requests_total"].get(key, 0) + 1


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware to record HTTP metrics"""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    # Record metrics
    method = request.method
    endpoint = request.url.path
    status_code = response.status_code

    record_http_metric(method, endpoint, status_code)

    # Log request
    logger.info(f"{method} {endpoint} {status_code} {duration:.3f}s")

    return response


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": app.version if hasattr(app, "version") else "unknown",
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def get_metrics():
    """Prometheus-compatible metrics endpoint"""
    lines = []

    # HTTP requests total
    lines.append("# HELP orch_http_requests_total Total HTTP requests")
    lines.append("# TYPE orch_http_requests_total counter")
    for key, value in metrics_data["http_requests_total"].items():
        method, endpoint, status = key.split("_", 2)
        lines.append(
            f'orch_http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {value}'
        )

    # SSE connections
    lines.append("# HELP orch_sse_connections_active Active SSE connections")
    lines.append("# TYPE orch_sse_connections_active gauge")
    lines.append(f"orch_sse_connections_active {metrics_data['sse_connections_active']}")

    # Webhook signatures
    lines.append("# HELP orch_webhook_signatures_verified_total Verified webhook signatures")
    lines.append("# TYPE orch_webhook_signatures_verified_total counter")
    lines.append(
        f"orch_webhook_signatures_verified_total {metrics_data['webhook_signatures_verified_total']}"
    )

    # Task duration (simplified - would need proper histogram in production)
    lines.append("# HELP orch_task_duration_seconds Task execution duration")
    lines.append("# TYPE orch_task_duration_seconds histogram")
    for key, value in metrics_data["task_duration_seconds"].items():
        lines.append(f'orch_task_duration_seconds_sum{{task_id="{key}"}} {value}')

    return "\n".join(lines)


@app.post("/dispatch")
async def dispatch_task(
    request: DispatchRequestModel, dispatcher: TaskDispatcher = Depends(get_dispatcher)
):
    """Dispatch task to worker - replaces PowerShell dispatcher"""
    try:
        priority_map = {
            "low": TaskPriority.LOW,
            "medium": TaskPriority.MEDIUM,
            "high": TaskPriority.HIGH,
            "critical": TaskPriority.CRITICAL,
        }

        dispatch_request = DispatchRequest(
            core_id=request.core_id,
            stay=request.stay,
            priority=priority_map.get(request.priority, TaskPriority.MEDIUM),
            timeout=request.timeout,
        )

        result = dispatcher.dispatch_task(dispatch_request)

        if result["success"]:
            return result
        else:
            raise HTTPException(status_code=404, detail=result["message"])

    except Exception as e:
        logger.error(f"Dispatch error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhook")
async def handle_webhook(
    request: Request, background_tasks: BackgroundTasks, payload: WebhookPayload
):
    """Handle incoming webhooks with HMAC verification"""
    try:
        # Get raw body for signature verification
        body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256", "")

        # In production, get this from environment variable
        webhook_secret = "your-webhook-secret"  # TODO: Move to config

        # Verify signature
        if not verify_webhook_signature(body, signature, webhook_secret):
            logger.warning("Webhook signature verification failed")
            raise HTTPException(status_code=401, detail="Invalid signature")

        metrics_data["webhook_signatures_verified_total"] += 1

        # Process webhook in background
        background_tasks.add_task(process_webhook, payload)

        return {"status": "accepted", "timestamp": datetime.now(timezone.utc).isoformat()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def process_webhook(payload: WebhookPayload):
    """Process webhook payload in background"""
    try:
        logger.info(f"Processing webhook event: {payload.event}")

        # Add your webhook processing logic here
        # For example: trigger tasks, update status, send notifications

        if payload.event == "task_completed":
            # Handle task completion
            pass
        elif payload.event == "system_alert":
            # Handle system alerts
            pass

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")


@app.get("/jobs/{job_id}/events")
async def get_job_events(job_id: str):
    """Get events for a specific job"""
    # TODO: Implement event store query
    return {"job_id": job_id, "events": []}


@app.put("/jobs/{job_id}")
async def update_job(
    job_id: str, update: TaskUpdateModel, dispatcher: TaskDispatcher = Depends(get_dispatcher)
):
    """Update job status and metadata"""
    try:
        status_map = {
            "pending": TaskStatus.PENDING,
            "ready": TaskStatus.READY,
            "doing": TaskStatus.DOING,
            "review": TaskStatus.REVIEW,
            "done": TaskStatus.DONE,
            "hold": TaskStatus.HOLD,
            "drop": TaskStatus.DROP,
        }

        status = status_map.get(update.status)
        if not status:
            raise HTTPException(status_code=400, detail=f"Invalid status: {update.status}")

        # TODO: Get owner from authentication context
        owner = "system"  # Placeholder

        success = dispatcher.update_task_status(
            job_id, status, owner, artifact=update.artifact, notes=update.notes
        )

        if success:
            return {
                "job_id": job_id,
                "status": update.status,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            raise HTTPException(status_code=404, detail="Job not found or not authorized")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Job update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Removed deprecated on_event startup/shutdown handlers in favor of lifespan


async def cleanup_task():
    """Background task for periodic cleanup"""
    while True:
        try:
            dispatcher.cleanup_expired_locks()
            await asyncio.sleep(300)  # Run every 5 minutes
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
            await asyncio.sleep(60)  # Retry after 1 minute on error


def main():
    """Run the orchestrator"""
    uvicorn.run("orchestrator:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main()
