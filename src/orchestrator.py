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
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .dispatcher import DispatchRequest, TaskDispatcher, TaskPriority, TaskStatus
from .workflows_api import router as workflows_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("data/logs/orchestrator.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


# Pydantic models
class DispatchRequestModel(BaseModel):
    core_id: str = Field(..., description="Core ID for task assignment", alias="coreId")
    stay: bool = Field(False, description="Keep dispatcher lock after dispatch")
    priority: Union[str, int] = Field(
        "medium", description="Task priority: low, medium, high, critical or numeric 1-4"
    )
    timeout: int = Field(1800, description="Lock timeout in seconds")

    class Config:
        allow_population_by_field_name = True
        extra = "allow"


class WebhookPayload(BaseModel):
    event: str
    data: Dict[str, Any]
    timestamp: Optional[Union[str, int, float]] = None


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
    # Use injected dispatcher if available (for testing)
    if hasattr(app.state, 'dispatcher'):
        return app.state.dispatcher
    return dispatcher

# Register routers
app.include_router(workflows_router)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC signature for webhook security

    Supports both GitHub-style header (X-Hub-Signature-256: sha256=<hex>) and
    compact header style (X-Signature: t=<ts>,v1=<hex>) used in tests.
    """
    try:
        if not signature:
            return False

        # GitHub style
        if signature.startswith("sha256="):
            expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            received = signature[7:]  # Remove 'sha256=' prefix
            return hmac.compare_digest(expected, received)

        # Compact style: "t=<timestamp>,v1=<signature>"
        if "t=" in signature and "v1=" in signature:
            # Parse simple comma-separated key=value pairs
            parts = {}
            for seg in signature.split(","):
                if "=" in seg:
                    k, v = seg.split("=", 1)
                    parts[k.strip()] = v.strip()
            ts = parts.get("t")
            sig_v1 = parts.get("v1")
            if ts is None or sig_v1 is None:
                return False

            # Build message as f"{timestamp}.{json_payload}" with compact separators
            json_payload = json.dumps(json.loads(payload.decode("utf-8")), sort_keys=True, separators=(",", ":"))
            message = f"{ts}.{json_payload}".encode("utf-8")
            expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, sig_v1)

        return False
    except Exception:
        return False


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

    # Agents metrics (synchronized with registry)
    try:
        lines.append("# HELP orch_agents_total Total number of agents")
        lines.append("# TYPE orch_agents_total gauge")
        # Load registry from known locations and merge to reflect actual active agents
        import json as _json
        import time as _time
        from datetime import datetime as _dt
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent  # ORCH-Next
        reg_paths = [
            root / "data" / "agents_registry.json",  # ORCH-Next registry
            root.parent / "MOC" / "ORCH" / "data" / "agents_registry.json",  # MOC ORCH registry
        ]
        agents = []
        for rp in reg_paths:
            try:
                if rp.exists():
                    loaded = _json.loads(rp.read_text(encoding="utf-8")) or []
                    by_id = {a.get("id"): a for a in agents if a.get("id") is not None}
                    for a in loaded:
                        aid = a.get("id")
                        if aid is None:
                            continue
                        by_id[aid] = a
                    agents = list(by_id.values())
            except Exception:
                pass
        lines.append(f"orch_agents_total {len(agents)}")

        # Status breakdown
        lines.append("# HELP orch_agents_status Agents per status")
        lines.append("# TYPE orch_agents_status gauge")
        try:
            from collections import Counter as _Counter

            status_counts = _Counter([(a.get("status") or "unknown") for a in agents])
        except Exception:
            status_counts = {}
        for st, cnt in status_counts.items():
            lines.append(f'orch_agents_status{{status="{st}"}} {cnt}')

        # Max heartbeat age seconds
        lines.append(
            "# HELP orch_agents_heartbeat_age_max_seconds Max seconds since last heartbeat across agents"
        )
        lines.append("# TYPE orch_agents_heartbeat_age_max_seconds gauge")
        try:
            now = _time.time()
            ages = []
            for a in agents:
                ts = a.get("heartbeat_at") or a.get("updated_at")
                if ts:
                    if isinstance(ts, (int, float)):
                        ages.append(max(0, now - float(ts)))
                    else:
                        try:
                            dt = _dt.fromisoformat(str(ts).replace("Z", ""))
                            ages.append(max(0, now - dt.timestamp()))
                        except Exception:
                            pass
            max_age = max(ages) if ages else 0
        except Exception:
            max_age = 0
        lines.append(f"orch_agents_heartbeat_age_max_seconds {max_age}")

        # Agents API audit (if summary JSON available)
        lines.append("# HELP orch_agents_api_audit_total Agents API audit total checks")
        lines.append("# TYPE orch_agents_api_audit_total gauge")
        lines.append("# HELP orch_agents_api_audit_failures Agents API audit failure count")
        lines.append("# TYPE orch_agents_api_audit_failures gauge")
        try:
            audit_json = root / "ORCH" / "REPORTS" / "agents_api_audit_summary.json"
            if audit_json.exists():
                data = _json.loads(audit_json.read_text(encoding="utf-8"))
                total = int(data.get("total_checks", 0))
                ok = int(data.get("ok_checks", 0))
                errors = int(data.get("error_checks", 0))
                fail_count = errors if errors else max(0, total - ok)
                lines.append(f"orch_agents_api_audit_total {total}")
                lines.append(f"orch_agents_api_audit_failures {fail_count}")
            else:
                lines.append("orch_agents_api_audit_total 0")
                lines.append("orch_agents_api_audit_failures 0")
        except Exception:
            lines.append("orch_agents_api_audit_total 0")
            lines.append("orch_agents_api_audit_failures 0")
    except Exception:
        # If agents metrics block fails, continue outputting other metrics
        pass

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

        # Accept numeric priority values 1-4 as well as string labels
        if isinstance(request.priority, int):
            prio = TaskPriority(max(1, min(4, request.priority)))
        else:
            prio = priority_map.get(str(request.priority).lower(), TaskPriority.MEDIUM)

        dispatch_request = DispatchRequest(
            core_id=request.core_id,
            stay=request.stay,
            priority=prio,
            timeout=request.timeout,
        )

        result = dispatcher.dispatch_task(dispatch_request)

        if result["success"]:
            # Record a dispatch event for this task
            try:
                task_id = result.get("task_id")
                if task_id:
                    global _job_events_store
                    try:
                        _job_events_store.setdefault(task_id, []).append(
                            {
                                "event_id": str(uuid.uuid4()),
                                "task_id": task_id,
                                "event_type": "dispatch",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                    except NameError:
                        globals()["_job_events_store"] = {}
                        _job_events_store[task_id] = [
                            {
                                "event_id": str(uuid.uuid4()),
                                "task_id": task_id,
                                "event_type": "dispatch",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        ]
            except Exception:
                pass
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
        signature = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Signature", "")

        # Load secret from app.state.config if available, else fallback to production.json, else default
        webhook_secret = None
        try:
            if hasattr(app.state, "config") and isinstance(app.state.config, dict):
                webhook_secret = (app.state.config.get("webhook") or {}).get("secret")
        except Exception:
            webhook_secret = None
        if not webhook_secret:
            try:
                cfg_path = Path("config/production.json")
                if cfg_path.exists():
                    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                    webhook_secret = (cfg.get("webhook") or {}).get("secret")
            except Exception:
                webhook_secret = None
        if not webhook_secret:
            webhook_secret = "your-webhook-secret"

        # Verify signature
        if not verify_webhook_signature(body, signature, webhook_secret):
            logger.warning("Webhook signature verification failed")
            raise HTTPException(status_code=401, detail="Invalid signature")

        metrics_data["webhook_signatures_verified_total"] += 1

        # Process webhook in background
        background_tasks.add_task(process_webhook, payload)

        return {"status": "received", "event_id": str(uuid.uuid4())}

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
    # Simple in-memory event store for integration tests
    global _job_events_store
    try:
        events = _job_events_store.get(job_id, [])
    except NameError:
        _job_events_store = {}
        events = []
    return {"job_id": job_id, "events": events}


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


class JobStatusUpdateModel(BaseModel):
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@app.put("/jobs/{job_id}/status")
async def update_job_status(
    job_id: str, update: JobStatusUpdateModel, dispatcher: TaskDispatcher = Depends(get_dispatcher)
):
    """Update job status (integration test compatibility)"""
    try:
        status_map = {
            "pending": TaskStatus.PENDING,
            "ready": TaskStatus.READY,
            "running": TaskStatus.DOING,
            "doing": TaskStatus.DOING,
            "review": TaskStatus.REVIEW,
            "completed": TaskStatus.DONE,
            "success": TaskStatus.DONE,
            "done": TaskStatus.DONE,
            "hold": TaskStatus.HOLD,
            "failed": TaskStatus.DROP,
            "error": TaskStatus.DROP,
            "drop": TaskStatus.DROP,
        }

        status = status_map.get(update.status.lower())
        if not status:
            raise HTTPException(status_code=400, detail=f"Invalid status: {update.status}")

        owner = "system"
        success = dispatcher.update_task_status(job_id, status, owner)

        if success:
            # Record event
            try:
                _job_events_store.setdefault(job_id, []).append(
                    {
                        "event_id": str(uuid.uuid4()),
                        "task_id": job_id,
                        "event_type": "status_update",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": status.value,
                        "progress": update.progress,
                        "message": update.message,
                    }
                )
            except NameError:
                # Initialize store lazily
                globals()["_job_events_store"] = {}
                _job_events_store[job_id] = [
                    {
                        "event_id": str(uuid.uuid4()),
                        "task_id": job_id,
                        "event_type": "status_update",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": status.value,
                        "progress": update.progress,
                        "message": update.message,
                    }
                ]
            return {"status": "updated", "task_id": job_id}
        else:
            raise HTTPException(status_code=404, detail="Job not found or not authorized")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Job status update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def main():
    """Run the orchestrator"""
    uvicorn.run("orchestrator:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main()
