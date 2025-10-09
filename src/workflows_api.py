"""
Workflow API (Phase 4)

FastAPI router providing minimal, safe workflow endpoints.
This implementation wires the YAML-based DSL loader and the no-op
WorkflowEngine to allow definition-based execution without side effects.

Endpoints (stable, subject to expansion):
- GET /api/workflows/            → List available workflows (stub)
- POST /api/workflows/run        → Run a workflow from YAML text
- GET /api/workflows/approvals   → List pending approvals (stub)
- POST /api/workflows/approvals  → Record an approval decision (stub)

Security: kept minimal for initial stub; integrate src.security
dependencies in subsequent iterations.
"""

from __future__ import annotations

import glob
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .security import SecurityManager, User, UserRole, get_current_user, require_role
from .workflow_dsl import WorkflowDSLException, load_workflow_definition
from .workflow_engine import WorkflowEngine, WorkflowResult


class ApprovalDecision(BaseModel):
    appr_id: str
    task_id: str
    op: str
    status: str  # "approved" or "rejected"
    requested_by: str
    approver: str
    approver_role: str  # "CMD" or "AUDIT"
    ts_req: str  # ISO8601 timestamp
    ts_dec: str  # ISO8601 timestamp
    evidence: str


class WorkflowCatalogItem(BaseModel):
    """Workflow catalog entry with metadata"""
    file_path: str
    name: str
    description: str
    version: str
    author: str
    tags: List[str]
    created_at: str
    metadata: Dict[str, Any]
    workflow_steps: int
    complexity: str
    estimated_duration_minutes: int
    requires_approval: bool
    risk_level: str


router = APIRouter(prefix="/api/workflows", tags=["workflows"])

# Workflow execution metrics
class WorkflowMetrics:
    def __init__(self):
        self.execution_count = 0
        self.execution_duration_total = 0.0
        self.execution_success_count = 0
        self.execution_failure_count = 0
        self.approval_request_count = 0
        self.approval_approved_count = 0
        self.approval_rejected_count = 0
        self.last_execution_timestamp = 0.0
        
    def record_execution_start(self):
        self.execution_count += 1
        self.last_execution_timestamp = time.time()
        
    def record_execution_success(self, duration: float):
        self.execution_success_count += 1
        self.execution_duration_total += duration
        
    def record_execution_failure(self, duration: float):
        self.execution_failure_count += 1
        self.execution_duration_total += duration
        
    def record_approval_request(self):
        self.approval_request_count += 1
        
    def record_approval_decision(self, approved: bool):
        if approved:
            self.approval_approved_count += 1
        else:
            self.approval_rejected_count += 1
            
    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus format metrics"""
        metrics = []
        
        # Workflow execution metrics
        metrics.append(f"# HELP workflow_executions_total Total number of workflow executions")
        metrics.append(f"# TYPE workflow_executions_total counter")
        metrics.append(f"workflow_executions_total {self.execution_count}")
        
        metrics.append(f"# HELP workflow_execution_duration_seconds_total Total execution duration")
        metrics.append(f"# TYPE workflow_execution_duration_seconds_total counter")
        metrics.append(f"workflow_execution_duration_seconds_total {self.execution_duration_total:.3f}")
        
        metrics.append(f"# HELP workflow_executions_success_total Successful workflow executions")
        metrics.append(f"# TYPE workflow_executions_success_total counter")
        metrics.append(f"workflow_executions_success_total {self.execution_success_count}")
        
        metrics.append(f"# HELP workflow_executions_failure_total Failed workflow executions")
        metrics.append(f"# TYPE workflow_executions_failure_total counter")
        metrics.append(f"workflow_executions_failure_total {self.execution_failure_count}")
        
        # Approval metrics
        metrics.append(f"# HELP workflow_approval_requests_total Total approval requests")
        metrics.append(f"# TYPE workflow_approval_requests_total counter")
        metrics.append(f"workflow_approval_requests_total {self.approval_request_count}")
        
        metrics.append(f"# HELP workflow_approvals_approved_total Approved requests")
        metrics.append(f"# TYPE workflow_approvals_approved_total counter")
        metrics.append(f"workflow_approvals_approved_total {self.approval_approved_count}")
        
        metrics.append(f"# HELP workflow_approvals_rejected_total Rejected requests")
        metrics.append(f"# TYPE workflow_approvals_rejected_total counter")
        metrics.append(f"workflow_approvals_rejected_total {self.approval_rejected_count}")
        
        # Last execution timestamp
        metrics.append(f"# HELP workflow_last_execution_timestamp_seconds Last execution timestamp")
        metrics.append(f"# TYPE workflow_last_execution_timestamp_seconds gauge")
        metrics.append(f"workflow_last_execution_timestamp_seconds {self.last_execution_timestamp}")
        
        return "\n".join(metrics)

# Global metrics instance
workflow_metrics = WorkflowMetrics()

_engine = WorkflowEngine()


def _load_workflow_catalog() -> List[WorkflowCatalogItem]:
    """Load workflow catalog from data/workflows/*.yaml files"""
    catalog = []
    workflows_dir = Path("data/workflows")
    
    if not workflows_dir.exists():
        return catalog
    
    for yaml_file in workflows_dir.glob("*.yaml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                workflow_data = yaml.safe_load(f)
            
            # Extract metadata
            metadata = workflow_data.get("metadata", {})
            workflow_steps = len(workflow_data.get("workflow", {}).get("steps", []))
            
            catalog_item = WorkflowCatalogItem(
                file_path=str(yaml_file.relative_to(Path.cwd())),
                name=workflow_data.get("name", yaml_file.stem),
                description=workflow_data.get("description", ""),
                version=workflow_data.get("version", "1.0.0"),
                author=workflow_data.get("author", "Unknown"),
                tags=workflow_data.get("tags", []),
                created_at=workflow_data.get("created_at", ""),
                metadata=metadata,
                workflow_steps=workflow_steps,
                complexity=metadata.get("complexity", "unknown"),
                estimated_duration_minutes=metadata.get("estimated_duration_minutes", 0),
                requires_approval=metadata.get("requires_approval", False),
                risk_level=metadata.get("risk_level", "unknown")
            )
            
            catalog.append(catalog_item)
            
        except Exception as e:
            # Log error but continue processing other files
            print(f"Warning: Failed to load workflow {yaml_file}: {e}")
            continue
    
    return catalog


@router.get("/", response_model=List[WorkflowCatalogItem])
@require_role(UserRole.VIEWER)
def list_workflows(current_user: User = Depends(get_current_user)) -> List[WorkflowCatalogItem]:
    """Return available workflows from catalog (requires VIEWER role or higher)"""
    return _load_workflow_catalog()


@router.get("/catalog", response_model=List[WorkflowCatalogItem])
@require_role(UserRole.VIEWER)
def get_workflow_catalog(current_user: User = Depends(get_current_user)) -> List[WorkflowCatalogItem]:
    """Get detailed workflow catalog with metadata (requires VIEWER role or higher)"""
    return _load_workflow_catalog()


@router.get("/{workflow_name}", response_model=WorkflowCatalogItem)
@require_role(UserRole.VIEWER)
def get_workflow_details(workflow_name: str, current_user: User = Depends(get_current_user)) -> WorkflowCatalogItem:
    """Get details for a specific workflow (requires VIEWER role or higher)"""
    catalog = _load_workflow_catalog()
    
    # Find workflow by name or file name
    for item in catalog:
        if item.name == workflow_name or Path(item.file_path).stem == workflow_name:
            return item
    
    raise HTTPException(status_code=404, detail=f"Workflow '{workflow_name}' not found")


@router.get("/metrics", include_in_schema=False)
def get_workflow_metrics():
    """Get Prometheus format metrics for workflow execution"""
    from fastapi import Response
    
    metrics_text = workflow_metrics.get_prometheus_metrics()
    return Response(content=metrics_text, media_type="text/plain")


@router.post("/run")
@require_role(UserRole.OPERATOR)
async def run_workflow(payload: Dict[str, Any], current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Run a workflow provided as YAML text (requires OPERATOR role or higher).

    Request JSON:
    {
      "yaml": "...",           # required (YAML string)
      "context": { ... }        # optional dict
    }
    """
    start_time = time.time()
    workflow_metrics.record_execution_start()
    
    yaml_text = payload.get("yaml")
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        raise HTTPException(status_code=400, detail="Field 'yaml' (YAML string) is required")

    context = payload.get("context") or {}
    if not isinstance(context, dict):
        raise HTTPException(status_code=400, detail="Field 'context' must be a JSON object if present")

    try:
        definition = load_workflow_definition(yaml_text)
    except WorkflowDSLException as e:
        execution_duration = time.time() - start_time
        workflow_metrics.record_execution_failure(execution_duration)
        raise HTTPException(status_code=400, detail=str(e))

    try:
        # Execute via engine (safe no-op)
        result: WorkflowResult = _engine.run_definition(definition, context)
        
        # Record successful execution
        execution_duration = time.time() - start_time
        workflow_metrics.record_execution_success(execution_duration)
        
        # Add execution metadata
        response = {
            "workflow_id": result.workflow_id,
            "status": result.status,
            "steps": [
                {"step_id": s.step_id, "status": s.status, "detail": s.detail}
                for s in result.steps
            ],
            "metadata": {
                "executed_by": current_user.username,
                "user_role": current_user.role.value,
                "execution_time": datetime.now(timezone.utc).isoformat(),
                "execution_duration_seconds": round(execution_duration, 3)
            }
        }
        
        return response
    except Exception as e:
        # Record failed execution
        execution_duration = time.time() - start_time
        workflow_metrics.record_execution_failure(execution_duration)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/approvals")
@require_role(UserRole.VIEWER)
def list_approvals(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Return pending approvals from local store (requires VIEWER role or higher)."""
    store = _load_approvals_store()
    pending = [a for a in store if a.get("status") == "pending"]
    decided = [a for a in store if a.get("status") in {"approved", "rejected", "expired"}]
    return {"pending": pending, "decided": decided}


@router.post("/approvals")
@require_role(UserRole.OPERATOR)
async def record_approval(payload: Dict[str, Any], current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Record an approval decision with role-based validation (requires OPERATOR role or higher).

    Request JSON:
    {
      "approval_id": "...",
      "decision": "approve" | "reject",
      "notes": "..."  # optional
    }
    """
    # Record approval request metric
    workflow_metrics.record_approval_request()
    
    approval_id = payload.get("approval_id") or payload.get("appr_id")
    decision = payload.get("decision")

    if not isinstance(approval_id, str) or not approval_id:
        raise HTTPException(status_code=400, detail="approval_id must be a non-empty string")
    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")

    # Optional fields to validate basic rules
    approver = payload.get("approver")
    requested_by = payload.get("requested_by")
    approver_role = payload.get("approver_role")
    ts_req = payload.get("ts_req")
    evidence = payload.get("evidence")

    if approver and requested_by and approver == requested_by:
        raise HTTPException(status_code=400, detail="self-approval is not allowed")
    if approver_role and approver_role not in {"CMD", "AUDIT"}:
        raise HTTPException(status_code=400, detail="approver_role must be 'CMD' or 'AUDIT'")

    # Enhanced validation with role hierarchy
    if approver_role:
        role_mapping = {
            UserRole.ADMIN: ["CMD", "AUDIT"],
            UserRole.OPERATOR: ["AUDIT"],
            UserRole.VIEWER: [],
            UserRole.WORKER: []
        }
        
        allowed_roles = role_mapping.get(current_user.role, [])
        if approver_role not in allowed_roles:
            raise HTTPException(
                status_code=403, 
                detail=f"User role {current_user.role.value} cannot approve as {approver_role}"
            )
    
    # Verify approver matches current user if provided
    if approver and approver != current_user.username:
        raise HTTPException(status_code=403, detail="Approver must match authenticated user")

    # Decision timestamp
    ts_dec = datetime.now(timezone.utc).isoformat()
    if isinstance(ts_req, str):
        try:
            # Ensure ts_dec >= ts_req
            req_dt = datetime.fromisoformat(ts_req.replace("Z", "+00:00"))
            dec_dt = datetime.fromisoformat(ts_dec.replace("Z", "+00:00"))
            if dec_dt < req_dt:
                raise HTTPException(status_code=400, detail="ts_dec must be >= ts_req")
        except Exception:
            # Ignore parse errors; rely on upstream format in subsequent iterations
            pass

    # Check for duplicate approval IDs
    store = _load_approvals_store()
    existing_ids = {a.get("appr_id") for a in store}
    if approval_id in existing_ids:
        raise HTTPException(status_code=409, detail=f"Approval ID {approval_id} already exists")

    # Record approval decision metric
    approved = decision == "approve"
    workflow_metrics.record_approval_decision(approved)

    # Persist to local store
    record = {
        "appr_id": approval_id,
        "status": "approved" if decision == "approve" else "rejected",
        "approver": approver or current_user.username,
        "approver_role": approver_role,
        "requested_by": requested_by,
        "ts_req": ts_req,
        "ts_dec": ts_dec,
        "evidence": evidence,
    }
    
    # Replace if appr_id exists, else append
    replaced = False
    for i, a in enumerate(store):
        if a.get("appr_id") == approval_id:
            store[i] = {**a, **record}
            replaced = True
            break
    if not replaced:
        store.append(record)
    _save_approvals_store(store)

    return {"status": "accepted", "approval_id": approval_id, "decision": decision}


# ---- Local approvals store helpers ----

def _approvals_store_path() -> Path:
    p = Path("data/approvals.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_approvals_store() -> List[Dict[str, Any]]:
    p = _approvals_store_path()
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _save_approvals_store(items: List[Dict[str, Any]]) -> None:
    p = _approvals_store_path()
    with p.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)