"""
WorkflowEngine (Phase 4)

Minimal skeleton to support workflow automation execution.
This is a placeholder implementation that will be expanded according to
docs/WORKFLOW_AUTOMATION_SPEC.md. Current behavior is a safe no-op
that returns success and does not affect existing systems.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .workflow_dsl import assert_valid_workflow_definition


@dataclass
class StepResult:
    step_id: str
    status: str
    detail: Optional[str] = None


@dataclass
class WorkflowResult:
    workflow_id: str
    status: str
    steps: List[StepResult]


class WorkflowEngine:
    """
    A minimal, stateless workflow engine stub.

    Next iterations will implement:
    - DSL parsing/loading
    - Deterministic state machine
    - Retry/timeout semantics
    - Approval waiting/decision handling
    - Integration adapters (HTTP/Queue/IDP/ERP)
    - Observability (metrics/logs/traces)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger("orch.workflow")

    def run(self, workflow_id: str, context: Dict[str, Any]) -> WorkflowResult:
        """
        Execute a workflow safely.
        Current stub logs the invocation and returns a successful result
        without performing any external side effects.
        """
        self.logger.info(
            "Running workflow '%s' with context keys: %s",
            workflow_id,
            list(context.keys()),
        )
        return WorkflowResult(workflow_id=workflow_id, status="success", steps=[])

    def run_definition(self, definition: Dict[str, Any], context: Dict[str, Any]) -> WorkflowResult:
        """
        Execute a workflow definition after validating it.
        Current stub validates and logs, then returns a successful result
        without performing external side effects.
        """
        assert_valid_workflow_definition(definition)
        workflow_id = definition.get("workflow", {}).get("id", "unknown")
        self.logger.info(
            "Running workflow definition '%s' with context keys: %s",
            workflow_id,
            list(context.keys()),
        )
        return WorkflowResult(workflow_id=workflow_id, status="success", steps=[])
