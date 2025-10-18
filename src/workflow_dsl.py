"""
Workflow DSL loader and validator (Phase 4)

Provides minimal YAML-based workflow definition parsing and basic validation.
If PyYAML is not available, a clear error is raised to guide installation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("orch.workflow.dsl")

try:
    import yaml  # type: ignore

    _YAML_AVAILABLE = True
except Exception:  # pragma: no cover - import failure path
    yaml = None  # type: ignore
    _YAML_AVAILABLE = False


class WorkflowDSLException(Exception):
    pass


def load_workflow_definition(text: str) -> Dict[str, Any]:
    """
    Load a workflow definition from YAML text.
    Raises WorkflowDSLException if PyYAML is not available or parse fails.
    """
    if not _YAML_AVAILABLE:
        raise WorkflowDSLException(
            "PyYAML is required to load workflow definitions. Please install 'PyYAML'."
        )
    try:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise WorkflowDSLException("Workflow definition must be a YAML mapping at top level.")
        return data
    except Exception as e:
        raise WorkflowDSLException(f"Failed to parse workflow definition: {e}")


def validate_workflow_definition(definition: Dict[str, Any]) -> List[str]:
    """
    Basic static validation of workflow definition structure.
    Returns a list of error messages; empty list means valid.
    """
    errors: List[str] = []

    wf = definition.get("workflow")
    if not isinstance(wf, dict):
        errors.append("'workflow' must be a mapping")
        return errors

    # Required fields
    if not isinstance(wf.get("id"), str) or not wf.get("id"):
        errors.append("workflow.id must be a non-empty string")
    if not isinstance(wf.get("name"), str) or not wf.get("name"):
        errors.append("workflow.name must be a non-empty string")

    # Steps
    steps = wf.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("workflow.steps must be a non-empty list")
    else:
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"steps[{i}] must be a mapping")
                continue
            if not isinstance(step.get("id"), str) or not step.get("id"):
                errors.append(f"steps[{i}].id must be a non-empty string")
            if not isinstance(step.get("action"), str) or not step.get("action"):
                errors.append(f"steps[{i}].action must be a non-empty string")

    # Context
    ctx = wf.get("context", {})
    if ctx:
        if not isinstance(ctx, dict):
            errors.append("workflow.context must be a mapping if present")
        for key in ("required", "optional"):
            val = ctx.get(key)
            if val is not None and not isinstance(val, list):
                errors.append(f"workflow.context.{key} must be a list if present")

    # Triggers (optional)
    triggers = wf.get("triggers")
    if triggers is not None:
        if not isinstance(triggers, list):
            errors.append("workflow.triggers must be a list if present")
        else:
            for i, trg in enumerate(triggers):
                if not isinstance(trg, dict):
                    errors.append(f"triggers[{i}] must be a mapping")
                    continue
                if not isinstance(trg.get("type"), str):
                    errors.append(f"triggers[{i}].type must be a string")

    return errors


def assert_valid_workflow_definition(definition: Dict[str, Any]) -> None:
    """Raise WorkflowDSLException if invalid."""
    errors = validate_workflow_definition(definition)
    if errors:
        raise WorkflowDSLException("Invalid workflow definition: " + "; ".join(errors))
