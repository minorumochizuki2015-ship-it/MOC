import pytest

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False

from src.workflow_dsl import (
    WorkflowDSLException,
    assert_valid_workflow_definition,
    load_workflow_definition,
)
from src.workflow_engine import WorkflowEngine

if not YAML_AVAILABLE:
    pytest.skip("PyYAML not available; workflow DSL tests skipped.", allow_module_level=True)


VALID_YAML = """
workflow:
  id: wf_user_onboarding
  name: "User Onboarding"
  steps:
    - id: create_account
      action: http.request
    - id: approval
      action: approval.request
    - id: provision_access
      action: idp.assign_role
"""


def test_parse_and_run_workflow_definition():
    definition = load_workflow_definition(VALID_YAML)
    assert_valid_workflow_definition(definition)

    engine = WorkflowEngine()
    context = {"user": {"id": "u-1", "email": "u1@example.com"}}
    result = engine.run_definition(definition, context)
    assert result.status == "success"
    assert result.workflow_id == "wf_user_onboarding"


def test_invalid_workflow_definition_missing_id():
    invalid_yaml = """
workflow:
  name: x
  steps:
    - id: s1
      action: a1
"""
    definition = load_workflow_definition(invalid_yaml)
    with pytest.raises(WorkflowDSLException):
        assert_valid_workflow_definition(definition)