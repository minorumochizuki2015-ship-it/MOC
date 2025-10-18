"""
Workflow DSL モジュールのunit テスト
"""

import unittest
from unittest.mock import MagicMock, patch

from src.workflow_dsl import (
    WorkflowDSLException,
    assert_valid_workflow_definition,
    load_workflow_definition,
    validate_workflow_definition,
)


class TestWorkflowDSL(unittest.TestCase):
    """Workflow DSL のunit テスト"""

    def test_load_workflow_definition_success(self):
        """正常なYAMLワークフロー定義の読み込みテスト"""
        yaml_text = """
workflow:
  id: test_workflow
  name: Test Workflow
  steps:
    - id: step1
      action: test_action
"""
        result = load_workflow_definition(yaml_text)

        self.assertIsInstance(result, dict)
        self.assertIn("workflow", result)
        self.assertEqual(result["workflow"]["id"], "test_workflow")
        self.assertEqual(result["workflow"]["name"], "Test Workflow")
        self.assertEqual(len(result["workflow"]["steps"]), 1)

    def test_load_workflow_definition_invalid_yaml(self):
        """無効なYAMLの読み込みエラーテスト"""
        invalid_yaml = "invalid: yaml: content: ["

        with self.assertRaises(WorkflowDSLException) as cm:
            load_workflow_definition(invalid_yaml)

        self.assertIn("Failed to parse workflow definition", str(cm.exception))

    def test_load_workflow_definition_non_dict(self):
        """辞書以外のYAMLの読み込みエラーテスト"""
        non_dict_yaml = "- item1\n- item2"

        with self.assertRaises(WorkflowDSLException) as cm:
            load_workflow_definition(non_dict_yaml)

        self.assertIn("Workflow definition must be a YAML mapping at top level", str(cm.exception))

    @patch("src.workflow_dsl._YAML_AVAILABLE", False)
    def test_load_workflow_definition_no_yaml(self):
        """PyYAMLが利用できない場合のエラーテスト"""
        with self.assertRaises(WorkflowDSLException) as cm:
            load_workflow_definition("workflow: {}")

        self.assertIn("PyYAML is required", str(cm.exception))

    def test_validate_workflow_definition_valid(self):
        """正常なワークフロー定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertEqual(len(errors), 0)

    def test_validate_workflow_definition_missing_workflow(self):
        """workflowキーが欠如している場合のバリデーションテスト"""
        definition = {"invalid": "definition"}

        errors = validate_workflow_definition(definition)
        self.assertIn("'workflow' must be a mapping", errors)

    def test_validate_workflow_definition_missing_id(self):
        """workflow.idが欠如している場合のバリデーションテスト"""
        definition = {
            "workflow": {
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.id must be a non-empty string", errors)

    def test_validate_workflow_definition_empty_id(self):
        """workflow.idが空文字列の場合のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.id must be a non-empty string", errors)

    def test_validate_workflow_definition_missing_name(self):
        """workflow.nameが欠如している場合のバリデーションテスト"""
        definition = {
            "workflow": {"id": "test_workflow", "steps": [{"id": "step1", "action": "test_action"}]}
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.name must be a non-empty string", errors)

    def test_validate_workflow_definition_missing_steps(self):
        """workflow.stepsが欠如している場合のバリデーションテスト"""
        definition = {"workflow": {"id": "test_workflow", "name": "Test Workflow"}}

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.steps must be a non-empty list", errors)

    def test_validate_workflow_definition_empty_steps(self):
        """workflow.stepsが空リストの場合のバリデーションテスト"""
        definition = {"workflow": {"id": "test_workflow", "name": "Test Workflow", "steps": []}}

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.steps must be a non-empty list", errors)

    def test_validate_workflow_definition_invalid_step(self):
        """無効なステップ定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [
                    {"id": "step1", "action": "test_action"},
                    {"action": "missing_id"},  # idが欠如
                    {"id": "step3"},  # actionが欠如
                ],
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("steps[1].id must be a non-empty string", errors)
        self.assertIn("steps[2].action must be a non-empty string", errors)

    def test_validate_workflow_definition_with_context(self):
        """コンテキスト付きワークフロー定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
                "context": {"required": ["param1", "param2"], "optional": ["param3"]},
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertEqual(len(errors), 0)

    def test_validate_workflow_definition_invalid_context(self):
        """無効なコンテキスト定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
                "context": {"required": "not_a_list", "optional": ["param3"]},
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("workflow.context.required must be a list if present", errors)

    def test_validate_workflow_definition_with_triggers(self):
        """トリガー付きワークフロー定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
                "triggers": [{"type": "webhook", "config": {"url": "/webhook"}}],
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertEqual(len(errors), 0)

    def test_validate_workflow_definition_invalid_triggers(self):
        """無効なトリガー定義のバリデーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
                "triggers": [{"config": {"url": "/webhook"}}],  # typeが欠如
            }
        }

        errors = validate_workflow_definition(definition)
        self.assertIn("triggers[0].type must be a string", errors)

    def test_assert_valid_workflow_definition_success(self):
        """正常なワークフロー定義のアサーションテスト"""
        definition = {
            "workflow": {
                "id": "test_workflow",
                "name": "Test Workflow",
                "steps": [{"id": "step1", "action": "test_action"}],
            }
        }

        # 例外が発生しないことを確認
        assert_valid_workflow_definition(definition)

    def test_assert_valid_workflow_definition_failure(self):
        """無効なワークフロー定義のアサーションテスト"""
        definition = {"invalid": "definition"}

        with self.assertRaises(WorkflowDSLException) as cm:
            assert_valid_workflow_definition(definition)

        self.assertIn("Invalid workflow definition", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
