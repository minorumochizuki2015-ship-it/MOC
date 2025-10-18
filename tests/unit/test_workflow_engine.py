"""
WorkflowEngine モジュールのunit テスト
"""

import unittest
from unittest.mock import MagicMock, patch

from src.workflow_engine import StepResult, WorkflowEngine, WorkflowResult


class TestStepResult(unittest.TestCase):
    """StepResult データクラスのテスト"""

    def test_step_result_creation(self):
        """StepResult の作成テスト"""
        step_result = StepResult(step_id="step1", status="success", detail="completed")
        self.assertEqual(step_result.step_id, "step1")
        self.assertEqual(step_result.status, "success")
        self.assertEqual(step_result.detail, "completed")

    def test_step_result_without_detail(self):
        """detail なしの StepResult 作成テスト"""
        step_result = StepResult(step_id="step2", status="failed")
        self.assertEqual(step_result.step_id, "step2")
        self.assertEqual(step_result.status, "failed")
        self.assertIsNone(step_result.detail)


class TestWorkflowResult(unittest.TestCase):
    """WorkflowResult データクラスのテスト"""

    def test_workflow_result_creation(self):
        """WorkflowResult の作成テスト"""
        steps = [
            StepResult(step_id="step1", status="success"),
            StepResult(step_id="step2", status="failed", detail="error occurred"),
        ]
        workflow_result = WorkflowResult(workflow_id="workflow1", status="completed", steps=steps)
        self.assertEqual(workflow_result.workflow_id, "workflow1")
        self.assertEqual(workflow_result.status, "completed")
        self.assertEqual(len(workflow_result.steps), 2)
        self.assertEqual(workflow_result.steps[0].step_id, "step1")


class TestWorkflowEngine(unittest.TestCase):
    """WorkflowEngine のunit テスト"""

    def setUp(self):
        """テスト前の準備"""
        self.engine = WorkflowEngine()

    def test_init(self):
        """WorkflowEngine 初期化のテスト"""
        self.assertIsNotNone(self.engine.logger)
        self.assertEqual(self.engine.logger.name, "orch.workflow")

    @patch("src.workflow_engine.logging.getLogger")
    def test_run_workflow(self, mock_get_logger):
        """ワークフロー実行のテスト"""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        engine = WorkflowEngine()
        context = {"key1": "value1", "key2": "value2"}

        result = engine.run("test_workflow", context)

        # 結果の検証
        self.assertIsInstance(result, WorkflowResult)
        self.assertEqual(result.workflow_id, "test_workflow")
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.steps), 0)

        # ログが呼ばれたことを確認
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0]
        self.assertIn("test_workflow", call_args[1])
        self.assertEqual(call_args[2], ["key1", "key2"])

    @patch("src.workflow_engine.assert_valid_workflow_definition")
    @patch("src.workflow_engine.logging.getLogger")
    def test_run_definition(self, mock_get_logger, mock_assert_valid):
        """ワークフロー定義実行のテスト"""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        engine = WorkflowEngine()
        definition = {"workflow": {"id": "test_definition_workflow", "name": "Test Workflow"}}
        context = {"param1": "value1"}

        result = engine.run_definition(definition, context)

        # バリデーションが呼ばれたことを確認
        mock_assert_valid.assert_called_once_with(definition)

        # 結果の検証
        self.assertIsInstance(result, WorkflowResult)
        self.assertEqual(result.workflow_id, "test_definition_workflow")
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.steps), 0)

        # ログが呼ばれたことを確認
        mock_logger.info.assert_called_once()

    @patch("src.workflow_engine.assert_valid_workflow_definition")
    @patch("src.workflow_engine.logging.getLogger")
    def test_run_definition_without_workflow_id(self, mock_get_logger, mock_assert_valid):
        """ワークフローIDなしの定義実行テスト"""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        engine = WorkflowEngine()
        definition = {"workflow": {"name": "Test Workflow"}}  # id なし
        context = {}

        result = engine.run_definition(definition, context)

        # デフォルトのworkflow_idが使用されることを確認
        self.assertEqual(result.workflow_id, "unknown")
        self.assertEqual(result.status, "success")

    @patch("src.workflow_engine.assert_valid_workflow_definition")
    def test_run_definition_validation_error(self, mock_assert_valid):
        """ワークフロー定義バリデーションエラーのテスト"""
        mock_assert_valid.side_effect = ValueError("Invalid workflow definition")

        engine = WorkflowEngine()
        definition = {"invalid": "definition"}
        context = {}

        with self.assertRaises(ValueError) as cm:
            engine.run_definition(definition, context)

        self.assertEqual(str(cm.exception), "Invalid workflow definition")


if __name__ == "__main__":
    unittest.main()
