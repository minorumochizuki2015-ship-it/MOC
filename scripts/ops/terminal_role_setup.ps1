# Terminal Role Setup & Standard Commands
param(
    [string]$Role = "Auditor"
)

function Set-CommonEnv {
    $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
}

function Start-IntegrationTests {
    Set-CommonEnv
    .\.venv\Scripts\python -m pytest -q tests\integration\test_full_workflow.py::TestFullWorkflow::test_metrics_endpoint_workflow tests\integration\test_full_workflow.py::TestFullWorkflow::test_rate_limiting_workflow -q
}

function Start-ContractTests {
    Set-CommonEnv
    .\.venv\Scripts\python -m pytest -q tests\contract\test_jwt_contract.py -q
}

function Start-UnitSecurityTests {
    Set-CommonEnv
    .\.venv\Scripts\python -m pytest -q tests\test_security.py -q
}

function Start-UnitOrchestratorTests {
    Set-CommonEnv
    .\.venv\Scripts\python -m pytest -q tests\test_orchestrator.py -q
}

Write-Host "Role: $Role"
switch ($Role) {
    'Auditor' { Start-IntegrationTests }
    'Executor-Contract' { Start-ContractTests }
    'Executor-Unit' { Start-UnitSecurityTests }
    'Executor-Orchestrator' { Start-UnitOrchestratorTests }
    default { Write-Host "Specify Role=Auditor|Executor-Contract|Executor-Unit|Executor-Orchestrator" }
}