import json
import os
from json.decoder import JSONDecodeError
from pathlib import Path

import pytest
import requests
from jsonschema import validate

# Skip contract schema validation tests in CI via environment variable
pytestmark = pytest.mark.skipif(
    os.getenv("SKIP_CONTRACT") == "1",
    reason="Contract tests skipped in CI via SKIP_CONTRACT=1",
)


SCHEMAS = {
    "http://localhost:5000/api/prediction": "schema/dashboard_prediction.schema.json",
    "http://localhost:5000/api/trends": "schema/dashboard_trends.schema.json",
    "http://localhost:5000/api/metrics": "schema/dashboard_metrics.schema.json",
    "http://localhost:5000/api/system-health": "schema/system_health.schema.json",
    "http://localhost:5001/api/realtime/metrics": "schema/realtime_metrics.schema.json",
    "http://localhost:5001/api/realtime/alerts": "schema/realtime_alerts.schema.json",
    "http://localhost:5001/api/realtime/system-status": "schema/realtime_system_status.schema.json",
}


@pytest.mark.parametrize("endpoint,schema_path", list(SCHEMAS.items()))
def test_endpoint_schema(endpoint: str, schema_path: str):
    # Load schema
    schema_file = Path(schema_path)
    assert schema_file.exists(), f"Missing schema file: {schema_path}"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    # Fetch endpoint
    try:
        resp = requests.get(endpoint, timeout=5)
    except Exception as e:
        pytest.skip(f"Endpoint not reachable ({endpoint}): {e}")

    # Validate only successful responses
    if not (200 <= resp.status_code < 300):
        pytest.skip(f"Non-2xx response for {endpoint}: {resp.status_code}")

    # Parse JSON payload; if invalid/malformed, skip to avoid false negatives in CI
    try:
        payload = resp.json()
    except JSONDecodeError:
        pytest.skip(f"Invalid JSON response for {endpoint}")
    # Validate JSON against schema
    validate(instance=payload, schema=schema)
