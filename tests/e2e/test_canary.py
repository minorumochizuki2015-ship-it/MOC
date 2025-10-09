import json
import os
import time
import urllib.error
import urllib.request

import pytest


def load_config():
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "staging.json")
    cfg_path = os.path.normpath(cfg_path)
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_setting(cfg, key, env_key):
    return os.getenv(env_key) or cfg[key]


@pytest.mark.e2e
def test_canary_healthcheck_config_exists():
    cfg = load_config()
    # Ensure required keys exist
    for k in ["healthcheck_url", "retry_sec", "max_wait_sec", "success_required"]:
        assert k in cfg


@pytest.mark.e2e
def test_canary_healthcheck_run_if_enabled():
    if os.getenv("RUN_E2E") not in {"1", "true", "TRUE"}:
        pytest.skip("RUN_E2E not enabled; skipping network canary test")

    cfg = load_config()
    url = get_setting(cfg, "healthcheck_url", "HEALTHCHECK_URL")
    retry_sec = int(get_setting(cfg, "retry_sec", "RETRY_SEC"))
    max_wait = int(get_setting(cfg, "max_wait_sec", "MAX_WAIT_SEC"))
    success_required = int(get_setting(cfg, "success_required", "SUCCESS_REQUIRED"))

    successes = 0
    deadline = time.time() + max_wait
    while time.time() < deadline and successes < success_required:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    successes += 1
        except (urllib.error.URLError, urllib.error.HTTPError):
            pass
        time.sleep(retry_sec)

    assert (
        successes >= success_required
    ), f"Canary failed: successes={successes}, required={success_required}, url={url}"
