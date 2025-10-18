import importlib

import pytest


def test_kernel_exports():
    mod = importlib.import_module("kernel")
    for name in ["generate", "generate_chat", "read_paths", "healthcheck", "_model_id"]:
        assert hasattr(mod, name), f"kernel should expose {name}"


def test_healthcheck_ok():
    mod = importlib.import_module("kernel")
    hc = mod.healthcheck()
    assert isinstance(hc, dict)
    assert hc.get("status") == "ok"
    assert isinstance(hc.get("version"), str)
    ts = hc.get("timestamp")
    assert isinstance(ts, str)
    assert ts.endswith("Z")


def test_generate_echo_basic():
    mod = importlib.import_module("kernel")
    res = mod.generate("hello")
    assert isinstance(res, dict)
    assert res["text"] == "hello"
    assert res["finish_reason"] in ("stop", "length")
    assert isinstance(res.get("model_id"), str)


@pytest.mark.parametrize("bad_prompt", ["", "   ", None])
def test_generate_invalid_prompt_raises(bad_prompt):
    mod = importlib.import_module("kernel")
    with pytest.raises(ValueError):
        mod.generate(bad_prompt)
