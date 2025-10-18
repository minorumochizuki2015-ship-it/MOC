import importlib


def test_import_kernel_shim():
    mod = importlib.import_module("kernel")
    # shim が期待される公開関数を持つことを確認
    for name in ["generate", "generate_chat", "read_paths", "healthcheck", "_model_id"]:
        assert hasattr(mod, name)
