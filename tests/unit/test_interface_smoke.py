def test_import_interface():
    import importlib

    mod = importlib.import_module("interface")
    # モジュールが正常にインポートできること
    assert mod is not None
    # ドキュメント文字列が存在する（プレースホルダでも可）
    assert isinstance(getattr(mod, "__doc__", ""), str)
