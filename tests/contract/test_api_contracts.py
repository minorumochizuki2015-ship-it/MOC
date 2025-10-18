import json
import os


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_contract_files_exist_and_basic_shape():
    base = os.path.join(os.getcwd(), "schema", "contracts")
    files = [
        "site.load.json",
        "site.select.json",
        "patch.propose.json",
        "patch.test.json",
        "patch.apply.json",
        "patch.rollback.json",
    ]
    for fn in files:
        p = os.path.join(base, fn)
        assert os.path.exists(p), f"missing contract: {fn}"
        data = _load_json(p)
        # 最低限のキー検証
        assert data.get("title"), f"{fn} missing title"
        assert data.get("type") == "object", f"{fn} must be object schema"
        assert "properties" in data, f"{fn} missing properties"
        assert isinstance(data["properties"], dict)