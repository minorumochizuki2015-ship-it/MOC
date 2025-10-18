import sys, os
from pathlib import Path

# プロジェクトルートを import パスに追加
sys.path.append(os.path.abspath('.'))

from src.dashboard import app

print("static_folder =", app.static_folder)
for fn in ["test_preview_ext.html", "next.html"]:
    p = Path(app.static_folder) / fn
    print(fn, "exists:", p.exists(), "path:", p)
