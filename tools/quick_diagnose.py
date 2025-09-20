from __future__ import annotations
import os, sys, json, time, urllib.request
from pathlib import Path

EXIT_OK, EXIT_WARN, EXIT_ERR = 0, 1, 2

def _base():
    v = os.environ.get("OPENAI_COMPAT_BASE") or os.environ.get("OPENAI_BASE") or "http://127.0.0.1:8080"
    v = v.rstrip("/")
    return v[:-3] if v.endswith("/v1") else v

def _ping_models(base: str, timeout=2.0):
    try:
        with urllib.request.urlopen(f"{base}/v1/models", timeout=timeout) as r:
            return (200 <= r.status < 300), r.status
    except Exception as e:
        return False, str(e)[:120]

def _file_exists(p: str | Path): return Path(p).exists()

def _import_ui():
    try:
        # パス解決を先に実行
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        
        from src.common.paths import activate
        activate()
        __import__("src.ui.modern_interface")
        return True, None
    except Exception as e:
        return False, str(e)[:200]

def _scan_kernel_for_double_v1():
    try:
        # パス解決を先に実行
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
            
        from src.common.paths import ROOT
        code = (ROOT / "src" / "core" / "kernel.py").read_text(encoding="utf-8", errors="ignore")
        return ("/v1/v1/" not in code), None
    except Exception as e:
        return False, str(e)[:120]

def main():
    t0 = time.perf_counter()
    base = _base()
    env_ok = not (os.environ.get("OPENAI_COMPAT_BASE","").rstrip("/").endswith("/v1"))
    srv_ok, srv_info = _ping_models(base)
    ui_ok, ui_err = _import_ui()
    k_ok, k_err = _scan_kernel_for_double_v1()
    scripts_ok = any(_file_exists(p) for p in [
        "scripts/server/start_server_python_robust.bat",
        "start_server_python_robust.bat",
        "scripts/server/start_server_python_robust.py",
    ])

    result = {
        "base": base,
        "env_has_trailing_v1": not env_ok,
        "server_ok": srv_ok,
        "server_info": srv_info,
        "ui_import_ok": ui_ok,
        "ui_import_err": ui_err,
        "kernel_double_v1_ok": k_ok,
        "kernel_scan_err": k_err,
        "start_scripts_found": scripts_ok,
        "elapsed_ms": int((time.perf_counter()-t0)*1000),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # 判定
    if not env_ok or not k_ok:      # 危険設定/実装
        sys.exit(EXIT_ERR)
    if not srv_ok or not ui_ok or not scripts_ok:
        sys.exit(EXIT_WARN)
    sys.exit(EXIT_OK)

if __name__ == "__main__":
    main()
