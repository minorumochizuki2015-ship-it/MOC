from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from socket import socket

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

def _port_open(port=8080, host="127.0.0.1"):
    try:
        s = socket(); s.settimeout(0.2); s.connect((host, int(port))); s.close(); return True
    except Exception:
        return False

def _load_settings():
    try:
        from src.common.paths import resolve_config
        p = resolve_config("settings.json")
        with open(p, "r", encoding="utf-8") as f:
            json.load(f)
        return True, str(p)
    except Exception as e:
        return False, str(e)[:200]

def _gpu_info():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            stderr=subprocess.DEVNULL, timeout=1
        )
        return [ln.strip() for ln in out.decode(errors="ignore").splitlines() if ln.strip()]
    except Exception:
        return None

def main():
    t0 = time.perf_counter()
    force_local = os.environ.get("OPENAI_FORCE_LOCAL","1") == "1"
    base = _base()
    
    # 非ローカル禁止
    from urllib.parse import urlparse
    host = (urlparse(base).hostname or "").lower()
    local_only = host in ("127.0.0.1","localhost")
    
    # API鍵の存在を警告/禁止
    leaked = [k for k in ("OPENAI_API_KEY","AZURE_OPENAI_KEY","ANTHROPIC_API_KEY","GOOGLE_API_KEY")
              if os.environ.get(k)]
    
    if force_local and not local_only:
        result = {"base": base, "local_only": local_only, "error": "REMOTE_ENDPOINT_BLOCKED"}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(EXIT_ERR)
    
    if force_local and leaked:
        result = {"base": base, "local_only": local_only, "api_keys_present": leaked, "error": f"API_KEYS_PRESENT:{','.join(leaked)}"}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(EXIT_ERR)
    
    env_ok = not (os.environ.get("OPENAI_COMPAT_BASE","").rstrip("/").endswith("/v1"))
    srv_ok, srv_info = _ping_models(base)
    ui_ok, ui_err = _import_ui()
    k_ok, k_err = _scan_kernel_for_double_v1()
    cfg_ok, cfg_info = _load_settings()
    port_ok = _port_open(os.environ.get("LOCALAI_PORT","8080"))
    gpu = _gpu_info()
    scripts_ok = any(_file_exists(p) for p in [
        "scripts/server/start_server_python_robust.bat",
        "start_server_python_robust.bat",
        "scripts/server/start_server_python_robust.py",
    ])

    result = {
        "base": base,
        "local_only": local_only,
        "api_keys_present": leaked,
        "env_has_trailing_v1": not env_ok,
        "server_ok": srv_ok,
        "server_info": srv_info,
        "ui_import_ok": ui_ok,
        "ui_import_err": ui_err,
        "kernel_double_v1_ok": k_ok,
        "kernel_scan_err": k_err,
        "config_ok": cfg_ok,
        "config_info": cfg_info,
        "port_open": port_ok,
        "gpu": gpu,
        "start_scripts_found": scripts_ok,
        "elapsed_ms": int((time.perf_counter()-t0)*1000),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # 判定
    if not env_ok or not k_ok:      # 危険設定/実装
        sys.exit(EXIT_ERR)
    if not srv_ok or not ui_ok or not scripts_ok or not cfg_ok or not port_ok:
        sys.exit(EXIT_WARN)
    sys.exit(EXIT_OK)

if __name__ == "__main__":
    main()
