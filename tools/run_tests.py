import subprocess, sys

def run(cmd: str = "") -> dict:
    """
    既定: pytest → 無ければ unittest discovery
    """
    try:
        if cmd:
            rc = subprocess.call(cmd, shell=True)
            return {"ok": rc == 0, "rc": rc}
        # pytest 優先
        rc = subprocess.call([sys.executable, "-m", "pytest", "-q"])
        if rc == 127 or rc == 2:  # pytest無
            raise OSError()
        return {"ok": rc == 0, "rc": rc}
    except Exception:
        rc = subprocess.call([sys.executable, "-m", "unittest", "discover"])
        return {"ok": rc == 0, "rc": rc}
