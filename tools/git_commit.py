import subprocess, shlex

def commit(message: str = "chore: agent commit") -> dict:
    try:
        subprocess.check_call(shlex.split("git add -A"))
        subprocess.check_call(shlex.split(f'git commit -m "{message}"'))
        return {"ok": True, "message": message}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": str(e)}