# UTF-8
import re
import subprocess
import sys

MAX_LINES = 150      # 変更行の上限
ALLOWED_EXTRA = {r"^tests/"}  # 例外（任意）

def run(cmd): return subprocess.check_output(cmd, text=True)

def main():
    names = run(["git","diff","--cached","--name-only"]).splitlines()
    n = len(names)
    if n == 0: return
    # 例外以外の対象数を数える
    def allowed(p): return any(re.search(pat, p) for pat in ALLOWED_EXTRA)
    core = [p for p in names if not allowed(p)]
    if len(core) > 1:
        sys.stderr.write(f"[PATCH] one commit must touch 1 file (now {len(core)}):\n  - " + "\n  - ".join(core) + "\n")
        sys.exit(1)
    # 差分行数チェック
    stat = run(["git","diff","--cached","--numstat"]).splitlines()
    ins=del_ = 0
    for line in stat:
        a,b,_ = line.split("\t")
        if a != "-" and b != "-":
            ins += int(a); del_ += int(b)
    if ins + del_ > MAX_LINES:
        sys.stderr.write(f"[PATCH] diff too large ({ins+del_} lines > {MAX_LINES}). Split commits.\n")
        sys.exit(1)

if __name__ == "__main__": main()
