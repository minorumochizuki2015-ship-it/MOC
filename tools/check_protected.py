# UTF-8
import pathlib
import re
import subprocess
import sys

PROTECTED = {
    r"^start_modern_ui\.bat$", r"^main_modern\.py$",
    r"^\.cursor/rules/.*$", r"^tools/.*\.py$",
    r"^\.github/workflows/.*$"
}

def changed_files():
    out = subprocess.check_output(["git","diff","--cached","--name-only"], text=True)
    return [p for p in out.splitlines() if p.strip()]

def main():
    bad = []
    for p in changed_files():
        for pat in PROTECTED:
            if re.search(pat, p.replace("\\","/")):
                bad.append(p)
                break
    if bad:
        sys.stderr.write(
          "[GUARD] protected files are staged:\n  - " + "\n  - ".join(bad) +
          "\nRemove them from the commit or run the approved Guard flow.\n")
        sys.exit(1)

if __name__ == "__main__": main()
