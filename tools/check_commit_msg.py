# UTF-8
import pathlib
import re
import sys

if len(sys.argv) < 2:
    sys.stderr.write("[PTP] Usage: python check_commit_msg.py <commit_message_file>\n")
    sys.exit(1)
msg = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
need = ["PLAN:", "TEST:", "PATCH:"]
missing = [k for k in need if k not in msg.upper()]
if missing:
    sys.stderr.write("[PTP] commit message must contain 'Plan:','Test:','Patch:' sections.\n")
    sys.exit(1)

# ルール優先順位の警告
if "PRIORITY:" not in msg.upper():
    sys.stderr.write("[PTP] tip: add 'Priority: SAFE>TECH>USER' line.\n")
