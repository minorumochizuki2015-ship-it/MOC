#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
最小コミットユーティリティ（Agentから呼び出し可）
"""
import subprocess
import sys


def main():
    msg = sys.argv[1] if len(sys.argv) > 1 else "agent: update"
    try:
        subprocess.check_call(["git", "add", "-A"])
        subprocess.check_call(["git", "commit", "-m", msg])
        print(f"committed: {msg}")
    except subprocess.CalledProcessError as e:
        print(f"git commit failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
