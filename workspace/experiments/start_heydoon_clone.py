#!/usr/bin/env python3
"""
HeyDooon Clone ゲーム起動スクリプト
"""

import sys
from pathlib import Path

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from heydoon_clone.heydoon_game import main

if __name__ == "__main__":
    main()