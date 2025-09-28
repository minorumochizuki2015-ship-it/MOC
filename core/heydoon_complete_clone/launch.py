#!/usr/bin/env python3
"""
HeyDooon Complete Clone 起動スクリプト
"""

import sys
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.game import main

if __name__ == "__main__":
    main()
