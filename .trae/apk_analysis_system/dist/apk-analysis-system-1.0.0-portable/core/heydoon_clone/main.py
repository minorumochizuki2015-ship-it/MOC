#!/usr/bin/env python3
"""
HeyDooon Complete Clone - メイン実行ファイル
ゲームの起動とエラーハンドリングを担当
"""

import sys
import os
from pathlib import Path
import json
import time
from datetime import datetime

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# 共通ログ設定をインポート
from core.config.logging_config import setup_logging, get_logger
from core.heydoon_clone.game_engine import HeyDooonGameEngine

# ログ設定
logger = setup_logging("heydoon_clone")

def check_dependencies():
    """依存関係のチェック"""
    try:
        import pygame
        logger = get_logger(__name__)
        logger.info(f"Pygame version: {pygame.version.ver}")
        return True
    except ImportError as e:
        logger = get_logger(__name__)
        logger.error(f"Pygame import error: {e}")
        return False

def main():
    """メイン実行関数"""
    logger = get_logger(__name__)
    
    try:
        logger.info("=== HeyDooon Clone Game Starting ===")
        
        # 依存関係チェック
        if not check_dependencies():
            logger.error("Dependencies check failed")
            return False
        
        # ゲームエンジン初期化
        logger.info("Initializing game engine...")
        game_engine = HeyDooonGameEngine()
        
        # ゲーム実行
        logger.info("Starting game loop...")
        game_engine.run()
        
        logger.info("Game ended successfully")
        return True
        
    except Exception as e:
        logger.error(f"Game execution failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False
    finally:
        import pygame
        pygame.quit()
        logger.info("=== HeyDooon Clone Game Ended ===")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)