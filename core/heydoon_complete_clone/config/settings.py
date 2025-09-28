#!/usr/bin/env python3
"""
HeyDooon Complete Clone - 設定システム
"""

class GameSettings:
    """ゲーム設定クラス"""
    
    def __init__(self):
        """設定初期化"""
        # 画面設定
        self.screen_width = 800
        self.screen_height = 600
        self.fps = 60
        
        # ゲーム設定
        self.difficulty = 1
        self.sound_enabled = True
        self.music_enabled = True
        
        # 色設定
        self.bg_color = (0, 0, 0)
        self.text_color = (255, 255, 255)
        self.accent_color = (0, 255, 0)