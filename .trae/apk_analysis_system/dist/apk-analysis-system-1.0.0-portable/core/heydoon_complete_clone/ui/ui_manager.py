#!/usr/bin/env python3
"""
HeyDooon Complete Clone - UI管理システム
"""

import pygame
from typing import Dict, Any

class UIManager:
    """UI管理クラス"""
    
    def __init__(self, screen: pygame.Surface):
        """UI管理システム初期化"""
        self.screen = screen
        self.font = pygame.font.Font(None, 36)
        self.title_font = pygame.font.Font(None, 72)
        
    def update(self, dt: float):
        """UI更新"""
        pass
        
    def render(self, screen: pygame.Surface):
        """UI描画"""
        # タイトル表示
        title_text = self.title_font.render("HeyDooon Clone", True, (255, 255, 255))
        title_rect = title_text.get_rect(center=(screen.get_width()//2, 150))
        screen.blit(title_text, title_rect)
        
        # 説明文表示
        info_text = self.font.render("完全クローン版", True, (200, 200, 200))
        info_rect = info_text.get_rect(center=(screen.get_width()//2, 200))
        screen.blit(info_text, info_rect)
        
        # 操作説明
        start_text = self.font.render("SPACE キーでゲーム開始", True, (100, 255, 100))
        start_rect = start_text.get_rect(center=(screen.get_width()//2, 300))
        screen.blit(start_text, start_rect)