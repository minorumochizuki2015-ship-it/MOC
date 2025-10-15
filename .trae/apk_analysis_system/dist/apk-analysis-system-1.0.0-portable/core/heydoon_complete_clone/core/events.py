#!/usr/bin/env python3
"""
イベントシステム
"""

import pygame
from typing import Dict, List, Callable, Any

class EventSystem:
    """イベント処理システム"""
    
    def __init__(self):
        """イベントシステムの初期化"""
        self.event_handlers: Dict[int, List[Callable]] = {}
        self.custom_events: Dict[str, int] = {}
        
        # カスタムイベントの登録
        self._register_custom_events()
    
    def _register_custom_events(self):
        """カスタムイベントの登録"""
        self.custom_events = {
            "GAME_START": pygame.USEREVENT + 1,
            "GAME_END": pygame.USEREVENT + 2,
            "SCORE_UPDATE": pygame.USEREVENT + 3,
            "LEVEL_COMPLETE": pygame.USEREVENT + 4,
            "CHALLENGE_START": pygame.USEREVENT + 5,
            "CHALLENGE_COMPLETE": pygame.USEREVENT + 6
        }
    
    def register_handler(self, event_type: int, handler: Callable):
        """イベントハンドラーの登録"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def handle_event(self, event: pygame.event.Event):
        """イベント処理"""
        if event.type in self.event_handlers:
            for handler in self.event_handlers[event.type]:
                handler(event)
    
    def post_custom_event(self, event_name: str, data: Dict[str, Any] = None):
        """カスタムイベントの送信"""
        if event_name in self.custom_events:
            event = pygame.event.Event(
                self.custom_events[event_name],
                data or {}
            )
            pygame.event.post(event)
