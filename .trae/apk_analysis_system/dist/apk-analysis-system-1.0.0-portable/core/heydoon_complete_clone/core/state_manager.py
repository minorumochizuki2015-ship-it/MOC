#!/usr/bin/env python3
"""
ゲーム状態管理システム
"""

from enum import Enum
from typing import Dict, Any
import pygame

class GameState(Enum):
    """ゲーム状態"""
    MENU = "menu"
    PLAYING = "playing"
    PAUSED = "paused"
    RESULT = "result"
    SETTINGS = "settings"

class StateManager:
    """ゲーム状態管理クラス"""
    
    def __init__(self):
        """状態管理器の初期化"""
        self.current_state = GameState.MENU
        self.previous_state = None
        self.state_data = {}
        
        # 状態別処理ハンドラー
        self.state_handlers = {
            GameState.MENU: self._handle_menu_state,
            GameState.PLAYING: self._handle_playing_state,
            GameState.PAUSED: self._handle_paused_state,
            GameState.RESULT: self._handle_result_state,
            GameState.SETTINGS: self._handle_settings_state
        }
    
    def change_state(self, new_state: GameState, data: Dict[str, Any] = None):
        """状態変更"""
        self.previous_state = self.current_state
        self.current_state = new_state
        self.state_data = data or {}
        
        print(f"🔄 状態変更: {self.previous_state.value} → {new_state.value}")
    
    def update(self, dt: float):
        """状態更新"""
        if self.current_state in self.state_handlers:
            self.state_handlers[self.current_state](dt)
    
    def render(self, screen: pygame.Surface):
        """状態描画"""
        # 状態別描画処理
        pass
    
    def _handle_menu_state(self, dt: float):
        """メニュー状態の処理"""
        pass
    
    def _handle_playing_state(self, dt: float):
        """プレイ状態の処理"""
        pass
    
    def _handle_paused_state(self, dt: float):
        """一時停止状態の処理"""
        pass
    
    def _handle_result_state(self, dt: float):
        """結果状態の処理"""
        pass
    
    def _handle_settings_state(self, dt: float):
        """設定状態の処理"""
        pass
