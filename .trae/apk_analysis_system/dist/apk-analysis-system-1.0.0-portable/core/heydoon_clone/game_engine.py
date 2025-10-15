#!/usr/bin/env python3
"""
HeyDooon クローンゲーム - ゲームエンジン
基本ゲーム構造の実装（状態管理、UI、入力処理、描画システム）
"""

import pygame
import sys
import json
import time
import random
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from enum import Enum
from datetime import datetime

from .game_mechanics import (
    GameMechanics, Challenge, GameResult, ChallengeType, 
    DifficultyLevel, ScoreCalculator
)

# 共通ログ設定をインポート
from core.config.logging_config import get_logger

logger = get_logger(__name__)

class GameState(Enum):
    """ゲーム状態の定義"""
    MENU = "menu"
    PLAYING = "playing"
    PAUSED = "paused"
    GAME_OVER = "game_over"
    SETTINGS = "settings"
    LOADING = "loading"

class HeyDooonGameEngine:
    """HeyDooonクローンゲームのメインエンジン"""
    
    def __init__(self, width: int = 800, height: int = 600):
        """
        ゲームエンジンの初期化
        
        Args:
            width: ウィンドウ幅
            height: ウィンドウ高さ
        """
        # Pygame初期化
        pygame.init()
        pygame.mixer.init()
        
        # ウィンドウ設定
        self.width = width
        self.height = height
        self.screen = pygame.display.set_mode((width, height))
        pygame.display.set_caption("HeyDooon Complete Clone")
        
        # ゲーム状態管理
        self.current_state = GameState.LOADING
        self.previous_state = None
        self.state_stack = []
        
        # フレームレート制御
        self.clock = pygame.time.Clock()
        self.target_fps = 60
        
        # 入力管理
        self.keys_pressed = set()
        self.keys_just_pressed = set()
        self.keys_just_released = set()
        self.mouse_pos = (0, 0)
        self.mouse_pressed = set()
        self.mouse_just_pressed = set()
        self.mouse_just_released = set()
        
        # ゲームデータ
        self.game_data = {
            "score": 0,
            "level": 1,
            "lives": 3,
            "high_score": 0,
            "settings": {
                "sound_enabled": True,
                "music_enabled": True,
                "difficulty": "normal"
            }
        }
        
        # リソース管理
        self.images = {}
        self.sounds = {}
        self.fonts = {}
        
        # ゲームメカニクス
        self.game_mechanics = GameMechanics()
        self.current_challenges = []
        self.current_challenge_index = 0
        self.current_challenge = None
        self.challenge_start_time = 0
        self.challenge_attempts = 0
        
        # チャレンジ実行状態
        self.waiting_for_input = False
        self.challenge_sequence = []  # シーケンス記憶用
        self.player_sequence = []     # プレイヤー入力用
        self.reaction_start_time = 0
        
        # ゲーム実行フラグ
        self.running = True
        
        # 設定ファイルパス
        self.config_path = Path("data/heydoon_clone/config.json")
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("HeyDooonゲームエンジンを初期化しました")
    
    def load_resources(self):
        """ゲームリソースの読み込み"""
        logger.info("リソースを読み込み中...")
        
        try:
            # フォントの読み込み
            self.fonts["default"] = pygame.font.Font(None, 36)
            self.fonts["large"] = pygame.font.Font(None, 48)
            self.fonts["small"] = pygame.font.Font(None, 24)
            
            # 基本色の定義
            self.colors = {
                "white": (255, 255, 255),
                "black": (0, 0, 0),
                "red": (255, 0, 0),
                "green": (0, 255, 0),
                "blue": (0, 0, 255),
                "yellow": (255, 255, 0),
                "purple": (128, 0, 128),
                "orange": (255, 165, 0),
                "gray": (128, 128, 128),
                "dark_gray": (64, 64, 64)
            }
            
            # 設定の読み込み
            self.load_config()
            
            logger.info("リソースの読み込みが完了しました")
            
        except Exception as e:
            logger.error(f"リソース読み込みエラー: {e}")
    
    def load_config(self):
        """設定ファイルの読み込み"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.game_data.update(config)
                logger.info("設定ファイルを読み込みました")
            else:
                logger.info("設定ファイルが見つかりません。デフォルト設定を使用します")
        except Exception as e:
            logger.error(f"設定読み込みエラー: {e}")
    
    def save_config(self):
        """設定ファイルの保存"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.game_data, f, ensure_ascii=False, indent=2)
            logger.info("設定ファイルを保存しました")
        except Exception as e:
            logger.error(f"設定保存エラー: {e}")
    
    def handle_events(self):
        """イベント処理"""
        # 前フレームの入力状態をクリア
        self.keys_just_pressed.clear()
        self.keys_just_released.clear()
        self.mouse_just_pressed.clear()
        self.mouse_just_released.clear()
        
        # イベント処理
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False
            
            elif event.type == pygame.KEYDOWN:
                self.keys_pressed.add(event.key)
                self.keys_just_pressed.add(event.key)
                
                # ESCキーでメニューに戻る
                if event.key == pygame.K_ESCAPE:
                    if self.current_state == GameState.PLAYING:
                        self.change_state(GameState.PAUSED)
                    elif self.current_state == GameState.PAUSED:
                        self.change_state(GameState.PLAYING)
                    elif self.current_state == GameState.SETTINGS:
                        self.change_state(GameState.MENU)
            
            elif event.type == pygame.KEYUP:
                self.keys_pressed.discard(event.key)
                self.keys_just_released.add(event.key)
            
            elif event.type == pygame.MOUSEBUTTONDOWN:
                self.mouse_pressed.add(event.button)
                self.mouse_just_pressed.add(event.button)
            
            elif event.type == pygame.MOUSEBUTTONUP:
                self.mouse_pressed.discard(event.button)
                self.mouse_just_released.add(event.button)
            
            elif event.type == pygame.MOUSEMOTION:
                self.mouse_pos = event.pos
    
    def change_state(self, new_state: GameState):
        """ゲーム状態の変更"""
        if new_state != self.current_state:
            logger.info(f"ゲーム状態変更: {self.current_state.value} -> {new_state.value}")
            self.previous_state = self.current_state
            self.current_state = new_state
    
    def push_state(self, new_state: GameState):
        """ゲーム状態をスタックにプッシュ"""
        self.state_stack.append(self.current_state)
        self.change_state(new_state)
    
    def pop_state(self):
        """ゲーム状態をスタックからポップ"""
        if self.state_stack:
            previous_state = self.state_stack.pop()
            self.change_state(previous_state)
    
    def update(self, dt: float):
        """ゲーム状態の更新"""
        if self.current_state == GameState.LOADING:
            self.update_loading(dt)
        elif self.current_state == GameState.MENU:
            self.update_menu(dt)
        elif self.current_state == GameState.PLAYING:
            self.update_playing(dt)
        elif self.current_state == GameState.PAUSED:
            self.update_paused(dt)
        elif self.current_state == GameState.GAME_OVER:
            self.update_game_over(dt)
        elif self.current_state == GameState.SETTINGS:
            self.update_settings(dt)
    
    def update_loading(self, dt: float):
        """ローディング状態の更新"""
        # リソース読み込み完了後にメニューに移行
        self.change_state(GameState.MENU)
    
    def update_menu(self, dt: float):
        """メニュー状態の更新"""
        # スペースキーでゲーム開始
        if pygame.K_SPACE in self.keys_just_pressed:
            self.change_state(GameState.PLAYING)
            self.reset_game()
        
        # 設定画面への移行
        if pygame.K_s in self.keys_just_pressed:
            self.change_state(GameState.SETTINGS)
    
    def update_playing(self, dt: float):
        """ゲームプレイ状態の更新"""
        # 現在のチャレンジがない場合、新しいレベルを開始
        if not self.current_challenges:
            self.start_new_level()
        
        # 現在のチャレンジを実行
        if self.current_challenge:
            self.update_current_challenge(dt)
        else:
            self.load_next_challenge()
    
    def start_new_level(self):
        """新しいレベルの開始"""
        self.current_challenges = self.game_mechanics.start_new_level()
        self.current_challenge_index = 0
        logger.info(f"新しいレベル開始: {len(self.current_challenges)} チャレンジ")
    
    def load_next_challenge(self):
        """次のチャレンジを読み込み"""
        if self.current_challenge_index < len(self.current_challenges):
            self.current_challenge = self.current_challenges[self.current_challenge_index]
            self.challenge_start_time = time.time()
            self.challenge_attempts = 0
            self.waiting_for_input = False
            
            # チャレンジタイプ別の初期化
            if self.current_challenge.challenge_type == ChallengeType.REACTION_TIME:
                self.init_reaction_time_challenge()
            elif self.current_challenge.challenge_type == ChallengeType.SEQUENCE_MEMORY:
                self.init_sequence_memory_challenge()
            elif self.current_challenge.challenge_type == ChallengeType.COLOR_MATCH:
                self.init_color_match_challenge()
            
            logger.info(f"チャレンジ開始: {self.current_challenge.challenge_type.value}")
        else:
            # レベル完了
            self.complete_level()
    
    def init_reaction_time_challenge(self):
        """反応時間チャレンジの初期化"""
        # ランダムな待機時間後に反応開始
        self.reaction_start_time = time.time() + random.uniform(1.0, 3.0)
        self.waiting_for_input = False
    
    def init_sequence_memory_challenge(self):
        """シーケンス記憶チャレンジの初期化"""
        sequence_length = int(self.current_challenge.target_value)
        self.challenge_sequence = [random.randint(1, 4) for _ in range(sequence_length)]
        self.player_sequence = []
        self.waiting_for_input = False
        logger.info(f"シーケンス生成: {self.challenge_sequence}")
    
    def init_color_match_challenge(self):
        """色マッチチャレンジの初期化"""
        num_colors = int(self.current_challenge.target_value)
        self.challenge_sequence = [random.randint(1, 6) for _ in range(num_colors)]
        self.player_sequence = []
        self.waiting_for_input = True
    
    def update_current_challenge(self, dt: float):
        """現在のチャレンジの更新"""
        current_time = time.time()
        elapsed_time = current_time - self.challenge_start_time
        
        # タイムアウトチェック
        if elapsed_time > self.current_challenge.time_limit:
            self.complete_challenge(False, elapsed_time, 0.0)
            return
        
        # チャレンジタイプ別の更新
        if self.current_challenge.challenge_type == ChallengeType.REACTION_TIME:
            self.update_reaction_time_challenge(current_time)
        elif self.current_challenge.challenge_type == ChallengeType.SEQUENCE_MEMORY:
            self.update_sequence_memory_challenge()
        elif self.current_challenge.challenge_type == ChallengeType.COLOR_MATCH:
            self.update_color_match_challenge()
    
    def handle_playing_input(self, event):
        """ゲームプレイ中の入力処理"""
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_ESCAPE:
                self.state = GameState.PAUSED
                return
            
            # チャレンジ中の入力処理
            if self.current_challenge:
                challenge_type = self.current_challenge.challenge_type
                
                if challenge_type == ChallengeType.REACTION_TIME:
                    self.handle_reaction_time_input(event)
                elif challenge_type == ChallengeType.SEQUENCE_MEMORY:
                    self.handle_sequence_memory_input(event)
                elif challenge_type == ChallengeType.COLOR_MATCH:
                    self.handle_color_match_input(event)
    
    def handle_reaction_time_input(self, event):
        """反応時間チャレンジの入力処理"""
        if event.key == pygame.K_SPACE and self.waiting_for_input:
            # 反応時間計測
            reaction_time = time.time() - self.reaction_start_time
            
            # チャレンジ完了処理
            self.complete_challenge(True, reaction_time, 1.0)
    
    def handle_sequence_memory_input(self, event):
        """シーケンス記憶チャレンジの入力処理"""
        # 数字キー1-4の処理
        key_mapping = {
            pygame.K_1: 1, pygame.K_2: 2, pygame.K_3: 3, pygame.K_4: 4
        }
        
        if event.key in key_mapping:
            input_number = key_mapping[event.key]
            self.player_sequence.append(input_number)
            
            # シーケンス完了チェック
            if len(self.player_sequence) >= len(self.challenge_sequence):
                self.check_sequence_match()
    
    def handle_color_match_input(self, event):
        """色マッチチャレンジの入力処理"""
        # 数字キー1-6の処理
        key_mapping = {
            pygame.K_1: 1, pygame.K_2: 2, pygame.K_3: 3,
            pygame.K_4: 4, pygame.K_5: 5, pygame.K_6: 6
        }
        
        if event.key in key_mapping:
            input_number = key_mapping[event.key]
            self.player_sequence.append(input_number)
            
            # 色マッチ完了チェック
            if len(self.player_sequence) >= len(self.challenge_sequence):
                self.check_color_match()
    
    def update_reaction_time_challenge(self, current_time: float):
        """反応時間チャレンジの更新"""
        if not self.waiting_for_input and current_time >= self.reaction_start_time:
            self.waiting_for_input = True
            logger.info("反応開始!")
        
        # スペースキーで反応
        if self.waiting_for_input and pygame.K_SPACE in self.keys_just_pressed:
            reaction_time = current_time - self.reaction_start_time
            target_time = self.current_challenge.target_value
            tolerance = self.current_challenge.tolerance
            
            # 精度計算
            accuracy = max(0.0, 1.0 - abs(reaction_time - target_time) / target_time)
            success = abs(reaction_time - target_time) <= tolerance
            
            self.complete_challenge(success, reaction_time, accuracy)
    
    def update_sequence_memory_challenge(self):
        """シーケンス記憶チャレンジの更新"""
        # 数字キー1-4での入力
        for key in [pygame.K_1, pygame.K_2, pygame.K_3, pygame.K_4]:
            if key in self.keys_just_pressed:
                input_value = key - pygame.K_0  # 1-4に変換
                self.player_sequence.append(input_value)
                
                # シーケンス完了チェック
                if len(self.player_sequence) >= len(self.challenge_sequence):
                    self.check_sequence_match()
                break
    
    def update_color_match_challenge(self):
        """色マッチチャレンジの更新"""
        # 数字キー1-6での入力
        for key in [pygame.K_1, pygame.K_2, pygame.K_3, pygame.K_4, pygame.K_5, pygame.K_6]:
            if key in self.keys_just_pressed:
                input_value = key - pygame.K_0  # 1-6に変換
                self.player_sequence.append(input_value)
                
                # 必要な色数に達したかチェック
                if len(self.player_sequence) >= len(self.challenge_sequence):
                    self.check_color_match()
                break
    
    def check_sequence_match(self):
        """シーケンス一致チェック"""
        current_time = time.time()
        reaction_time = current_time - self.challenge_start_time
        
        # 完全一致チェック
        success = self.player_sequence == self.challenge_sequence
        
        # 精度計算（部分一致も考慮）
        correct_count = sum(1 for i, val in enumerate(self.player_sequence) 
                          if i < len(self.challenge_sequence) and val == self.challenge_sequence[i])
        accuracy = correct_count / len(self.challenge_sequence)
        
        self.complete_challenge(success, reaction_time, accuracy)
    
    def check_color_match(self):
        """色マッチチェック"""
        current_time = time.time()
        reaction_time = current_time - self.challenge_start_time
        
        # 順序は関係なく、同じ色が含まれているかチェック
        success = set(self.player_sequence) == set(self.challenge_sequence)
        
        # 精度計算
        correct_colors = len(set(self.player_sequence) & set(self.challenge_sequence))
        total_colors = len(set(self.challenge_sequence))
        accuracy = correct_colors / total_colors if total_colors > 0 else 0.0
        
        self.complete_challenge(success, reaction_time, accuracy)
    
    def complete_challenge(self, success: bool, reaction_time: float, accuracy: float):
        """チャレンジ完了処理"""
        self.challenge_attempts += 1
        
        # 結果作成
        result = GameResult(
            challenge=self.current_challenge,
            success=success,
            score=0,  # ゲームメカニクスで計算される
            reaction_time=reaction_time,
            accuracy=accuracy,
            attempts_used=self.challenge_attempts
        )
        
        # ゲームメカニクスで結果処理
        process_result = self.game_mechanics.process_challenge_result(result)
        
        # ゲームデータ更新
        game_state = self.game_mechanics.get_game_state()
        self.game_data.update({
            "score": game_state["total_score"],
            "level": game_state["level"],
            "lives": game_state["lives"]
        })
        
        logger.info(f"チャレンジ完了: 成功={success}, スコア={result.score}, 精度={accuracy:.2f}")
        
        # ゲームオーバーチェック
        if process_result["game_over"]:
            self.change_state(GameState.GAME_OVER)
            return
        
        # 次のチャレンジへ
        self.current_challenge_index += 1
        self.current_challenge = None
        
        # レベルアップチェック
        if process_result["level_up"]:
            logger.info("レベルアップ!")
    
    def complete_level(self):
        """レベル完了処理"""
        logger.info("レベル完了!")
        self.current_challenges = []
        self.current_challenge_index = 0
    
    def update_paused(self, dt: float):
        """ポーズ状態の更新"""
        # ポーズ中の処理
        pass
    
    def update_game_over(self, dt: float):
        """ゲームオーバー状態の更新"""
        # リスタートまたはメニューに戻る
        if pygame.K_r in self.keys_just_pressed:
            self.change_state(GameState.PLAYING)
            self.reset_game()
        elif pygame.K_m in self.keys_just_pressed:
            self.change_state(GameState.MENU)
    
    def update_settings(self, dt: float):
        """設定状態の更新"""
        # 設定画面の処理
        pass
    
    def render(self):
        """画面描画"""
        self.screen.fill(self.colors["black"])
        
        if self.current_state == GameState.LOADING:
            self.render_loading()
        elif self.current_state == GameState.MENU:
            self.render_menu()
        elif self.current_state == GameState.PLAYING:
            self.render_playing()
        elif self.current_state == GameState.PAUSED:
            self.render_paused()
        elif self.current_state == GameState.GAME_OVER:
            self.render_game_over()
        elif self.current_state == GameState.SETTINGS:
            self.render_settings()
        
        pygame.display.flip()
    
    def render_loading(self):
        """ローディング画面の描画"""
        text = self.fonts["large"].render("Loading...", True, self.colors["white"])
        text_rect = text.get_rect(center=(self.width // 2, self.height // 2))
        self.screen.blit(text, text_rect)
    
    def render_menu(self):
        """メニュー画面の描画"""
        # タイトル
        title = self.fonts["large"].render("HeyDooon Complete Clone", True, self.colors["white"])
        title_rect = title.get_rect(center=(self.width // 2, self.height // 3))
        self.screen.blit(title, title_rect)
        
        # メニューオプション
        start_text = self.fonts["default"].render("Press SPACE to Start", True, self.colors["green"])
        start_rect = start_text.get_rect(center=(self.width // 2, self.height // 2))
        self.screen.blit(start_text, start_rect)
        
        settings_text = self.fonts["default"].render("Press S for Settings", True, self.colors["yellow"])
        settings_rect = settings_text.get_rect(center=(self.width // 2, self.height // 2 + 50))
        self.screen.blit(settings_text, settings_rect)
        
        quit_text = self.fonts["default"].render("Press ESC to Quit", True, self.colors["red"])
        quit_rect = quit_text.get_rect(center=(self.width // 2, self.height // 2 + 100))
        self.screen.blit(quit_text, quit_rect)
    
    def render_playing(self):
        """ゲームプレイ画面の描画"""
        # ゲーム状態取得
        game_state = self.game_mechanics.get_game_state()
        
        # スコア表示
        score_text = self.fonts["default"].render(f"Score: {game_state['total_score']}", True, self.colors["white"])
        self.screen.blit(score_text, (10, 10))
        
        # レベル表示
        level_text = self.fonts["default"].render(f"Level: {game_state['level']}", True, self.colors["white"])
        self.screen.blit(level_text, (10, 50))
        
        # ライフ表示
        lives_text = self.fonts["default"].render(f"Lives: {game_state['lives']}", True, self.colors["white"])
        self.screen.blit(lives_text, (10, 90))
        
        # 経験値バー
        exp_progress = game_state['experience'] / game_state['exp_to_next_level']
        exp_bar_width = 200
        exp_bar_height = 10
        exp_bar_x = 10
        exp_bar_y = 130
        
        # 経験値バー背景
        pygame.draw.rect(self.screen, self.colors["dark_gray"], 
                        (exp_bar_x, exp_bar_y, exp_bar_width, exp_bar_height))
        
        # 経験値バー進行
        pygame.draw.rect(self.screen, self.colors["green"], 
                        (exp_bar_x, exp_bar_y, int(exp_bar_width * exp_progress), exp_bar_height))
        
        # 経験値テキスト
        exp_text = self.fonts["small"].render(f"EXP: {game_state['experience']}/{game_state['exp_to_next_level']}", 
                                            True, self.colors["white"])
        self.screen.blit(exp_text, (exp_bar_x, exp_bar_y + 15))
        
        # コンボ表示
        if game_state['combo_count'] > 1:
            combo_text = self.fonts["default"].render(f"Combo: {game_state['combo_count']}x", 
                                                    True, self.colors["yellow"])
            combo_rect = combo_text.get_rect(topright=(self.width - 10, 10))
            self.screen.blit(combo_text, combo_rect)
        
        # ゲーム領域
        game_area_rect = pygame.Rect(50, 180, self.width - 100, self.height - 230)
        pygame.draw.rect(self.screen, self.colors["dark_gray"], game_area_rect)
        pygame.draw.rect(self.screen, self.colors["white"], game_area_rect, 2)
        
        # 現在のチャレンジ表示
        if self.current_challenge:
            self.render_current_challenge(game_area_rect)
        else:
            # チャレンジ待機中
            waiting_text = self.fonts["default"].render("Loading next challenge...", True, self.colors["white"])
            waiting_rect = waiting_text.get_rect(center=game_area_rect.center)
            self.screen.blit(waiting_text, waiting_rect)
    
    def render_current_challenge(self, game_area: pygame.Rect):
        """現在のチャレンジの描画"""
        challenge_type = self.current_challenge.challenge_type
        center_x = game_area.centerx
        center_y = game_area.centery
        
        # チャレンジタイトル
        title_text = self.fonts["large"].render(challenge_type.value.replace('_', ' ').title(), 
                                              True, self.colors["white"])
        title_rect = title_text.get_rect(center=(center_x, game_area.top + 40))
        self.screen.blit(title_text, title_rect)
        
        # 残り時間表示
        elapsed_time = time.time() - self.challenge_start_time
        remaining_time = max(0, self.current_challenge.time_limit - elapsed_time)
        time_text = self.fonts["default"].render(f"Time: {remaining_time:.1f}s", True, self.colors["red"])
        time_rect = time_text.get_rect(center=(center_x, game_area.top + 80))
        self.screen.blit(time_text, time_rect)
        
        # チャレンジタイプ別の描画
        if challenge_type == ChallengeType.REACTION_TIME:
            self.render_reaction_time_challenge(game_area)
        elif challenge_type == ChallengeType.SEQUENCE_MEMORY:
            self.render_sequence_memory_challenge(game_area)
        elif challenge_type == ChallengeType.COLOR_MATCH:
            self.render_color_match_challenge(game_area)
        else:
            # デフォルト表示
            instruction_text = self.fonts["default"].render("Follow the instructions", True, self.colors["white"])
            instruction_rect = instruction_text.get_rect(center=(center_x, center_y))
            self.screen.blit(instruction_text, instruction_rect)
    
    def render_reaction_time_challenge(self, game_area: pygame.Rect):
        """反応時間チャレンジの描画"""
        center_x = game_area.centerx
        center_y = game_area.centery
        
        if not self.waiting_for_input:
            # 待機中
            wait_text = self.fonts["large"].render("Wait for the signal...", True, self.colors["yellow"])
            wait_rect = wait_text.get_rect(center=(center_x, center_y - 50))
            self.screen.blit(wait_text, wait_rect)
            
            instruction_text = self.fonts["default"].render("Press SPACE when you see GO!", True, self.colors["white"])
            instruction_rect = instruction_text.get_rect(center=(center_x, center_y + 20))
            self.screen.blit(instruction_text, instruction_rect)
        else:
            # 反応開始
            go_text = self.fonts["large"].render("GO!", True, self.colors["green"])
            go_rect = go_text.get_rect(center=(center_x, center_y - 50))
            self.screen.blit(go_text, go_rect)
            
            # 反応時間表示
            current_reaction_time = time.time() - self.reaction_start_time
            reaction_text = self.fonts["default"].render(f"Reaction Time: {current_reaction_time:.3f}s", 
                                                       True, self.colors["white"])
            reaction_rect = reaction_text.get_rect(center=(center_x, center_y + 20))
            self.screen.blit(reaction_text, reaction_rect)
    
    def render_sequence_memory_challenge(self, game_area: pygame.Rect):
        """シーケンス記憶チャレンジの描画"""
        center_x = game_area.centerx
        center_y = game_area.centery
        
        # 指示
        instruction_text = self.fonts["default"].render("Remember the sequence and repeat it (1-4 keys)", 
                                                       True, self.colors["white"])
        instruction_rect = instruction_text.get_rect(center=(center_x, center_y - 80))
        self.screen.blit(instruction_text, instruction_rect)
        
        # シーケンス表示
        sequence_text = self.fonts["large"].render(" ".join(map(str, self.challenge_sequence)), 
                                                 True, self.colors["yellow"])
        sequence_rect = sequence_text.get_rect(center=(center_x, center_y - 30))
        self.screen.blit(sequence_text, sequence_rect)
        
        # プレイヤー入力表示
        if self.player_sequence:
            player_text = self.fonts["default"].render(f"Your input: {' '.join(map(str, self.player_sequence))}", 
                                                     True, self.colors["green"])
            player_rect = player_text.get_rect(center=(center_x, center_y + 30))
            self.screen.blit(player_text, player_rect)
        
        # 進行状況
        progress_text = self.fonts["small"].render(f"Progress: {len(self.player_sequence)}/{len(self.challenge_sequence)}", 
                                                 True, self.colors["white"])
        progress_rect = progress_text.get_rect(center=(center_x, center_y + 70))
        self.screen.blit(progress_text, progress_rect)
    
    def render_color_match_challenge(self, game_area: pygame.Rect):
        """色マッチチャレンジの描画"""
        center_x = game_area.centerx
        center_y = game_area.centery
        
        # 指示
        instruction_text = self.fonts["default"].render("Match the colors (1-6 keys)", True, self.colors["white"])
        instruction_rect = instruction_text.get_rect(center=(center_x, center_y - 80))
        self.screen.blit(instruction_text, instruction_rect)
        
        # 色パレット表示
        colors_to_match = [
            self.colors["red"], self.colors["green"], self.colors["blue"],
            self.colors["yellow"], self.colors["purple"], self.colors["orange"]
        ]
        
        # ターゲット色表示
        target_y = center_y - 30
        for i, color_index in enumerate(self.challenge_sequence):
            color = colors_to_match[color_index - 1]
            rect = pygame.Rect(center_x - 100 + i * 40, target_y, 30, 30)
            pygame.draw.rect(self.screen, color, rect)
            pygame.draw.rect(self.screen, self.colors["white"], rect, 2)
        
        # プレイヤー入力表示
        if self.player_sequence:
            player_y = center_y + 30
            for i, color_index in enumerate(self.player_sequence):
                color = colors_to_match[color_index - 1]
                rect = pygame.Rect(center_x - 100 + i * 40, player_y, 30, 30)
                pygame.draw.rect(self.screen, color, rect)
                pygame.draw.rect(self.screen, self.colors["white"], rect, 2)
        
        # 色パレット参照
        palette_y = center_y + 80
        for i, color in enumerate(colors_to_match):
            rect = pygame.Rect(center_x - 120 + i * 40, palette_y, 30, 30)
            pygame.draw.rect(self.screen, color, rect)
            pygame.draw.rect(self.screen, self.colors["white"], rect, 2)
            
            # 番号表示
            num_text = self.fonts["small"].render(str(i + 1), True, self.colors["white"])
            num_rect = num_text.get_rect(center=(rect.centerx, rect.bottom + 10))
            self.screen.blit(num_text, num_rect)
    
    def render_paused(self):
        """ポーズ画面の描画"""
        # ゲーム画面を暗くする
        overlay = pygame.Surface((self.width, self.height))
        overlay.set_alpha(128)
        overlay.fill(self.colors["black"])
        self.screen.blit(overlay, (0, 0))
        
        # ポーズメッセージ
        pause_text = self.fonts["large"].render("PAUSED", True, self.colors["white"])
        pause_rect = pause_text.get_rect(center=(self.width // 2, self.height // 2))
        self.screen.blit(pause_text, pause_rect)
        
        resume_text = self.fonts["default"].render("Press ESC to Resume", True, self.colors["green"])
        resume_rect = resume_text.get_rect(center=(self.width // 2, self.height // 2 + 50))
        self.screen.blit(resume_text, resume_rect)
    
    def render_game_over(self):
        """ゲームオーバー画面の描画"""
        # ゲームオーバーメッセージ
        game_over_text = self.fonts["large"].render("GAME OVER", True, self.colors["red"])
        game_over_rect = game_over_text.get_rect(center=(self.width // 2, self.height // 2 - 50))
        self.screen.blit(game_over_text, game_over_rect)
        
        # 最終スコア
        final_score_text = self.fonts["default"].render(f"Final Score: {self.game_data['score']}", True, self.colors["white"])
        final_score_rect = final_score_text.get_rect(center=(self.width // 2, self.height // 2))
        self.screen.blit(final_score_text, final_score_rect)
        
        # リスタートオプション
        restart_text = self.fonts["default"].render("Press R to Restart", True, self.colors["green"])
        restart_rect = restart_text.get_rect(center=(self.width // 2, self.height // 2 + 50))
        self.screen.blit(restart_text, restart_rect)
        
        menu_text = self.fonts["default"].render("Press M for Menu", True, self.colors["yellow"])
        menu_rect = menu_text.get_rect(center=(self.width // 2, self.height // 2 + 100))
        self.screen.blit(menu_text, menu_rect)
    
    def render_settings(self):
        """設定画面の描画"""
        # 設定タイトル
        settings_title = self.fonts["large"].render("Settings", True, self.colors["white"])
        settings_rect = settings_title.get_rect(center=(self.width // 2, 100))
        self.screen.blit(settings_title, settings_rect)
        
        # 設定項目（プレースホルダー）
        y_offset = 200
        for setting, value in self.game_data["settings"].items():
            setting_text = self.fonts["default"].render(f"{setting}: {value}", True, self.colors["white"])
            self.screen.blit(setting_text, (100, y_offset))
            y_offset += 40
        
        # 戻るオプション
        back_text = self.fonts["default"].render("Press ESC to go back", True, self.colors["yellow"])
        back_rect = back_text.get_rect(center=(self.width // 2, self.height - 100))
        self.screen.blit(back_text, back_rect)
    
    def reset_game(self):
        """ゲームのリセット"""
        self.game_data["score"] = 0
        self.game_data["level"] = 1
        self.game_data["lives"] = 3
        logger.info("ゲームをリセットしました")
    
    def run(self):
        """メインゲームループ"""
        logger.info("ゲームを開始します")
        
        # リソース読み込み
        self.load_resources()
        
        while self.running:
            # デルタタイム計算
            dt = self.clock.tick(self.target_fps) / 1000.0
            
            # イベント処理
            self.handle_events()
            
            # ゲーム更新
            self.update(dt)
            
            # 画面描画
            self.render()
        
        # 終了処理
        self.save_config()
        pygame.quit()
        logger.info("ゲームを終了しました")

def main():
    """メイン実行関数"""
    try:
        game = HeyDooonGameEngine()
        game.run()
    except Exception as e:
        logger.error(f"ゲーム実行エラー: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()