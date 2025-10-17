#!/usr/bin/env python3
"""
HeyDooon Complete Clone - メインゲームクラス
"""

import pygame
import sys
import os
import random
import time
from enum import Enum
from dataclasses import dataclass
from typing import Tuple, List, Optional

class GameState(Enum):
    """ゲーム状態"""
    MENU = "menu"
    PLAYING = "playing"
    RESULT = "result"

class ReactionType(Enum):
    """リアクション種別"""
    TAP = "tap"
    MULTI_TAP = "multi_tap"

@dataclass
class Challenge:
    """チャレンジ課題"""
    id: str
    type: ReactionType
    instruction: str
    target_color: Optional[Tuple[int, int, int]] = None
    target_shape: Optional[str] = None
    time_limit: float = 2.0
    points: int = 100

class HeyDooonCompleteClone:
    """HeyDooon完全クローンメインクラス"""
    
    def __init__(self):
        """ゲーム初期化"""
        pygame.init()
        pygame.mixer.init()
        
        # 画面設定
        self.screen_width = 800
        self.screen_height = 600
        self.fps = 60
        
        self.screen = pygame.display.set_mode((self.screen_width, self.screen_height))
        pygame.display.set_caption("HeyDooon Complete Clone")
        
        # フォント設定
        try:
            self.title_font = pygame.font.SysFont("arial", 48)
            self.font = pygame.font.SysFont("arial", 24)
            self.large_font = pygame.font.SysFont("arial", 36)
        except:
            self.title_font = pygame.font.Font(None, 48)
            self.font = pygame.font.Font(None, 24)
            self.large_font = pygame.font.Font(None, 36)
        
        # 色定義
        self.colors = {
            'white': (255, 255, 255),
            'black': (0, 0, 0),
            'red': (255, 0, 0),
            'green': (0, 255, 0),
            'blue': (0, 0, 255),
            'yellow': (255, 255, 0),
            'purple': (128, 0, 128),
            'orange': (255, 165, 0),
            'gray': (128, 128, 128),
            'light_gray': (200, 200, 200)
        }
        
        # ゲーム状態
        self.clock = pygame.time.Clock()
        self.running = True
        self.state = GameState.MENU
        self.score = 0
        self.current_challenge = None
        self.challenge_start_time = 0
        self.current_challenge_index = 0
        self.challenges = []
        self.reaction_times = []
        self.multi_tap_count = 0
        
        # チャレンジ生成
        self._generate_challenges()
        
        print("🎮 HeyDooon Complete Clone 初期化完了")
    
    def _generate_challenges(self):
        """チャレンジ課題を生成"""
        self.challenges = []
        
        # 色認識チャレンジ
        colors = ['red', 'green', 'blue', 'yellow', 'purple', 'orange']
        for color in colors:
            self.challenges.append(Challenge(
                id=f"color_{color}",
                type=ReactionType.TAP,
                instruction=f"Tap {color.upper()} color!",
                target_color=self.colors[color],
                time_limit=2.0,
                points=100
            ))
        
        # 形状認識チャレンジ
        shapes = ['circle', 'square', 'triangle']
        for shape in shapes:
            self.challenges.append(Challenge(
                id=f"shape_{shape}",
                type=ReactionType.TAP,
                instruction=f"Tap {shape.upper()}!",
                target_shape=shape,
                time_limit=1.8,
                points=150
            ))
        
        # 反応速度チャレンジ
        for i in range(3):
            self.challenges.append(Challenge(
                id=f"speed_{i}",
                type=ReactionType.TAP,
                instruction="Tap when screen flashes!",
                time_limit=1.0,
                points=200
            ))
        
        # マルチタップチャレンジ
        for i in range(2):
            self.challenges.append(Challenge(
                id=f"multi_{i}",
                type=ReactionType.MULTI_TAP,
                instruction="Triple tap quickly!",
                time_limit=2.5,
                points=300
            ))
        
        # チャレンジをシャッフル
        random.shuffle(self.challenges)
        print(f"📝 Generated {len(self.challenges)} challenges")
    
    def handle_events(self):
        """イベント処理"""
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    if self.state == GameState.PLAYING:
                        self.state = GameState.MENU
                        self.current_challenge = None
                    else:
                        self.running = False
                elif event.key == pygame.K_SPACE:
                    if self.state == GameState.MENU:
                        self._start_game()
                    elif self.state == GameState.RESULT:
                        self._reset_game()
            elif event.type == pygame.MOUSEBUTTONDOWN:
                self._handle_click(event.pos)
    
    def _handle_click(self, pos: Tuple[int, int]):
        """クリック処理"""
        if self.state == GameState.MENU:
            # スタートボタンチェック
            start_rect = pygame.Rect(300, 400, 200, 60)
            if start_rect.collidepoint(pos):
                self._start_game()
        
        elif self.state == GameState.PLAYING and self.current_challenge:
            # チャレンジ応答処理
            reaction_time = time.time() - self.challenge_start_time
            
            if self.current_challenge.type == ReactionType.TAP:
                self._handle_tap_challenge(pos, reaction_time)
            elif self.current_challenge.type == ReactionType.MULTI_TAP:
                self._handle_multi_tap_challenge(pos, reaction_time)
        
        elif self.state == GameState.RESULT:
            # リスタートボタンチェック
            restart_rect = pygame.Rect(300, 450, 200, 60)
            if restart_rect.collidepoint(pos):
                self._reset_game()
    
    def _handle_tap_challenge(self, pos: Tuple[int, int], reaction_time: float):
        """タップチャレンジ処理"""
        success = False
        
        if self.current_challenge.target_color or self.current_challenge.target_shape:
            # 画面中央の対象をチェック
            center = (self.screen_width // 2, self.screen_height // 2)
            distance = ((pos[0] - center[0]) ** 2 + (pos[1] - center[1]) ** 2) ** 0.5
            if distance <= 100:  # 対象の範囲
                success = True
        else:
            # 反応速度チャレンジ - どこでもOK
            success = True
        
        self._complete_challenge(success, reaction_time)
    
    def _handle_multi_tap_challenge(self, pos: Tuple[int, int], reaction_time: float):
        """マルチタップチャレンジ処理"""
        center = (self.screen_width // 2, self.screen_height // 2)
        distance = ((pos[0] - center[0]) ** 2 + (pos[1] - center[1]) ** 2) ** 0.5
        
        if distance <= 100:
            self.multi_tap_count += 1
            print(f"タップ {self.multi_tap_count}/3")
            
            if self.multi_tap_count >= 3:
                self._complete_challenge(True, reaction_time)
    
    def _complete_challenge(self, success: bool, reaction_time: float):
        """チャレンジ完了処理"""
        if success and reaction_time <= self.current_challenge.time_limit:
            # 成功
            points = max(50, int(self.current_challenge.points * (1.0 - reaction_time / self.current_challenge.time_limit)))
            self.score += points
            self.reaction_times.append(reaction_time)
            print(f"✅ 成功! +{points}点 (反応時間: {reaction_time:.3f}s)")
        else:
            # 失敗
            print(f"❌ 失敗 (反応時間: {reaction_time:.3f}s)")
        
        # 次のチャレンジへ
        self.current_challenge_index += 1
        self.multi_tap_count = 0
        
        if self.current_challenge_index >= len(self.challenges):
            self._end_game()
        else:
            self._start_next_challenge()
    
    def _start_game(self):
        """ゲーム開始"""
        self.state = GameState.PLAYING
        self.score = 0
        self.reaction_times = []
        self.current_challenge_index = 0
        self.multi_tap_count = 0
        self._start_next_challenge()
        print("🎮 ゲーム開始!")
    
    def _start_next_challenge(self):
        """次のチャレンジ開始"""
        if self.current_challenge_index < len(self.challenges):
            self.current_challenge = self.challenges[self.current_challenge_index]
            self.challenge_start_time = time.time()
            print(f"📋 チャレンジ {self.current_challenge_index + 1}: {self.current_challenge.instruction}")
    
    def _end_game(self):
        """ゲーム終了"""
        self.state = GameState.RESULT
        accuracy = len(self.reaction_times) / len(self.challenges) * 100 if self.challenges else 0
        avg_reaction = sum(self.reaction_times) / len(self.reaction_times) if self.reaction_times else 0
        print(f"🏁 ゲーム終了! スコア: {self.score}, 正解率: {accuracy:.1f}%, 平均反応時間: {avg_reaction:.3f}s")
    
    def _reset_game(self):
        """ゲームリセット"""
        self.state = GameState.MENU
        self.current_challenge = None
        self.current_challenge_index = 0
        self.score = 0
        self.reaction_times = []
        self.multi_tap_count = 0
        self._generate_challenges()
    
    def update(self, dt):
        """ゲーム更新"""
        if self.state == GameState.PLAYING and self.current_challenge:
            elapsed = time.time() - self.challenge_start_time
            
            # タイムアウトチェック
            if elapsed > self.current_challenge.time_limit:
                self._complete_challenge(False, elapsed)
    
    def render(self):
        """描画処理"""
        self.screen.fill(self.colors['white'])
        
        if self.state == GameState.MENU:
            self._render_menu()
        elif self.state == GameState.PLAYING:
            self._render_game()
        elif self.state == GameState.RESULT:
            self._render_result()
        
        pygame.display.flip()
    
    def _render_menu(self):
        """メニュー画面描画"""
        # タイトル
        title = self.title_font.render("HeyDooon Clone", True, self.colors['black'])
        title_rect = title.get_rect(center=(self.screen_width // 2, 150))
        self.screen.blit(title, title_rect)
        
        # サブタイトル
        subtitle = self.large_font.render("Reaction Game", True, self.colors['gray'])
        subtitle_rect = subtitle.get_rect(center=(self.screen_width // 2, 200))
        self.screen.blit(subtitle, subtitle_rect)
        
        # 説明
        instructions = [
            "React quickly to on-screen instructions!",
            "Identify colors and shapes by tapping",
            "Speed and accuracy are key",
            "",
            "SPACE or Click to START"
        ]
        
        for i, instruction in enumerate(instructions):
            text = self.font.render(instruction, True, self.colors['black'])
            text_rect = text.get_rect(center=(self.screen_width // 2, 280 + i * 30))
            self.screen.blit(text, text_rect)
        
        # スタートボタン
        start_rect = pygame.Rect(300, 400, 200, 60)
        pygame.draw.rect(self.screen, self.colors['green'], start_rect)
        pygame.draw.rect(self.screen, self.colors['black'], start_rect, 2)
        
        start_text = self.large_font.render("START", True, self.colors['white'])
        start_text_rect = start_text.get_rect(center=start_rect.center)
        self.screen.blit(start_text, start_text_rect)
    
    def _render_game(self):
        """ゲーム画面描画"""
        if not self.current_challenge:
            return
        
        # 進捗表示
        progress = f"Challenge {self.current_challenge_index + 1}/{len(self.challenges)}"
        progress_text = self.font.render(progress, True, self.colors['black'])
        self.screen.blit(progress_text, (10, 10))
        
        # スコア表示
        score_text = self.font.render(f"Score: {self.score}", True, self.colors['black'])
        score_rect = score_text.get_rect(topright=(self.screen_width - 10, 10))
        self.screen.blit(score_text, score_rect)
        
        # 指示文表示
        instruction = self.large_font.render(self.current_challenge.instruction, True, self.colors['black'])
        instruction_rect = instruction.get_rect(center=(self.screen_width // 2, 100))
        self.screen.blit(instruction, instruction_rect)
        
        # チャレンジ内容描画
        center = (self.screen_width // 2, self.screen_height // 2)
        
        if self.current_challenge.target_color:
            # 色チャレンジ - 色付き円を描画
            pygame.draw.circle(self.screen, self.current_challenge.target_color, center, 100)
            pygame.draw.circle(self.screen, self.colors['black'], center, 100, 3)
        
        elif self.current_challenge.target_shape:
            # 形状チャレンジ - 形状を描画
            self._draw_shape(self.current_challenge.target_shape, center, 80)
        
        else:
            # 反応速度チャレンジ - フラッシュ効果
            flash_color = self.colors['yellow'] if int(time.time() * 10) % 2 else self.colors['white']
            pygame.draw.circle(self.screen, flash_color, center, 100)
            pygame.draw.circle(self.screen, self.colors['black'], center, 100, 3)
        
        # マルチタップの場合、カウント表示
        if self.current_challenge.type == ReactionType.MULTI_TAP:
            count_text = self.large_font.render(f"Taps: {self.multi_tap_count}/3", True, self.colors['black'])
            count_rect = count_text.get_rect(center=(self.screen_width // 2, self.screen_height // 2 + 150))
            self.screen.blit(count_text, count_rect)
        
        # 残り時間表示
        elapsed = time.time() - self.challenge_start_time
        remaining = max(0, self.current_challenge.time_limit - elapsed)
        time_text = self.font.render(f"Time: {remaining:.1f}s", True, self.colors['red'])
        time_rect = time_text.get_rect(center=(self.screen_width // 2, 50))
        self.screen.blit(time_text, time_rect)
    
    def _draw_shape(self, shape: str, center: Tuple[int, int], size: int):
        """形状を描画"""
        if shape == "circle":
            pygame.draw.circle(self.screen, self.colors['blue'], center, size)
            pygame.draw.circle(self.screen, self.colors['black'], center, size, 3)
        elif shape == "square":
            rect = pygame.Rect(center[0] - size, center[1] - size, size * 2, size * 2)
            pygame.draw.rect(self.screen, self.colors['red'], rect)
            pygame.draw.rect(self.screen, self.colors['black'], rect, 3)
        elif shape == "triangle":
            points = [
                (center[0], center[1] - size),
                (center[0] - size, center[1] + size),
                (center[0] + size, center[1] + size)
            ]
            pygame.draw.polygon(self.screen, self.colors['green'], points)
            pygame.draw.polygon(self.screen, self.colors['black'], points, 3)
    
    def _render_result(self):
        """結果画面描画"""
        # 結果タイトル
        result_title = self.title_font.render("GAME OVER", True, self.colors['black'])
        result_rect = result_title.get_rect(center=(self.screen_width // 2, 150))
        self.screen.blit(result_title, result_rect)
        
        # スコア
        score_text = self.large_font.render(f"Final Score: {self.score}", True, self.colors['black'])
        score_rect = score_text.get_rect(center=(self.screen_width // 2, 220))
        self.screen.blit(score_text, score_rect)
        
        # 統計
        accuracy = len(self.reaction_times) / len(self.challenges) * 100 if self.challenges else 0
        accuracy_text = self.font.render(f"Accuracy: {accuracy:.1f}%", True, self.colors['black'])
        accuracy_rect = accuracy_text.get_rect(center=(self.screen_width // 2, 270))
        self.screen.blit(accuracy_text, accuracy_rect)
        
        if self.reaction_times:
            avg_reaction = sum(self.reaction_times) / len(self.reaction_times)
            avg_text = self.font.render(f"Avg Reaction: {avg_reaction:.3f}s", True, self.colors['black'])
            avg_rect = avg_text.get_rect(center=(self.screen_width // 2, 300))
            self.screen.blit(avg_text, avg_rect)
        
        # 操作説明
        restart_instruction = self.font.render("SPACE or Click to Play Again", True, self.colors['gray'])
        restart_rect = restart_instruction.get_rect(center=(self.screen_width // 2, 380))
        self.screen.blit(restart_instruction, restart_rect)
        
        # リスタートボタン
        restart_button_rect = pygame.Rect(300, 450, 200, 60)
        pygame.draw.rect(self.screen, self.colors['blue'], restart_button_rect)
        pygame.draw.rect(self.screen, self.colors['black'], restart_button_rect, 2)
        
        restart_text = self.large_font.render("RESTART", True, self.colors['white'])
        restart_text_rect = restart_text.get_rect(center=restart_button_rect.center)
        self.screen.blit(restart_text, restart_text_rect)
    
    def run(self):
        """メインゲームループ"""
        while self.running:
            dt = self.clock.tick(self.fps) / 1000.0
            
            self.handle_events()
            self.update(dt)
            self.render()
        
        pygame.quit()
        sys.exit()

def main():
    """メイン実行関数"""
    print("🎮 HeyDooon Complete Clone 起動中...")
    game = HeyDooonCompleteClone()
    game.run()

if __name__ == "__main__":
    main()
