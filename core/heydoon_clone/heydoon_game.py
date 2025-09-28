#!/usr/bin/env python3
"""
HeyDooon クローンゲーム - リアクションベースのタッチゲーム
APK解析結果を基に再現したゲーム実装
"""

import json
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import pygame
import pygame.mixer
from pygame import Surface, Rect
from pygame.font import Font
from pygame.time import Clock

# プロジェクトルート設定
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ASSETS_DIR = PROJECT_ROOT / "assets"
DATA_DIR = PROJECT_ROOT / "data"

class GameState(Enum):
    """ゲーム状態"""
    MENU = "menu"
    PLAYING = "playing"
    RESULT = "result"
    PAUSED = "paused"

class ReactionType(Enum):
    """リアクション種別"""
    TAP = "tap"
    HOLD = "hold"
    SWIPE = "swipe"
    MULTI_TAP = "multi_tap"

@dataclass
class GameConfig:
    """ゲーム設定"""
    screen_width: int = 800
    screen_height: int = 600
    fps: int = 60
    reaction_time_limit: float = 2.0
    difficulty_levels: List[str] = None
    
    def __post_init__(self):
        if self.difficulty_levels is None:
            self.difficulty_levels = ["Easy", "Normal", "Hard", "Expert"]

@dataclass
class Challenge:
    """チャレンジ課題"""
    id: str
    type: ReactionType
    instruction: str
    target_image: Optional[str] = None
    target_color: Optional[Tuple[int, int, int]] = None
    target_shape: Optional[str] = None
    time_limit: float = 2.0
    points: int = 100

@dataclass
class GameResult:
    """ゲーム結果"""
    score: int
    accuracy: float
    reaction_times: List[float]
    challenges_completed: int
    total_challenges: int
    difficulty: str
    timestamp: datetime

def find_japanese_font():
    """日本語フォントを検索"""
    font_candidates = [
        "C:/Windows/Fonts/YuGothM.ttc",
        "C:/Windows/Fonts/meiryo.ttc", 
        "C:/Windows/Fonts/msgothic.ttc",
        "/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"
    ]
    
    for font_path in font_candidates:
        if Path(font_path).exists():
            return font_path
    return None

class HeyDooonClone:
    """HeyDooon クローンゲームメインクラス"""
    
    def __init__(self, config: GameConfig = None):
        """ゲーム初期化"""
        self.config = config or GameConfig()
        self.state = GameState.MENU
        self.score = 0
        self.current_challenge = None
        self.challenge_start_time = 0
        self.reaction_times = []
        self.challenges = []
        self.current_challenge_index = 0
        self.difficulty = "Normal"
        
        # Pygame初期化
        pygame.init()
        pygame.mixer.init()
        
        # 画面設定
        self.screen = pygame.display.set_mode(
            (self.config.screen_width, self.config.screen_height)
        )
        pygame.display.set_caption("HeyDooon Clone - Reaction Game")
        
        # 日本語フォント設定
        japanese_font = find_japanese_font()
        if japanese_font:
            self.font_large = pygame.font.Font(japanese_font, 48)
            self.font_medium = pygame.font.Font(japanese_font, 32)
            self.font_small = pygame.font.Font(japanese_font, 24)
        else:
            # フォールバック（英語のみ）
            self.font_large = pygame.font.Font(None, 48)
            self.font_medium = pygame.font.Font(None, 32)
            self.font_small = pygame.font.Font(None, 24)
        
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
        
        # クロック
        self.clock = Clock()
        
        # チャレンジ生成
        self._generate_challenges()
        
        # サウンド読み込み
        self._load_sounds()
        
        print("🎮 HeyDooon Clone ゲーム初期化完了")

    def _load_sounds(self):
        """サウンド読み込み"""
        self.sounds = {
            'correct': None,
            'wrong': None,
            'reveal': None
        }
        
        # サウンドファイルが存在する場合のみ読み込み
        sound_dir = ASSETS_DIR / "se"
        if sound_dir.exists():
            for name, filename in [('correct', 'win.wav'), ('wrong', 'fault.wav'), ('reveal', 'reveal.wav')]:
                path = sound_dir / filename
                if path.exists():
                    try:
                        self.sounds[name] = pygame.mixer.Sound(str(path))
                    except pygame.error:
                        pass

    def _generate_challenges(self):
        """チャレンジ課題を生成"""
        self.challenges = []
        
        # 色認識チャレンジ（英語表記に変更）
        colors = ['red', 'green', 'blue', 'yellow', 'purple', 'orange']
        for i, color in enumerate(colors):
            self.challenges.append(Challenge(
                id=f"color_{color}",
                type=ReactionType.TAP,
                instruction=f"Tap {color.upper()} color!",
                target_color=self.colors[color],
                time_limit=2.0,
                points=100
            ))
        
        # 形状認識チャレンジ（英語表記に変更）
        shapes = ['circle', 'square', 'triangle', 'star']
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
        for i in range(5):
            self.challenges.append(Challenge(
                id=f"speed_{i}",
                type=ReactionType.TAP,
                instruction="Tap when screen flashes!",
                time_limit=1.0,
                points=200
            ))
        
        # マルチタップチャレンジ
        for i in range(3):
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

    def run(self):
        """メインゲームループ"""
        running = True
        
        while running:
            dt = self.clock.tick(self.config.fps) / 1000.0
            
            # イベント処理
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        running = False
                    elif event.key == pygame.K_SPACE:
                        if self.state == GameState.MENU:
                            self._start_game()
                        elif self.state == GameState.RESULT:
                            self._reset_game()
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    self._handle_click(event.pos)
            
            # 状態別更新
            if self.state == GameState.PLAYING:
                self._update_game(dt)
            
            # 描画
            self._render()
            pygame.display.flip()
        
        pygame.quit()
    
    def _handle_click(self, pos: Tuple[int, int]):
        """クリック処理"""
        if self.state == GameState.MENU:
            # スタートボタンチェック
            start_rect = Rect(300, 400, 200, 60)
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
            restart_rect = Rect(300, 450, 200, 60)
            if restart_rect.collidepoint(pos):
                self._reset_game()
    
    def _handle_tap_challenge(self, pos: Tuple[int, int], reaction_time: float):
        """タップチャレンジ処理"""
        success = False
        
        if self.current_challenge.target_color:
            # 色チャレンジ - 画面中央の色付き円をチェック
            center = (self.config.screen_width // 2, self.config.screen_height // 2)
            distance = ((pos[0] - center[0]) ** 2 + (pos[1] - center[1]) ** 2) ** 0.5
            if distance <= 100:  # 円の半径
                success = True
        
        elif self.current_challenge.target_shape:
            # 形状チャレンジ - 画面中央の形状をチェック
            center = (self.config.screen_width // 2, self.config.screen_height // 2)
            distance = ((pos[0] - center[0]) ** 2 + (pos[1] - center[1]) ** 2) ** 0.5
            if distance <= 80:  # 形状の範囲
                success = True
        
        else:
            # 反応速度チャレンジ - どこでもOK
            success = True
        
        self._complete_challenge(success, reaction_time)
    
    def _handle_multi_tap_challenge(self, pos: Tuple[int, int], reaction_time: float):
        """マルチタップチャレンジ処理"""
        # 簡単な実装：3回タップで成功
        if not hasattr(self, 'tap_count'):
            self.tap_count = 0
        
        self.tap_count += 1
        
        if self.tap_count >= 3:
            self._complete_challenge(True, reaction_time)
            self.tap_count = 0
        elif reaction_time > self.current_challenge.time_limit:
            self._complete_challenge(False, reaction_time)
            self.tap_count = 0
    
    def _complete_challenge(self, success: bool, reaction_time: float):
        """チャレンジ完了処理"""
        if success and reaction_time <= self.current_challenge.time_limit:
            # 成功
            points = max(50, int(self.current_challenge.points * (1.0 - reaction_time / self.current_challenge.time_limit)))
            self.score += points
            self.reaction_times.append(reaction_time)
            
            if self.sounds['correct']:
                self.sounds['correct'].play()
            
            print(f"✅ 成功! +{points}点 (反応時間: {reaction_time:.3f}s)")
        
        else:
            # 失敗
            if self.sounds['wrong']:
                self.sounds['wrong'].play()
            
            print(f"❌ 失敗 (反応時間: {reaction_time:.3f}s)")
        
        # 次のチャレンジへ
        self.current_challenge_index += 1
        
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
        self._start_next_challenge()
        print("🎮 ゲーム開始!")
    
    def _start_next_challenge(self):
        """次のチャレンジ開始"""
        if self.current_challenge_index < len(self.challenges):
            self.current_challenge = self.challenges[self.current_challenge_index]
            self.challenge_start_time = time.time()
            
            if self.sounds['reveal']:
                self.sounds['reveal'].play()
            
            print(f"📋 チャレンジ {self.current_challenge_index + 1}: {self.current_challenge.instruction}")
    
    def _update_game(self, dt: float):
        """ゲーム更新"""
        if self.current_challenge:
            elapsed = time.time() - self.challenge_start_time
            
            # タイムアウトチェック
            if elapsed > self.current_challenge.time_limit:
                self._complete_challenge(False, elapsed)
    
    def _end_game(self):
        """ゲーム終了"""
        self.state = GameState.RESULT
        
        # 結果計算
        accuracy = len(self.reaction_times) / len(self.challenges) * 100
        avg_reaction = sum(self.reaction_times) / len(self.reaction_times) if self.reaction_times else 0
        
        result = GameResult(
            score=self.score,
            accuracy=accuracy,
            reaction_times=self.reaction_times,
            challenges_completed=len(self.reaction_times),
            total_challenges=len(self.challenges),
            difficulty=self.difficulty,
            timestamp=datetime.now()
        )
        
        # 結果保存
        self._save_result(result)
        
        print(f"🏁 ゲーム終了! スコア: {self.score}, 正解率: {accuracy:.1f}%, 平均反応時間: {avg_reaction:.3f}s")
    
    def _save_result(self, result: GameResult):
        """結果保存"""
        results_file = DATA_DIR / "heydoon_results.json"
        
        try:
            # 既存結果読み込み
            if results_file.exists():
                with open(results_file, 'r', encoding='utf-8') as f:
                    results = json.load(f)
            else:
                results = []
            
            # 新しい結果追加
            result_dict = {
                'score': result.score,
                'accuracy': result.accuracy,
                'reaction_times': result.reaction_times,
                'challenges_completed': result.challenges_completed,
                'total_challenges': result.total_challenges,
                'difficulty': result.difficulty,
                'timestamp': result.timestamp.isoformat()
            }
            
            results.append(result_dict)
            
            # 保存
            results_file.parent.mkdir(parents=True, exist_ok=True)
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            print(f"💾 結果を保存しました: {results_file}")
        
        except Exception as e:
            print(f"❌ 結果保存エラー: {e}")
    
    def _reset_game(self):
        """ゲームリセット"""
        self.state = GameState.MENU
        self.current_challenge = None
        self.current_challenge_index = 0
        self.score = 0
        self.reaction_times = []
        self._generate_challenges()  # 新しいチャレンジ生成
    
    def _render(self):
        """画面描画"""
        self.screen.fill(self.colors['white'])
        
        if self.state == GameState.MENU:
            self._render_menu()
        elif self.state == GameState.PLAYING:
            self._render_game()
        elif self.state == GameState.RESULT:
            self._render_result()
    
    def _render_menu(self):
        """メニュー画面描画"""
        # タイトル
        title = self.font_large.render("HeyDooon Clone", True, self.colors['black'])
        title_rect = title.get_rect(center=(self.config.screen_width // 2, 150))
        self.screen.blit(title, title_rect)
        
        # サブタイトル
        subtitle = self.font_medium.render("Reaction Game", True, self.colors['gray'])
        subtitle_rect = subtitle.get_rect(center=(self.config.screen_width // 2, 200))
        self.screen.blit(subtitle, subtitle_rect)
        
        # 説明（英語に変更）
        instructions = [
            "React quickly to on-screen instructions!",
            "Identify colors and shapes by tapping",
            "Speed and accuracy are key",
            "",
            "SPACE or Click to START"
        ]
        
        for i, instruction in enumerate(instructions):
            text = self.font_small.render(instruction, True, self.colors['black'])
            text_rect = text.get_rect(center=(self.config.screen_width // 2, 280 + i * 30))
            self.screen.blit(text, text_rect)
        
        # スタートボタン
        start_rect = Rect(300, 400, 200, 60)
        pygame.draw.rect(self.screen, self.colors['green'], start_rect)
        pygame.draw.rect(self.screen, self.colors['black'], start_rect, 2)
        
        start_text = self.font_medium.render("START", True, self.colors['white'])
        start_text_rect = start_text.get_rect(center=start_rect.center)
        self.screen.blit(start_text, start_text_rect)
    
    def _render_game(self):
        """ゲーム画面描画"""
        if not self.current_challenge:
            return
        
        # 進捗表示
        progress = f"チャレンジ {self.current_challenge_index + 1}/{len(self.challenges)}"
        progress_text = self.font_small.render(progress, True, self.colors['black'])
        self.screen.blit(progress_text, (10, 10))
        
        # スコア表示
        score_text = self.font_small.render(f"スコア: {self.score}", True, self.colors['black'])
        score_rect = score_text.get_rect(topright=(self.config.screen_width - 10, 10))
        self.screen.blit(score_text, score_rect)
        
        # 指示文表示
        instruction = self.font_large.render(self.current_challenge.instruction, True, self.colors['black'])
        instruction_rect = instruction.get_rect(center=(self.config.screen_width // 2, 100))
        self.screen.blit(instruction, instruction_rect)
        
        # チャレンジ内容描画
        center = (self.config.screen_width // 2, self.config.screen_height // 2)
        
        if self.current_challenge.target_color:
            # 色チャレンジ - 色付き円を描画
            pygame.draw.circle(self.screen, self.current_challenge.target_color, center, 100)
            pygame.draw.circle(self.screen, self.colors['black'], center, 100, 3)
        
        elif self.current_challenge.target_shape:
            # 形状チャレンジ - 形状を描画
            self._draw_shape(self.current_challenge.target_shape, center, 80)
        
        else:
            # 反応速度チャレンジ - 光る効果
            elapsed = time.time() - self.challenge_start_time
            if elapsed > 0.5:  # 0.5秒後に光る
                pygame.draw.circle(self.screen, self.colors['yellow'], center, 120)
                pygame.draw.circle(self.screen, self.colors['black'], center, 120, 5)
        
        # タイムバー
        elapsed = time.time() - self.challenge_start_time
        remaining = max(0, self.current_challenge.time_limit - elapsed)
        bar_width = int((remaining / self.current_challenge.time_limit) * 400)
        
        bar_rect = Rect(200, 500, 400, 20)
        pygame.draw.rect(self.screen, self.colors['light_gray'], bar_rect)
        
        if bar_width > 0:
            fill_rect = Rect(200, 500, bar_width, 20)
            color = self.colors['green'] if remaining > 0.5 else self.colors['red']
            pygame.draw.rect(self.screen, color, fill_rect)
        
        pygame.draw.rect(self.screen, self.colors['black'], bar_rect, 2)
    
    def _draw_shape(self, shape: str, center: Tuple[int, int], size: int):
        """形状描画"""
        x, y = center
        
        if shape == 'circle':
            pygame.draw.circle(self.screen, self.colors['blue'], center, size)
            pygame.draw.circle(self.screen, self.colors['black'], center, size, 3)
        
        elif shape == 'square':
            rect = Rect(x - size, y - size, size * 2, size * 2)
            pygame.draw.rect(self.screen, self.colors['red'], rect)
            pygame.draw.rect(self.screen, self.colors['black'], rect, 3)
        
        elif shape == 'triangle':
            points = [
                (x, y - size),
                (x - size, y + size),
                (x + size, y + size)
            ]
            pygame.draw.polygon(self.screen, self.colors['green'], points)
            pygame.draw.polygon(self.screen, self.colors['black'], points, 3)
        
        elif shape == 'star':
            # 簡単な星形（5角星）
            import math
            points = []
            for i in range(10):
                angle = i * math.pi / 5
                radius = size if i % 2 == 0 else size // 2
                px = x + radius * math.cos(angle - math.pi / 2)
                py = y + radius * math.sin(angle - math.pi / 2)
                points.append((px, py))
            
            pygame.draw.polygon(self.screen, self.colors['yellow'], points)
            pygame.draw.polygon(self.screen, self.colors['black'], points, 3)
    
    def _render_result(self):
        """結果画面描画"""
        # タイトル
        title = self.font_large.render("ゲーム結果", True, self.colors['black'])
        title_rect = title.get_rect(center=(self.config.screen_width // 2, 100))
        self.screen.blit(title, title_rect)
        
        # 結果詳細
        accuracy = len(self.reaction_times) / len(self.challenges) * 100 if self.challenges else 0
        avg_reaction = sum(self.reaction_times) / len(self.reaction_times) if self.reaction_times else 0
        
        results = [
            f"最終スコア: {self.score}",
            f"正解率: {accuracy:.1f}% ({len(self.reaction_times)}/{len(self.challenges)})",
            f"平均反応時間: {avg_reaction:.3f}秒",
            f"最速反応: {min(self.reaction_times):.3f}秒" if self.reaction_times else "最速反応: --",
        ]
        
        for i, result in enumerate(results):
            text = self.font_medium.render(result, True, self.colors['black'])
            text_rect = text.get_rect(center=(self.config.screen_width // 2, 200 + i * 40))
            self.screen.blit(text, text_rect)
        
        # 評価
        if accuracy >= 90:
            grade = "EXCELLENT!"
            grade_color = self.colors['green']
        elif accuracy >= 70:
            grade = "GOOD!"
            grade_color = self.colors['blue']
        elif accuracy >= 50:
            grade = "OK"
            grade_color = self.colors['orange']
        else:
            grade = "TRY AGAIN"
            grade_color = self.colors['red']
        
        grade_text = self.font_large.render(grade, True, grade_color)
        grade_rect = grade_text.get_rect(center=(self.config.screen_width // 2, 360))
        self.screen.blit(grade_text, grade_rect)
        
        # リスタートボタン
        restart_rect = Rect(300, 450, 200, 60)
        pygame.draw.rect(self.screen, self.colors['blue'], restart_rect)
        pygame.draw.rect(self.screen, self.colors['black'], restart_rect, 2)
        
        restart_text = self.font_medium.render("RESTART", True, self.colors['white'])
        restart_text_rect = restart_text.get_rect(center=restart_rect.center)
        self.screen.blit(restart_text, restart_text_rect)

def main():
    """メイン実行関数"""
    print("🚀 HeyDooon Clone ゲーム起動中...")
    
    # ゲーム設定
    config = GameConfig(
        screen_width=800,
        screen_height=600,
        fps=60,
        reaction_time_limit=2.0
    )
    
    # ゲーム実行
    game = HeyDooonClone(config)
    game.run()

if __name__ == "__main__":
    main()