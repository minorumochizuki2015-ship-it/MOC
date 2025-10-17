#!/usr/bin/env python3
"""
HeyDooon クローンゲーム - ゲームメカニクス
スコアリング、レベル進行、ゲームルール、勝敗判定システム
"""

import pygame
import random
import math
import time
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

class ChallengeType(Enum):
    """チャレンジタイプの定義"""
    REACTION_TIME = "reaction_time"
    SEQUENCE_MEMORY = "sequence_memory"
    COLOR_MATCH = "color_match"
    PATTERN_RECOGNITION = "pattern_recognition"
    SPEED_TAP = "speed_tap"

class DifficultyLevel(Enum):
    """難易度レベル"""
    EASY = "easy"
    NORMAL = "normal"
    HARD = "hard"
    EXPERT = "expert"

@dataclass
class Challenge:
    """チャレンジデータクラス"""
    challenge_type: ChallengeType
    difficulty: DifficultyLevel
    target_value: float  # 目標値（時間、回数など）
    tolerance: float     # 許容誤差
    max_attempts: int    # 最大試行回数
    time_limit: float    # 制限時間
    bonus_multiplier: float = 1.0  # ボーナス倍率

@dataclass
class GameResult:
    """ゲーム結果データクラス"""
    challenge: Challenge
    success: bool
    score: int
    reaction_time: float
    accuracy: float
    attempts_used: int
    bonus_earned: int = 0

class ScoreCalculator:
    """スコア計算システム"""
    
    BASE_SCORES = {
        ChallengeType.REACTION_TIME: 100,
        ChallengeType.SEQUENCE_MEMORY: 150,
        ChallengeType.COLOR_MATCH: 120,
        ChallengeType.PATTERN_RECOGNITION: 180,
        ChallengeType.SPEED_TAP: 80
    }
    
    DIFFICULTY_MULTIPLIERS = {
        DifficultyLevel.EASY: 1.0,
        DifficultyLevel.NORMAL: 1.5,
        DifficultyLevel.HARD: 2.0,
        DifficultyLevel.EXPERT: 3.0
    }
    
    @classmethod
    def calculate_score(cls, challenge: Challenge, reaction_time: float, 
                       accuracy: float, attempts_used: int) -> Tuple[int, int]:
        """
        スコア計算
        
        Args:
            challenge: チャレンジ情報
            reaction_time: 反応時間
            accuracy: 精度
            attempts_used: 使用試行回数
            
        Returns:
            (基本スコア, ボーナススコア)
        """
        base_score = cls.BASE_SCORES[challenge.challenge_type]
        difficulty_multiplier = cls.DIFFICULTY_MULTIPLIERS[challenge.difficulty]
        
        # 基本スコア計算
        score = int(base_score * difficulty_multiplier)
        
        # 精度ボーナス
        accuracy_bonus = int(score * accuracy * 0.5)
        
        # 速度ボーナス（反応時間が短いほど高い）
        if reaction_time > 0:
            speed_bonus = int(score * max(0, (2.0 - reaction_time) / 2.0) * 0.3)
        else:
            speed_bonus = 0
        
        # 試行回数ボーナス（少ない試行回数ほど高い）
        attempt_bonus = int(score * (challenge.max_attempts - attempts_used) / challenge.max_attempts * 0.2)
        
        # チャレンジボーナス
        challenge_bonus = int(score * challenge.bonus_multiplier)
        
        total_bonus = accuracy_bonus + speed_bonus + attempt_bonus + challenge_bonus
        
        return score, total_bonus

class LevelProgression:
    """レベル進行システム"""
    
    def __init__(self):
        self.level = 1
        self.experience = 0
        self.experience_to_next_level = 1000
        self.total_experience = 0
        
        # レベル別設定
        self.level_configs = {
            1: {"challenges_per_level": 3, "difficulty_weights": {"easy": 0.7, "normal": 0.3}},
            2: {"challenges_per_level": 4, "difficulty_weights": {"easy": 0.5, "normal": 0.4, "hard": 0.1}},
            3: {"challenges_per_level": 5, "difficulty_weights": {"easy": 0.3, "normal": 0.5, "hard": 0.2}},
            4: {"challenges_per_level": 5, "difficulty_weights": {"normal": 0.4, "hard": 0.4, "expert": 0.2}},
            5: {"challenges_per_level": 6, "difficulty_weights": {"normal": 0.2, "hard": 0.5, "expert": 0.3}},
        }
    
    def add_experience(self, exp: int) -> bool:
        """
        経験値追加とレベルアップチェック
        
        Args:
            exp: 追加経験値
            
        Returns:
            レベルアップしたかどうか
        """
        self.experience += exp
        self.total_experience += exp
        
        if self.experience >= self.experience_to_next_level:
            return self._level_up()
        
        return False
    
    def _level_up(self) -> bool:
        """レベルアップ処理"""
        old_level = self.level
        self.level += 1
        self.experience -= self.experience_to_next_level
        
        # 次のレベルまでの必要経験値を計算（指数的増加）
        self.experience_to_next_level = int(1000 * (1.5 ** (self.level - 1)))
        
        logger.info(f"レベルアップ: {old_level} -> {self.level}")
        return True
    
    def get_current_config(self) -> Dict[str, Any]:
        """現在のレベル設定を取得"""
        if self.level in self.level_configs:
            return self.level_configs[self.level]
        else:
            # 高レベル用のデフォルト設定
            return {
                "challenges_per_level": min(8, 5 + (self.level - 5)),
                "difficulty_weights": {"hard": 0.3, "expert": 0.7}
            }

class ChallengeGenerator:
    """チャレンジ生成システム"""
    
    def __init__(self):
        self.challenge_templates = {
            ChallengeType.REACTION_TIME: {
                DifficultyLevel.EASY: Challenge(
                    ChallengeType.REACTION_TIME, DifficultyLevel.EASY,
                    target_value=1.0, tolerance=0.3, max_attempts=3, time_limit=5.0
                ),
                DifficultyLevel.NORMAL: Challenge(
                    ChallengeType.REACTION_TIME, DifficultyLevel.NORMAL,
                    target_value=0.7, tolerance=0.2, max_attempts=3, time_limit=4.0
                ),
                DifficultyLevel.HARD: Challenge(
                    ChallengeType.REACTION_TIME, DifficultyLevel.HARD,
                    target_value=0.5, tolerance=0.15, max_attempts=2, time_limit=3.0
                ),
                DifficultyLevel.EXPERT: Challenge(
                    ChallengeType.REACTION_TIME, DifficultyLevel.EXPERT,
                    target_value=0.3, tolerance=0.1, max_attempts=2, time_limit=2.0
                )
            },
            ChallengeType.SEQUENCE_MEMORY: {
                DifficultyLevel.EASY: Challenge(
                    ChallengeType.SEQUENCE_MEMORY, DifficultyLevel.EASY,
                    target_value=3, tolerance=0, max_attempts=3, time_limit=10.0
                ),
                DifficultyLevel.NORMAL: Challenge(
                    ChallengeType.SEQUENCE_MEMORY, DifficultyLevel.NORMAL,
                    target_value=5, tolerance=0, max_attempts=2, time_limit=15.0
                ),
                DifficultyLevel.HARD: Challenge(
                    ChallengeType.SEQUENCE_MEMORY, DifficultyLevel.HARD,
                    target_value=7, tolerance=0, max_attempts=2, time_limit=20.0
                ),
                DifficultyLevel.EXPERT: Challenge(
                    ChallengeType.SEQUENCE_MEMORY, DifficultyLevel.EXPERT,
                    target_value=10, tolerance=0, max_attempts=1, time_limit=25.0
                )
            },
            ChallengeType.COLOR_MATCH: {
                DifficultyLevel.EASY: Challenge(
                    ChallengeType.COLOR_MATCH, DifficultyLevel.EASY,
                    target_value=4, tolerance=0, max_attempts=3, time_limit=8.0
                ),
                DifficultyLevel.NORMAL: Challenge(
                    ChallengeType.COLOR_MATCH, DifficultyLevel.NORMAL,
                    target_value=6, tolerance=0, max_attempts=2, time_limit=10.0
                ),
                DifficultyLevel.HARD: Challenge(
                    ChallengeType.COLOR_MATCH, DifficultyLevel.HARD,
                    target_value=8, tolerance=0, max_attempts=2, time_limit=12.0
                ),
                DifficultyLevel.EXPERT: Challenge(
                    ChallengeType.COLOR_MATCH, DifficultyLevel.EXPERT,
                    target_value=12, tolerance=0, max_attempts=1, time_limit=15.0
                )
            }
        }
    
    def generate_challenge(self, challenge_type: ChallengeType, 
                          difficulty: DifficultyLevel) -> Challenge:
        """
        チャレンジ生成
        
        Args:
            challenge_type: チャレンジタイプ
            difficulty: 難易度
            
        Returns:
            生成されたチャレンジ
        """
        if challenge_type in self.challenge_templates:
            if difficulty in self.challenge_templates[challenge_type]:
                template = self.challenge_templates[challenge_type][difficulty]
                
                # テンプレートをコピーして少しランダム化
                challenge = Challenge(
                    challenge_type=template.challenge_type,
                    difficulty=template.difficulty,
                    target_value=template.target_value * random.uniform(0.9, 1.1),
                    tolerance=template.tolerance,
                    max_attempts=template.max_attempts,
                    time_limit=template.time_limit,
                    bonus_multiplier=random.uniform(1.0, 1.3)
                )
                
                return challenge
        
        # フォールバック: デフォルトチャレンジ
        return Challenge(
            challenge_type, difficulty,
            target_value=1.0, tolerance=0.2, max_attempts=3, time_limit=5.0
        )
    
    def generate_level_challenges(self, level_config: Dict[str, Any]) -> List[Challenge]:
        """
        レベル用チャレンジセット生成
        
        Args:
            level_config: レベル設定
            
        Returns:
            チャレンジリスト
        """
        challenges = []
        num_challenges = level_config["challenges_per_level"]
        difficulty_weights = level_config["difficulty_weights"]
        
        # 難易度の重み付き選択
        difficulties = list(difficulty_weights.keys())
        weights = list(difficulty_weights.values())
        
        for _ in range(num_challenges):
            # ランダムに難易度とチャレンジタイプを選択
            difficulty_str = random.choices(difficulties, weights=weights)[0]
            difficulty = DifficultyLevel(difficulty_str)
            challenge_type = random.choice(list(ChallengeType))
            
            challenge = self.generate_challenge(challenge_type, difficulty)
            challenges.append(challenge)
        
        return challenges

class GameRules:
    """ゲームルールエンジン"""
    
    def __init__(self):
        self.lives = 3
        self.max_lives = 5
        self.combo_multiplier = 1.0
        self.combo_count = 0
        self.perfect_streak = 0
        
        # ルール設定
        self.rules = {
            "life_loss_conditions": {
                "failed_challenge": True,
                "timeout": True,
                "accuracy_below_threshold": 0.3
            },
            "life_gain_conditions": {
                "perfect_streak_threshold": 5,
                "high_score_bonus": 10000
            },
            "combo_rules": {
                "combo_threshold": 0.8,  # 80%以上の精度でコンボ
                "combo_decay_time": 3.0,  # 3秒でコンボリセット
                "max_combo_multiplier": 5.0
            }
        }
        
        self.last_success_time = 0
    
    def evaluate_result(self, result: GameResult) -> Dict[str, Any]:
        """
        結果評価とルール適用
        
        Args:
            result: ゲーム結果
            
        Returns:
            評価結果辞書
        """
        evaluation = {
            "life_change": 0,
            "combo_change": 0,
            "bonus_multiplier": 1.0,
            "special_effects": []
        }
        
        current_time = time.time()
        
        # ライフ変更の判定
        if not result.success:
            evaluation["life_change"] = -1
            evaluation["special_effects"].append("life_lost")
            self._reset_combo()
        elif result.accuracy < self.rules["life_loss_conditions"]["accuracy_below_threshold"]:
            evaluation["life_change"] = -1
            evaluation["special_effects"].append("accuracy_penalty")
            self._reset_combo()
        else:
            # 成功時の処理
            self._update_combo(result, current_time)
            evaluation["combo_change"] = 1
            
            # パーフェクトストリーク判定
            if result.accuracy >= 0.95:
                self.perfect_streak += 1
                if self.perfect_streak >= self.rules["life_gain_conditions"]["perfect_streak_threshold"]:
                    if self.lives < self.max_lives:
                        evaluation["life_change"] = 1
                        evaluation["special_effects"].append("perfect_streak_bonus")
                    self.perfect_streak = 0
            else:
                self.perfect_streak = 0
        
        # コンボボーナス適用
        evaluation["bonus_multiplier"] = self.combo_multiplier
        
        # ライフ更新
        self.lives = max(0, min(self.max_lives, self.lives + evaluation["life_change"]))
        
        return evaluation
    
    def _update_combo(self, result: GameResult, current_time: float):
        """コンボ更新"""
        combo_threshold = self.rules["combo_rules"]["combo_threshold"]
        combo_decay_time = self.rules["combo_rules"]["combo_decay_time"]
        
        # コンボ継続判定
        if (result.accuracy >= combo_threshold and 
            current_time - self.last_success_time <= combo_decay_time):
            self.combo_count += 1
        else:
            self.combo_count = 1
        
        # コンボ倍率更新
        max_multiplier = self.rules["combo_rules"]["max_combo_multiplier"]
        self.combo_multiplier = min(max_multiplier, 1.0 + (self.combo_count - 1) * 0.2)
        
        self.last_success_time = current_time
    
    def _reset_combo(self):
        """コンボリセット"""
        self.combo_count = 0
        self.combo_multiplier = 1.0
        self.perfect_streak = 0
    
    def is_game_over(self) -> bool:
        """ゲームオーバー判定"""
        return self.lives <= 0
    
    def get_status(self) -> Dict[str, Any]:
        """現在のゲーム状態取得"""
        return {
            "lives": self.lives,
            "max_lives": self.max_lives,
            "combo_count": self.combo_count,
            "combo_multiplier": self.combo_multiplier,
            "perfect_streak": self.perfect_streak
        }

class GameMechanics:
    """ゲームメカニクス統合クラス"""
    
    def __init__(self):
        self.score_calculator = ScoreCalculator()
        self.level_progression = LevelProgression()
        self.challenge_generator = ChallengeGenerator()
        self.game_rules = GameRules()
        
        self.total_score = 0
        self.session_stats = {
            "challenges_completed": 0,
            "challenges_failed": 0,
            "total_reaction_time": 0.0,
            "average_accuracy": 0.0,
            "best_combo": 0,
            "perfect_challenges": 0
        }
    
    def start_new_level(self) -> List[Challenge]:
        """新しいレベル開始"""
        config = self.level_progression.get_current_config()
        challenges = self.challenge_generator.generate_level_challenges(config)
        
        logger.info(f"レベル {self.level_progression.level} 開始: {len(challenges)} チャレンジ")
        return challenges
    
    def process_challenge_result(self, result: GameResult) -> Dict[str, Any]:
        """
        チャレンジ結果処理
        
        Args:
            result: チャレンジ結果
            
        Returns:
            処理結果辞書
        """
        # スコア計算
        base_score, bonus_score = self.score_calculator.calculate_score(
            result.challenge, result.reaction_time, result.accuracy, result.attempts_used
        )
        
        # ルール評価
        rule_evaluation = self.game_rules.evaluate_result(result)
        
        # 最終スコア計算（コンボボーナス適用）
        final_score = int((base_score + bonus_score) * rule_evaluation["bonus_multiplier"])
        result.score = final_score
        result.bonus_earned = bonus_score
        
        # 総スコア更新
        self.total_score += final_score
        
        # 経験値追加とレベルアップチェック
        exp_gained = max(10, final_score // 10)
        level_up = self.level_progression.add_experience(exp_gained)
        
        # 統計更新
        self._update_session_stats(result)
        
        # 結果辞書作成
        process_result = {
            "result": result,
            "rule_evaluation": rule_evaluation,
            "exp_gained": exp_gained,
            "level_up": level_up,
            "total_score": self.total_score,
            "game_over": self.game_rules.is_game_over(),
            "level_info": {
                "current_level": self.level_progression.level,
                "experience": self.level_progression.experience,
                "exp_to_next": self.level_progression.experience_to_next_level
            },
            "game_status": self.game_rules.get_status()
        }
        
        return process_result
    
    def _update_session_stats(self, result: GameResult):
        """セッション統計更新"""
        if result.success:
            self.session_stats["challenges_completed"] += 1
            if result.accuracy >= 0.95:
                self.session_stats["perfect_challenges"] += 1
        else:
            self.session_stats["challenges_failed"] += 1
        
        self.session_stats["total_reaction_time"] += result.reaction_time
        
        # 平均精度更新
        total_challenges = (self.session_stats["challenges_completed"] + 
                          self.session_stats["challenges_failed"])
        if total_challenges > 0:
            current_avg = self.session_stats["average_accuracy"]
            self.session_stats["average_accuracy"] = (
                (current_avg * (total_challenges - 1) + result.accuracy) / total_challenges
            )
        
        # ベストコンボ更新
        current_combo = self.game_rules.combo_count
        if current_combo > self.session_stats["best_combo"]:
            self.session_stats["best_combo"] = current_combo
    
    def get_game_state(self) -> Dict[str, Any]:
        """現在のゲーム状態取得"""
        return {
            "total_score": self.total_score,
            "level": self.level_progression.level,
            "experience": self.level_progression.experience,
            "exp_to_next_level": self.level_progression.experience_to_next_level,
            "lives": self.game_rules.lives,
            "combo_count": self.game_rules.combo_count,
            "combo_multiplier": self.game_rules.combo_multiplier,
            "session_stats": self.session_stats.copy(),
            "game_over": self.game_rules.is_game_over()
        }
    
    def reset_game(self):
        """ゲームリセット"""
        self.level_progression = LevelProgression()
        self.game_rules = GameRules()
        self.total_score = 0
        self.session_stats = {
            "challenges_completed": 0,
            "challenges_failed": 0,
            "total_reaction_time": 0.0,
            "average_accuracy": 0.0,
            "best_combo": 0,
            "perfect_challenges": 0
        }
        
        logger.info("ゲームメカニクスをリセットしました")