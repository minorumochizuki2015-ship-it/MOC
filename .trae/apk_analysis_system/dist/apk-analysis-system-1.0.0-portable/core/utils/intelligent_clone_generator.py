"""
Intelligent Clone Generator - インテリジェントクローン生成器
解析結果から高品質なクローンコードを生成するシステム
"""
import os
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class CloneQuality(Enum):
    """クローン品質レベル"""
    LOW = "low"           # 基本的な構造のみ
    MEDIUM = "medium"     # 主要機能を含む
    HIGH = "high"         # 詳細な実装を含む
    PERFECT = "perfect"   # 完全なクローン

class GameType(Enum):
    """ゲームタイプ"""
    PUZZLE = "puzzle"
    ACTION = "action"
    STRATEGY = "strategy"
    CASUAL = "casual"
    EDUCATIONAL = "educational"
    UNKNOWN = "unknown"

@dataclass
class CloneTemplate:
    """クローンテンプレート"""
    name: str
    game_type: GameType
    quality_level: CloneQuality
    required_features: List[str]
    optional_features: List[str]
    code_templates: Dict[str, str]
    asset_requirements: Dict[str, Any]
    estimated_clone_rate: float

class IntelligentCloneGenerator:
    """インテリジェントクローン生成器"""
    
    def __init__(self, output_dir: str = "generated_clones"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # テンプレートの初期化
        self.templates = self._initialize_templates()
        
        # 品質評価基準
        self.quality_criteria = {
            "unity_detection": 20,
            "il2cpp_analysis": 25,
            "dynamic_analysis": 20,
            "asset_extraction": 15,
            "code_structure": 10,
            "ui_analysis": 10
        }
    
    def _initialize_templates(self) -> Dict[str, CloneTemplate]:
        """テンプレートの初期化"""
        templates = {}
        
        # パズルゲームテンプレート
        templates["puzzle_basic"] = CloneTemplate(
            name="Basic Puzzle Game",
            game_type=GameType.PUZZLE,
            quality_level=CloneQuality.MEDIUM,
            required_features=["grid_system", "piece_matching", "score_system"],
            optional_features=["animations", "sound_effects", "power_ups"],
            code_templates={
                "game_manager": self._get_puzzle_game_manager_template(),
                "grid_system": self._get_grid_system_template(),
                "piece_controller": self._get_piece_controller_template()
            },
            asset_requirements={
                "sprites": ["pieces", "background", "ui_elements"],
                "sounds": ["match", "move", "complete"],
                "fonts": ["score_font", "ui_font"]
            },
            estimated_clone_rate=0.75
        )
        
        # アクションゲームテンプレート
        templates["action_basic"] = CloneTemplate(
            name="Basic Action Game",
            game_type=GameType.ACTION,
            quality_level=CloneQuality.MEDIUM,
            required_features=["player_controller", "enemy_system", "collision_detection"],
            optional_features=["particle_effects", "screen_shake", "combo_system"],
            code_templates={
                "player_controller": self._get_player_controller_template(),
                "enemy_manager": self._get_enemy_manager_template(),
                "collision_system": self._get_collision_system_template()
            },
            asset_requirements={
                "sprites": ["player", "enemies", "projectiles", "environment"],
                "sounds": ["shoot", "hit", "explosion"],
                "animations": ["player_idle", "player_move", "enemy_death"]
            },
            estimated_clone_rate=0.65
        )
        
        # カジュアルゲームテンプレート
        templates["casual_basic"] = CloneTemplate(
            name="Basic Casual Game",
            game_type=GameType.CASUAL,
            quality_level=CloneQuality.HIGH,
            required_features=["simple_controls", "progression_system", "achievements"],
            optional_features=["daily_rewards", "social_features", "monetization"],
            code_templates={
                "game_controller": self._get_casual_game_controller_template(),
                "progression_manager": self._get_progression_manager_template(),
                "achievement_system": self._get_achievement_system_template()
            },
            asset_requirements={
                "sprites": ["characters", "items", "ui", "backgrounds"],
                "sounds": ["success", "failure", "ambient"],
                "effects": ["particles", "transitions"]
            },
            estimated_clone_rate=0.85
        )
        
        return templates
    
    def generate_intelligent_clone(self, analysis_result: Dict[str, Any], target_quality: CloneQuality = CloneQuality.HIGH) -> Dict[str, Any]:
        """インテリジェントクローン生成"""
        logger.info(f"インテリジェントクローン生成開始: 目標品質 {target_quality.value}")
        
        try:
            # 解析結果の評価
            quality_score = self._evaluate_analysis_quality(analysis_result)
            game_type = self._detect_game_type(analysis_result)
            
            logger.info(f"解析品質スコア: {quality_score:.2f}, ゲームタイプ: {game_type.value}")
            
            # 最適なテンプレートの選択
            template = self._select_optimal_template(game_type, target_quality, quality_score)
            
            if not template:
                return {
                    "success": False,
                    "error": "適切なテンプレートが見つかりません",
                    "quality_score": quality_score,
                    "game_type": game_type.value
                }
            
            # クローンコードの生成
            clone_result = self._generate_clone_code(analysis_result, template)
            
            # アセットの生成/抽出
            asset_result = self._generate_assets(analysis_result, template)
            
            # プロジェクト構造の作成
            project_result = self._create_project_structure(clone_result, asset_result, template)
            
            # 品質評価
            final_quality = self._evaluate_clone_quality(project_result, template)
            
            result = {
                "success": True,
                "clone_info": {
                    "template_used": template.name,
                    "game_type": game_type.value,
                    "target_quality": target_quality.value,
                    "achieved_quality": final_quality.value,
                    "estimated_clone_rate": template.estimated_clone_rate,
                    "actual_clone_rate": self._calculate_actual_clone_rate(analysis_result, project_result)
                },
                "generated_files": project_result.get("files", []),
                "project_path": project_result.get("project_path"),
                "quality_metrics": {
                    "analysis_quality": quality_score,
                    "code_completeness": project_result.get("code_completeness", 0),
                    "asset_completeness": project_result.get("asset_completeness", 0),
                    "functionality_score": project_result.get("functionality_score", 0)
                }
            }
            
            logger.info(f"クローン生成完了: 実際のクローン率 {result['clone_info']['actual_clone_rate']:.2f}")
            return result
            
        except Exception as e:
            logger.error(f"インテリジェントクローン生成エラー: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_quality": self._evaluate_analysis_quality(analysis_result) if analysis_result else 0
            }
    
    def _evaluate_analysis_quality(self, analysis_result: Dict[str, Any]) -> float:
        """解析結果の品質評価"""
        score = 0.0
        
        # Unity検出
        if analysis_result.get("unity_analysis", {}).get("unity_detected"):
            score += self.quality_criteria["unity_detection"]
        
        # IL2CPP解析
        il2cpp_analysis = analysis_result.get("il2cpp_analysis", {})
        if il2cpp_analysis.get("dump_result"):
            score += self.quality_criteria["il2cpp_analysis"]
        
        # 動的解析
        dynamic_analysis = analysis_result.get("dynamic_analysis", {})
        if dynamic_analysis and not dynamic_analysis.get("error"):
            score += self.quality_criteria["dynamic_analysis"]
        
        # アセット抽出
        if analysis_result.get("assets_extracted"):
            score += self.quality_criteria["asset_extraction"]
        
        # コード構造解析
        if analysis_result.get("code_structure"):
            score += self.quality_criteria["code_structure"]
        
        # UI解析
        if analysis_result.get("ui_analysis"):
            score += self.quality_criteria["ui_analysis"]
        
        return min(score, 100.0)
    
    def _detect_game_type(self, analysis_result: Dict[str, Any]) -> GameType:
        """ゲームタイプの検出"""
        # IL2CPP解析結果からクラス名を確認
        il2cpp_analysis = analysis_result.get("il2cpp_analysis", {})
        dump_result = il2cpp_analysis.get("dump_result", {})
        
        if dump_result:
            class_names = []
            for file_info in dump_result.get("files", []):
                if file_info.get("type") == "cs":
                    class_names.extend(self._extract_class_names(file_info.get("content", "")))
            
            # クラス名からゲームタイプを推測
            puzzle_keywords = ["grid", "tile", "match", "puzzle", "block", "piece"]
            action_keywords = ["player", "enemy", "weapon", "bullet", "combat", "shoot"]
            strategy_keywords = ["unit", "building", "resource", "strategy", "command"]
            casual_keywords = ["tap", "swipe", "casual", "simple", "easy"]
            
            keyword_counts = {
                GameType.PUZZLE: sum(1 for name in class_names if any(kw in name.lower() for kw in puzzle_keywords)),
                GameType.ACTION: sum(1 for name in class_names if any(kw in name.lower() for kw in action_keywords)),
                GameType.STRATEGY: sum(1 for name in class_names if any(kw in name.lower() for kw in strategy_keywords)),
                GameType.CASUAL: sum(1 for name in class_names if any(kw in name.lower() for kw in casual_keywords))
            }
            
            if keyword_counts:
                return max(keyword_counts, key=keyword_counts.get)
        
        # デフォルトはカジュアル
        return GameType.CASUAL
    
    def _extract_class_names(self, cs_content: str) -> List[str]:
        """C#コードからクラス名を抽出"""
        class_pattern = r'class\s+(\w+)'
        return re.findall(class_pattern, cs_content)
    
    def _select_optimal_template(self, game_type: GameType, target_quality: CloneQuality, quality_score: float) -> Optional[CloneTemplate]:
        """最適なテンプレートの選択"""
        # ゲームタイプに対応するテンプレートを検索
        matching_templates = [
            template for template in self.templates.values()
            if template.game_type == game_type
        ]
        
        if not matching_templates:
            # 対応するテンプレートがない場合はカジュアルゲームテンプレートを使用
            matching_templates = [
                template for template in self.templates.values()
                if template.game_type == GameType.CASUAL
            ]
        
        if not matching_templates:
            return None
        
        # 品質レベルと解析品質に基づいて最適なテンプレートを選択
        best_template = None
        best_score = -1
        
        for template in matching_templates:
            # テンプレートの適合度を計算
            quality_match = 1.0 if template.quality_level == target_quality else 0.5
            analysis_match = min(quality_score / 100.0, 1.0)
            
            template_score = quality_match * 0.6 + analysis_match * 0.4
            
            if template_score > best_score:
                best_score = template_score
                best_template = template
        
        return best_template
    
    def _generate_clone_code(self, analysis_result: Dict[str, Any], template: CloneTemplate) -> Dict[str, Any]:
        """クローンコードの生成"""
        generated_code = {}
        
        # IL2CPP解析結果からコード情報を抽出
        il2cpp_analysis = analysis_result.get("il2cpp_analysis", {})
        dump_result = il2cpp_analysis.get("dump_result", {})
        
        # テンプレートベースのコード生成
        for code_type, template_code in template.code_templates.items():
            # 解析結果に基づいてテンプレートをカスタマイズ
            customized_code = self._customize_template_code(
                template_code, 
                analysis_result, 
                code_type
            )
            generated_code[code_type] = customized_code
        
        # IL2CPP解析結果から追加のコードを生成
        if dump_result:
            additional_code = self._generate_from_il2cpp(dump_result, template)
            generated_code.update(additional_code)
        
        return {
            "success": True,
            "generated_code": generated_code,
            "code_completeness": self._calculate_code_completeness(generated_code, template)
        }
    
    def _customize_template_code(self, template_code: str, analysis_result: Dict[str, Any], code_type: str) -> str:
        """テンプレートコードのカスタマイズ"""
        customized = template_code
        
        # 動的解析結果からパラメータを抽出
        dynamic_analysis = analysis_result.get("dynamic_analysis", {})
        if dynamic_analysis and not dynamic_analysis.get("error"):
            # ゲーム設定値の抽出と適用
            game_settings = self._extract_game_settings(dynamic_analysis)
            for key, value in game_settings.items():
                placeholder = f"{{{{ {key} }}}}"
                if placeholder in customized:
                    customized = customized.replace(placeholder, str(value))
        
        # Unity解析結果からコンポーネント情報を適用
        unity_analysis = analysis_result.get("unity_analysis", {})
        if unity_analysis.get("unity_detected"):
            # Unityコンポーネントの適用
            customized = self._apply_unity_components(customized, unity_analysis)
        
        return customized
    
    def _extract_game_settings(self, dynamic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """動的解析結果からゲーム設定を抽出"""
        settings = {}
        
        # Fridaフック結果から設定値を抽出
        frida_output = dynamic_analysis.get("frida_output", "")
        if frida_output:
            # 数値パラメータの抽出
            score_pattern = r'score[_\s]*[:=]\s*(\d+)'
            speed_pattern = r'speed[_\s]*[:=]\s*(\d+\.?\d*)'
            level_pattern = r'level[_\s]*[:=]\s*(\d+)'
            
            score_match = re.search(score_pattern, frida_output, re.IGNORECASE)
            speed_match = re.search(speed_pattern, frida_output, re.IGNORECASE)
            level_match = re.search(level_pattern, frida_output, re.IGNORECASE)
            
            if score_match:
                settings["initial_score"] = int(score_match.group(1))
            if speed_match:
                settings["game_speed"] = float(speed_match.group(1))
            if level_match:
                settings["max_level"] = int(level_match.group(1))
        
        # デフォルト値の設定
        settings.setdefault("initial_score", 0)
        settings.setdefault("game_speed", 1.0)
        settings.setdefault("max_level", 10)
        
        return settings
    
    def _apply_unity_components(self, code: str, unity_analysis: Dict[str, Any]) -> str:
        """Unityコンポーネント情報の適用"""
        # Unity特有のコンポーネントやメソッドの適用
        if "{{ unity_components }}" in code:
            components = unity_analysis.get("components", [])
            component_code = "\n".join([f"    public {comp} {comp.lower()};" for comp in components])
            code = code.replace("{{ unity_components }}", component_code)
        
        return code
    
    def _generate_from_il2cpp(self, dump_result: Dict[str, Any], template: CloneTemplate) -> Dict[str, str]:
        """IL2CPP解析結果からコードを生成"""
        generated = {}
        
        # C#ファイルから重要なクラスを抽出
        for file_info in dump_result.get("files", []):
            if file_info.get("type") == "cs":
                content = file_info.get("content", "")
                filename = file_info.get("name", "")
                
                # ゲームロジックに関連するクラスを特定
                if self._is_game_logic_class(content, filename):
                    # クラスを簡略化してテンプレートに適用
                    simplified_class = self._simplify_class_code(content)
                    generated[f"extracted_{filename}"] = simplified_class
        
        return generated
    
    def _is_game_logic_class(self, content: str, filename: str) -> bool:
        """ゲームロジックに関連するクラスかどうかを判定"""
        game_keywords = [
            "game", "player", "enemy", "score", "level", "manager",
            "controller", "system", "logic", "state", "input"
        ]
        
        filename_lower = filename.lower()
        content_lower = content.lower()
        
        return any(keyword in filename_lower or keyword in content_lower for keyword in game_keywords)
    
    def _simplify_class_code(self, content: str) -> str:
        """クラスコードの簡略化"""
        # 基本的な構造のみを保持し、詳細な実装は削除
        lines = content.split('\n')
        simplified_lines = []
        
        in_method = False
        brace_count = 0
        
        for line in lines:
            stripped = line.strip()
            
            # クラス宣言、フィールド、メソッドシグネチャは保持
            if (stripped.startswith('public class') or 
                stripped.startswith('private class') or
                stripped.startswith('public') and ('(' in stripped or ';' in stripped)):
                
                simplified_lines.append(line)
                
                if '{' in stripped:
                    in_method = True
                    brace_count = stripped.count('{') - stripped.count('}')
                elif ';' in stripped:
                    in_method = False
            
            elif in_method:
                brace_count += stripped.count('{') - stripped.count('}')
                if brace_count <= 0:
                    in_method = False
                    simplified_lines.append("        // Implementation simplified")
                    simplified_lines.append("    }")
            
            elif stripped in ['{', '}']:
                simplified_lines.append(line)
        
        return '\n'.join(simplified_lines)
    
    def _generate_assets(self, analysis_result: Dict[str, Any], template: CloneTemplate) -> Dict[str, Any]:
        """アセットの生成/抽出"""
        asset_result = {
            "extracted_assets": [],
            "generated_assets": [],
            "asset_completeness": 0.0
        }
        
        # 抽出されたアセットの確認
        if analysis_result.get("assets_extracted"):
            asset_result["extracted_assets"] = analysis_result["assets_extracted"]
        
        # 不足しているアセットの生成
        required_assets = template.asset_requirements
        missing_assets = self._identify_missing_assets(asset_result["extracted_assets"], required_assets)
        
        for asset_type, assets in missing_assets.items():
            for asset_name in assets:
                generated_asset = self._generate_placeholder_asset(asset_type, asset_name)
                if generated_asset:
                    asset_result["generated_assets"].append(generated_asset)
        
        # アセット完成度の計算
        total_required = sum(len(assets) for assets in required_assets.values())
        total_available = len(asset_result["extracted_assets"]) + len(asset_result["generated_assets"])
        asset_result["asset_completeness"] = min(total_available / total_required, 1.0) if total_required > 0 else 1.0
        
        return asset_result
    
    def _identify_missing_assets(self, extracted_assets: List[str], required_assets: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """不足しているアセットの特定"""
        missing = {}
        
        for asset_type, required_list in required_assets.items():
            missing_in_type = []
            for required_asset in required_list:
                # 抽出されたアセットに類似のものがあるかチェック
                if not any(required_asset.lower() in extracted.lower() for extracted in extracted_assets):
                    missing_in_type.append(required_asset)
            
            if missing_in_type:
                missing[asset_type] = missing_in_type
        
        return missing
    
    def _generate_placeholder_asset(self, asset_type: str, asset_name: str) -> Optional[Dict[str, str]]:
        """プレースホルダーアセットの生成"""
        if asset_type == "sprites":
            return {
                "type": "sprite",
                "name": asset_name,
                "path": f"assets/sprites/{asset_name}.png",
                "content": "placeholder_sprite_data"
            }
        elif asset_type == "sounds":
            return {
                "type": "sound",
                "name": asset_name,
                "path": f"assets/sounds/{asset_name}.wav",
                "content": "placeholder_sound_data"
            }
        elif asset_type == "fonts":
            return {
                "type": "font",
                "name": asset_name,
                "path": f"assets/fonts/{asset_name}.ttf",
                "content": "placeholder_font_data"
            }
        
        return None
    
    def _create_project_structure(self, clone_result: Dict[str, Any], asset_result: Dict[str, Any], template: CloneTemplate) -> Dict[str, Any]:
        """プロジェクト構造の作成"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = f"{template.name.lower().replace(' ', '_')}_{timestamp}"
        project_path = self.output_dir / project_name
        
        project_path.mkdir(parents=True, exist_ok=True)
        
        # ディレクトリ構造の作成
        directories = [
            "src/scripts",
            "src/managers",
            "src/controllers",
            "assets/sprites",
            "assets/sounds",
            "assets/fonts",
            "scenes",
            "prefabs"
        ]
        
        for directory in directories:
            (project_path / directory).mkdir(parents=True, exist_ok=True)
        
        # コードファイルの作成
        generated_files = []
        for code_type, code_content in clone_result.get("generated_code", {}).items():
            file_path = project_path / "src" / "scripts" / f"{code_type}.cs"
            file_path.write_text(code_content, encoding='utf-8')
            generated_files.append(str(file_path))
        
        # アセットファイルの作成（プレースホルダー）
        for asset in asset_result.get("generated_assets", []):
            asset_path = project_path / asset["path"]
            asset_path.parent.mkdir(parents=True, exist_ok=True)
            asset_path.write_text(f"# Placeholder for {asset['name']}", encoding='utf-8')
            generated_files.append(str(asset_path))
        
        # プロジェクト設定ファイルの作成
        project_info = {
            "name": project_name,
            "template": template.name,
            "game_type": template.game_type.value,
            "quality_level": template.quality_level.value,
            "generated_at": datetime.now().isoformat(),
            "features": template.required_features + template.optional_features
        }
        
        project_info_path = project_path / "project_info.json"
        project_info_path.write_text(json.dumps(project_info, indent=2), encoding='utf-8')
        generated_files.append(str(project_info_path))
        
        return {
            "success": True,
            "project_path": str(project_path),
            "files": generated_files,
            "code_completeness": clone_result.get("code_completeness", 0),
            "asset_completeness": asset_result.get("asset_completeness", 0),
            "functionality_score": self._calculate_functionality_score(clone_result, asset_result, template)
        }
    
    def _calculate_code_completeness(self, generated_code: Dict[str, str], template: CloneTemplate) -> float:
        """コード完成度の計算"""
        required_code_types = len(template.code_templates)
        generated_code_types = len(generated_code)
        
        return min(generated_code_types / required_code_types, 1.0) if required_code_types > 0 else 1.0
    
    def _calculate_functionality_score(self, clone_result: Dict[str, Any], asset_result: Dict[str, Any], template: CloneTemplate) -> float:
        """機能性スコアの計算"""
        code_score = clone_result.get("code_completeness", 0) * 0.6
        asset_score = asset_result.get("asset_completeness", 0) * 0.4
        
        return code_score + asset_score
    
    def _evaluate_clone_quality(self, project_result: Dict[str, Any], template: CloneTemplate) -> CloneQuality:
        """クローン品質の評価"""
        functionality_score = project_result.get("functionality_score", 0)
        
        if functionality_score >= 0.9:
            return CloneQuality.PERFECT
        elif functionality_score >= 0.75:
            return CloneQuality.HIGH
        elif functionality_score >= 0.5:
            return CloneQuality.MEDIUM
        else:
            return CloneQuality.LOW
    
    def _calculate_actual_clone_rate(self, analysis_result: Dict[str, Any], project_result: Dict[str, Any]) -> float:
        """実際のクローン率の計算"""
        # 解析品質とプロジェクト完成度に基づいてクローン率を計算
        analysis_quality = self._evaluate_analysis_quality(analysis_result) / 100.0
        functionality_score = project_result.get("functionality_score", 0)
        
        # 重み付き平均でクローン率を計算
        clone_rate = (analysis_quality * 0.4 + functionality_score * 0.6)
        
        return min(clone_rate, 1.0)
    
    # テンプレートコード生成メソッド
    def _get_puzzle_game_manager_template(self) -> str:
        return '''using UnityEngine;
using System.Collections;

public class GameManager : MonoBehaviour
{
    [Header("Game Settings")]
    public int initialScore = {{ initial_score }};
    public float gameSpeed = {{ game_speed }};
    public int maxLevel = {{ max_level }};
    
    [Header("Components")]
    public GridSystem gridSystem;
    public ScoreManager scoreManager;
    public UIManager uiManager;
    
    {{ unity_components }}
    
    private GameState currentState;
    private int currentLevel = 1;
    
    void Start()
    {
        InitializeGame();
    }
    
    void InitializeGame()
    {
        currentState = GameState.Playing;
        scoreManager.SetScore(initialScore);
        gridSystem.InitializeGrid();
        // Implementation simplified
    }
    
    public void OnPieceMatched(int matchCount)
    {
        // Implementation simplified
    }
    
    public void CheckGameOver()
    {
        // Implementation simplified
    }
}

public enum GameState
{
    Menu,
    Playing,
    Paused,
    GameOver
}'''
    
    def _get_grid_system_template(self) -> str:
        return '''using UnityEngine;
using System.Collections.Generic;

public class GridSystem : MonoBehaviour
{
    [Header("Grid Settings")]
    public int gridWidth = 8;
    public int gridHeight = 8;
    public GameObject piecePrefab;
    
    private GameObject[,] grid;
    private List<Vector2Int> matchedPieces;
    
    public void InitializeGrid()
    {
        grid = new GameObject[gridWidth, gridHeight];
        matchedPieces = new List<Vector2Int>();
        CreateGrid();
    }
    
    void CreateGrid()
    {
        // Implementation simplified
    }
    
    public bool CheckForMatches()
    {
        // Implementation simplified
        return false;
    }
    
    public void RemoveMatches()
    {
        // Implementation simplified
    }
}'''
    
    def _get_piece_controller_template(self) -> str:
        return '''using UnityEngine;

public class PieceController : MonoBehaviour
{
    [Header("Piece Settings")]
    public PieceType pieceType;
    public Sprite pieceSprite;
    
    private Vector2Int gridPosition;
    private bool isSelected = false;
    
    void Start()
    {
        // Implementation simplified
    }
    
    void OnMouseDown()
    {
        // Implementation simplified
    }
    
    public void SetGridPosition(Vector2Int position)
    {
        gridPosition = position;
    }
    
    public void SetPieceType(PieceType type)
    {
        pieceType = type;
        // Implementation simplified
    }
}

public enum PieceType
{
    Red,
    Blue,
    Green,
    Yellow,
    Purple
}'''
    
    def _get_player_controller_template(self) -> str:
        return '''using UnityEngine;

public class PlayerController : MonoBehaviour
{
    [Header("Movement Settings")]
    public float moveSpeed = {{ game_speed }};
    public float jumpForce = 10f;
    
    [Header("Components")]
    public Rigidbody2D rb;
    public Collider2D col;
    
    {{ unity_components }}
    
    private bool isGrounded = false;
    private float horizontalInput;
    
    void Update()
    {
        HandleInput();
        Move();
    }
    
    void HandleInput()
    {
        horizontalInput = Input.GetAxis("Horizontal");
        
        if (Input.GetKeyDown(KeyCode.Space) && isGrounded)
        {
            Jump();
        }
    }
    
    void Move()
    {
        // Implementation simplified
    }
    
    void Jump()
    {
        // Implementation simplified
    }
}'''
    
    def _get_enemy_manager_template(self) -> str:
        return '''using UnityEngine;
using System.Collections.Generic;

public class EnemyManager : MonoBehaviour
{
    [Header("Enemy Settings")]
    public GameObject enemyPrefab;
    public float spawnRate = 2f;
    public int maxEnemies = 10;
    
    private List<GameObject> activeEnemies;
    private float lastSpawnTime;
    
    void Start()
    {
        activeEnemies = new List<GameObject>();
    }
    
    void Update()
    {
        if (Time.time - lastSpawnTime > spawnRate && activeEnemies.Count < maxEnemies)
        {
            SpawnEnemy();
        }
    }
    
    void SpawnEnemy()
    {
        // Implementation simplified
    }
    
    public void RemoveEnemy(GameObject enemy)
    {
        // Implementation simplified
    }
}'''
    
    def _get_collision_system_template(self) -> str:
        return '''using UnityEngine;

public class CollisionSystem : MonoBehaviour
{
    void OnTriggerEnter2D(Collider2D other)
    {
        HandleCollision(other);
    }
    
    void HandleCollision(Collider2D other)
    {
        // Implementation simplified
    }
    
    public static bool CheckCollision(GameObject obj1, GameObject obj2)
    {
        // Implementation simplified
        return false;
    }
}'''
    
    def _get_casual_game_controller_template(self) -> str:
        return '''using UnityEngine;

public class CasualGameController : MonoBehaviour
{
    [Header("Game Settings")]
    public int targetScore = 1000;
    public float timeLimit = 60f;
    
    {{ unity_components }}
    
    private int currentScore = {{ initial_score }};
    private float remainingTime;
    private bool gameActive = true;
    
    void Start()
    {
        remainingTime = timeLimit;
        StartGame();
    }
    
    void Update()
    {
        if (gameActive)
        {
            UpdateTimer();
            CheckWinCondition();
        }
    }
    
    void StartGame()
    {
        // Implementation simplified
    }
    
    void UpdateTimer()
    {
        // Implementation simplified
    }
    
    void CheckWinCondition()
    {
        // Implementation simplified
    }
    
    public void AddScore(int points)
    {
        // Implementation simplified
    }
}'''
    
    def _get_progression_manager_template(self) -> str:
        return '''using UnityEngine;

public class ProgressionManager : MonoBehaviour
{
    [Header("Progression Settings")]
    public int[] levelThresholds;
    public float[] difficultyMultipliers;
    
    private int currentLevel = 1;
    private int totalExperience = 0;
    
    public void AddExperience(int exp)
    {
        // Implementation simplified
    }
    
    public void CheckLevelUp()
    {
        // Implementation simplified
    }
    
    public float GetCurrentDifficulty()
    {
        // Implementation simplified
        return 1.0f;
    }
}'''
    
    def _get_achievement_system_template(self) -> str:
        return '''using UnityEngine;
using System.Collections.Generic;

public class AchievementSystem : MonoBehaviour
{
    [System.Serializable]
    public class Achievement
    {
        public string id;
        public string title;
        public string description;
        public bool unlocked;
    }
    
    public List<Achievement> achievements;
    
    void Start()
    {
        LoadAchievements();
    }
    
    public void UnlockAchievement(string achievementId)
    {
        // Implementation simplified
    }
    
    void LoadAchievements()
    {
        // Implementation simplified
    }
    
    void SaveAchievements()
    {
        // Implementation simplified
    }
}'''