#!/usr/bin/env python3
"""
Unity プロジェクトの実地テスト（Unity エディタ不要版）
生成されたクローンプロジェクトの品質と構造を検証する
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any
import subprocess
import sys

class UnityProjectTester:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.test_results = {
            "project_structure": {},
            "script_validation": {},
            "asset_validation": {},
            "overall_score": 0.0,
            "recommendations": []
        }
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """包括的なプロジェクトテストを実行"""
        print("🎮 Unity プロジェクト実地テスト開始")
        print(f"📁 プロジェクトパス: {self.project_path}")
        
        # 1. プロジェクト構造の検証
        self._test_project_structure()
        
        # 2. スクリプトの構文検証
        self._test_script_syntax()
        
        # 3. アセットの検証
        self._test_assets()
        
        # 4. Unity設定の検証
        self._test_unity_settings()
        
        # 5. 総合スコアの計算
        self._calculate_overall_score()
        
        # 6. 推奨事項の生成
        self._generate_recommendations()
        
        return self.test_results
    
    def _test_project_structure(self):
        """プロジェクト構造の検証"""
        print("\n📂 プロジェクト構造の検証...")
        
        required_dirs = [
            "Assets",
            "Assets/Scripts",
            "Assets/Scenes", 
            "Assets/Prefabs",
            "ProjectSettings"
        ]
        
        structure_score = 0
        total_dirs = len(required_dirs)
        
        for dir_path in required_dirs:
            full_path = self.project_path / dir_path
            exists = full_path.exists()
            self.test_results["project_structure"][dir_path] = {
                "exists": exists,
                "path": str(full_path)
            }
            if exists:
                structure_score += 1
                print(f"  ✅ {dir_path}")
            else:
                print(f"  ❌ {dir_path}")
        
        self.test_results["project_structure"]["score"] = structure_score / total_dirs
        print(f"📊 構造スコア: {structure_score}/{total_dirs} ({structure_score/total_dirs*100:.1f}%)")
    
    def _test_script_syntax(self):
        """C#スクリプトの構文検証"""
        print("\n🔍 スクリプト構文の検証...")
        
        scripts_dir = self.project_path / "Assets" / "Scripts"
        if not scripts_dir.exists():
            self.test_results["script_validation"]["error"] = "Scripts directory not found"
            return
        
        cs_files = list(scripts_dir.rglob("*.cs"))
        valid_scripts = 0
        script_details = {}
        
        for cs_file in cs_files:
            try:
                with open(cs_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 基本的な構文チェック
                issues = self._check_csharp_syntax(content)
                script_details[cs_file.name] = {
                    "path": str(cs_file),
                    "size": len(content),
                    "lines": len(content.split('\n')),
                    "issues": issues,
                    "valid": len(issues) == 0
                }
                
                if len(issues) == 0:
                    valid_scripts += 1
                    print(f"  ✅ {cs_file.name}")
                else:
                    print(f"  ⚠️  {cs_file.name} ({len(issues)} issues)")
                    for issue in issues:
                        print(f"     - {issue}")
                        
            except Exception as e:
                script_details[cs_file.name] = {
                    "path": str(cs_file),
                    "error": str(e),
                    "valid": False
                }
                print(f"  ❌ {cs_file.name} (読み込みエラー)")
        
        self.test_results["script_validation"] = {
            "total_scripts": len(cs_files),
            "valid_scripts": valid_scripts,
            "score": valid_scripts / len(cs_files) if cs_files else 0,
            "details": script_details
        }
        
        print(f"📊 スクリプトスコア: {valid_scripts}/{len(cs_files)} ({valid_scripts/len(cs_files)*100:.1f}%)")
    
    def _check_csharp_syntax(self, content: str) -> List[str]:
        """C#コードの基本的な構文チェック"""
        issues = []
        
        # 基本的なチェック
        if not re.search(r'using\s+UnityEngine;', content):
            issues.append("UnityEngine using statement missing")
        
        # クラス定義のチェック
        if not re.search(r'public\s+class\s+\w+', content):
            issues.append("Public class definition not found")
        
        # MonoBehaviour継承のチェック
        if re.search(r'public\s+class\s+\w+', content) and not re.search(r':\s*MonoBehaviour', content):
            issues.append("Class should inherit from MonoBehaviour")
        
        # 括弧の対応チェック
        open_braces = content.count('{')
        close_braces = content.count('}')
        if open_braces != close_braces:
            issues.append(f"Mismatched braces: {open_braces} open, {close_braces} close")
        
        return issues
    
    def _test_assets(self):
        """アセットの検証"""
        print("\n🎨 アセットの検証...")
        
        asset_dirs = ["Materials", "Textures", "Audio", "Animations", "Prefabs"]
        asset_score = 0
        asset_details = {}
        
        for asset_dir in asset_dirs:
            dir_path = self.project_path / "Assets" / asset_dir
            exists = dir_path.exists()
            file_count = 0
            
            if exists:
                # .meta ファイルを除外してカウント
                files = [f for f in dir_path.rglob("*") if f.is_file() and not f.name.endswith('.meta')]
                file_count = len(files)
                asset_score += 1
                print(f"  ✅ {asset_dir} ({file_count} files)")
            else:
                print(f"  ❌ {asset_dir}")
            
            asset_details[asset_dir] = {
                "exists": exists,
                "file_count": file_count
            }
        
        self.test_results["asset_validation"] = {
            "score": asset_score / len(asset_dirs),
            "details": asset_details
        }
        
        print(f"📊 アセットスコア: {asset_score}/{len(asset_dirs)} ({asset_score/len(asset_dirs)*100:.1f}%)")
    
    def _test_unity_settings(self):
        """Unity設定の検証"""
        print("\n⚙️  Unity設定の検証...")
        
        settings_files = [
            "ProjectSettings/ProjectSettings.asset",
            "ProjectSettings/ProjectVersion.txt",
            "Packages/manifest.json"
        ]
        
        settings_score = 0
        settings_details = {}
        
        for settings_file in settings_files:
            file_path = self.project_path / settings_file
            exists = file_path.exists()
            
            if exists:
                settings_score += 1
                print(f"  ✅ {settings_file}")
                
                # ProjectVersion.txtの内容チェック
                if settings_file.endswith("ProjectVersion.txt"):
                    try:
                        with open(file_path, 'r') as f:
                            version_content = f.read()
                        if "2022.3.0f1" in version_content:
                            print(f"     Unity Version: 2022.3.0f1 ✅")
                        else:
                            print(f"     Unity Version: {version_content.strip()}")
                    except:
                        pass
            else:
                print(f"  ❌ {settings_file}")
            
            settings_details[settings_file] = {"exists": exists}
        
        self.test_results["unity_settings"] = {
            "score": settings_score / len(settings_files),
            "details": settings_details
        }
        
        print(f"📊 設定スコア: {settings_score}/{len(settings_files)} ({settings_score/len(settings_files)*100:.1f}%)")
    
    def _calculate_overall_score(self):
        """総合スコアの計算"""
        weights = {
            "project_structure": 0.3,
            "script_validation": 0.4,
            "asset_validation": 0.2,
            "unity_settings": 0.1
        }
        
        total_score = 0
        for category, weight in weights.items():
            if category in self.test_results:
                score = self.test_results[category].get("score", 0)
                total_score += score * weight
        
        self.test_results["overall_score"] = total_score
    
    def _generate_recommendations(self):
        """改善推奨事項の生成"""
        recommendations = []
        
        # プロジェクト構造の推奨事項
        if self.test_results["project_structure"]["score"] < 1.0:
            recommendations.append("プロジェクト構造を完成させる - 不足しているディレクトリを作成")
        
        # スクリプトの推奨事項
        script_score = self.test_results.get("script_validation", {}).get("score", 0)
        if script_score < 1.0:
            recommendations.append("スクリプトの構文エラーを修正する")
        
        # アセットの推奨事項
        asset_score = self.test_results.get("asset_validation", {}).get("score", 0)
        if asset_score < 0.5:
            recommendations.append("アセットディレクトリにコンテンツを追加する")
        
        # 総合スコアに基づく推奨事項
        overall_score = self.test_results["overall_score"]
        if overall_score >= 0.8:
            recommendations.append("✅ プロジェクトは良好な状態です - Unityエディタでの実行テストを推奨")
        elif overall_score >= 0.6:
            recommendations.append("⚠️ いくつかの改善が必要です - 主要な問題を修正後にテスト実行")
        else:
            recommendations.append("❌ 大幅な改善が必要です - 基本構造から見直しが必要")
        
        self.test_results["recommendations"] = recommendations

def main():
    """メイン実行関数"""
    project_path = "data/clone_generation/UnityProject"
    
    if not os.path.exists(project_path):
        print(f"❌ プロジェクトが見つかりません: {project_path}")
        return
    
    tester = UnityProjectTester(project_path)
    results = tester.run_comprehensive_test()
    
    # 結果の表示
    print("\n" + "="*60)
    print("🎯 テスト結果サマリー")
    print("="*60)
    print(f"📊 総合スコア: {results['overall_score']:.1%}")
    print(f"📂 プロジェクト構造: {results['project_structure']['score']:.1%}")
    print(f"🔍 スクリプト品質: {results.get('script_validation', {}).get('score', 0):.1%}")
    print(f"🎨 アセット完成度: {results.get('asset_validation', {}).get('score', 0):.1%}")
    print(f"⚙️ Unity設定: {results.get('unity_settings', {}).get('score', 0):.1%}")
    
    print("\n💡 推奨事項:")
    for i, rec in enumerate(results["recommendations"], 1):
        print(f"  {i}. {rec}")
    
    # 結果をJSONファイルに保存
    output_path = "data/test_outputs/unity_project_test_results.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 詳細結果を保存: {output_path}")
    
    return results

if __name__ == "__main__":
    main()