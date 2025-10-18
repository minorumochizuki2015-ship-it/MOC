#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MOC依存関係分析スクリプト
既存MOCシステムの依存関係を分析し、移行計画を支援する
"""

import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Set


@dataclass
class DependencyInfo:
    """依存関係情報"""

    name: str
    version: str
    source: str  # requirements.txt, pyproject.toml, import
    usage_files: List[str]
    is_critical: bool = False


@dataclass
class FileAnalysis:
    """ファイル分析結果"""

    path: str
    imports: List[str]
    functions: List[str]
    classes: List[str]
    lines_of_code: int
    complexity_score: int


class MOCDependencyAnalyzer:
    """MOC依存関係分析器"""

    def __init__(self, moc_root: str = "C:\\Users\\User\\Trae\\MOC"):
        self.moc_root = Path(moc_root)
        self.orch_next_root = Path("C:\\Users\\User\\Trae\\ORCH-Next")
        self.dependencies: Dict[str, DependencyInfo] = {}
        self.file_analyses: List[FileAnalysis] = []
        self.critical_files = [
            "orch_dashboard.py",
            "Task-Dispatcher.ps1",
            "main.py",
            "integrated_config.json",
        ]

    def analyze_requirements(self) -> Dict[str, str]:
        """requirements.txtを分析"""
        req_file = self.moc_root / "requirements.txt"
        dependencies = {}

        if req_file.exists():
            with open(req_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # パッケージ名とバージョンを抽出
                        match = re.match(r"^([a-zA-Z0-9_-]+)([>=<~!]+.*)?", line)
                        if match:
                            name = match.group(1)
                            version = match.group(2) or ""
                            dependencies[name] = version

                            self.dependencies[name] = DependencyInfo(
                                name=name,
                                version=version,
                                source="requirements.txt",
                                usage_files=[],
                                is_critical=name in ["flask", "fastapi", "openai", "requests"],
                            )

        return dependencies

    def analyze_python_imports(self) -> Dict[str, Set[str]]:
        """Pythonファイルのimportを分析"""
        imports_by_file = {}

        for py_file in self.moc_root.rglob("*.py"):
            if "venv" in str(py_file) or "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # ASTを使用してimportを抽出
                tree = ast.parse(content)
                imports = set()

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.add(alias.name.split(".")[0])
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.add(node.module.split(".")[0])

                imports_by_file[str(py_file.relative_to(self.moc_root))] = imports

                # 依存関係情報を更新
                for imp in imports:
                    if imp in self.dependencies:
                        self.dependencies[imp].usage_files.append(
                            str(py_file.relative_to(self.moc_root))
                        )

            except Exception as e:
                print(f"Error analyzing {py_file}: {e}")

        return imports_by_file

    def analyze_file_complexity(self, file_path: Path) -> FileAnalysis:
        """ファイルの複雑度を分析"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            lines = content.split("\\n")
            loc = len([line for line in lines if line.strip() and not line.strip().startswith("#")])

            if file_path.suffix == ".py":
                tree = ast.parse(content)

                imports = []
                functions = []
                classes = []

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.append(node.module)
                    elif isinstance(node, ast.FunctionDef):
                        functions.append(node.name)
                    elif isinstance(node, ast.ClassDef):
                        classes.append(node.name)

                # 複雑度スコア（簡易版）
                complexity = len(functions) + len(classes) * 2 + loc // 100

                return FileAnalysis(
                    path=str(file_path.relative_to(self.moc_root)),
                    imports=imports,
                    functions=functions,
                    classes=classes,
                    lines_of_code=loc,
                    complexity_score=complexity,
                )
            else:
                # PowerShellファイルなど
                return FileAnalysis(
                    path=str(file_path.relative_to(self.moc_root)),
                    imports=[],
                    functions=[],
                    classes=[],
                    lines_of_code=loc,
                    complexity_score=loc // 50,  # PowerShellの複雑度は行数ベース
                )

        except Exception as e:
            print(f"Error analyzing complexity for {file_path}: {e}")
            return FileAnalysis(
                path=str(file_path.relative_to(self.moc_root)),
                imports=[],
                functions=[],
                classes=[],
                lines_of_code=0,
                complexity_score=0,
            )

    def find_critical_files(self) -> List[Path]:
        """重要ファイルを特定"""
        critical_files = []

        # 設定された重要ファイル
        for filename in self.critical_files:
            for file_path in self.moc_root.rglob(filename):
                critical_files.append(file_path)

        # 大きなPythonファイル（1000行以上）
        for py_file in self.moc_root.rglob("*.py"):
            if "venv" in str(py_file) or "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    lines = len(f.readlines())
                if lines > 1000:
                    critical_files.append(py_file)
            except:
                pass

        return list(set(critical_files))

    def compare_with_orch_next(self) -> Dict[str, str]:
        """ORCH-Nextとの依存関係比較"""
        comparison = {}

        # ORCH-Nextのrequirements.txtを読み込み
        orch_req = self.orch_next_root / "requirements.txt"
        orch_deps = {}

        if orch_req.exists():
            with open(orch_req, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        match = re.match(r"^([a-zA-Z0-9_-]+)([>=<~!]+.*)?", line)
                        if match:
                            name = match.group(1)
                            version = match.group(2) or ""
                            orch_deps[name] = version

        # 比較
        for name, dep_info in self.dependencies.items():
            if name in orch_deps:
                if dep_info.version != orch_deps[name]:
                    comparison[name] = (
                        f"VERSION_CONFLICT: MOC={dep_info.version}, ORCH-Next={orch_deps[name]}"
                    )
                else:
                    comparison[name] = "COMPATIBLE"
            else:
                comparison[name] = "MISSING_IN_ORCH_NEXT"

        # ORCH-NextにあってMOCにないもの
        for name in orch_deps:
            if name not in self.dependencies:
                comparison[name] = "NEW_IN_ORCH_NEXT"

        return comparison

    def generate_migration_report(self) -> Dict:
        """移行レポートを生成"""
        print("MOC依存関係分析を開始...")

        # 分析実行
        req_deps = self.analyze_requirements()
        import_analysis = self.analyze_python_imports()
        critical_files = self.find_critical_files()
        comparison = self.compare_with_orch_next()

        # 重要ファイルの複雑度分析
        for file_path in critical_files:
            analysis = self.analyze_file_complexity(file_path)
            self.file_analyses.append(analysis)

        # レポート生成
        report = {
            "analysis_date": str(Path(__file__).stat().st_mtime),
            "moc_root": str(self.moc_root),
            "summary": {
                "total_dependencies": len(self.dependencies),
                "critical_dependencies": len(
                    [d for d in self.dependencies.values() if d.is_critical]
                ),
                "critical_files": len(critical_files),
                "total_python_files": len(import_analysis),
                "conflicts": len([c for c in comparison.values() if "CONFLICT" in c]),
            },
            "dependencies": {name: asdict(dep) for name, dep in self.dependencies.items()},
            "file_analyses": [asdict(fa) for fa in self.file_analyses],
            "import_analysis": {k: list(v) for k, v in import_analysis.items()},
            "dependency_comparison": comparison,
            "migration_recommendations": self._generate_recommendations(comparison),
        }

        return report

    def _generate_recommendations(self, comparison: Dict[str, str]) -> List[str]:
        """移行推奨事項を生成"""
        recommendations = []

        conflicts = [name for name, status in comparison.items() if "CONFLICT" in status]
        if conflicts:
            recommendations.append(f"バージョン競合解決が必要: {', '.join(conflicts)}")

        missing = [name for name, status in comparison.items() if status == "MISSING_IN_ORCH_NEXT"]
        if missing:
            recommendations.append(f"ORCH-Nextに追加が必要: {', '.join(missing)}")

        critical_files = [fa for fa in self.file_analyses if fa.complexity_score > 50]
        if critical_files:
            recommendations.append(
                f"高複雑度ファイルの段階的移行推奨: {', '.join([cf.path for cf in critical_files])}"
            )

        return recommendations


def main():
    """メイン実行"""
    analyzer = MOCDependencyAnalyzer()

    try:
        report = analyzer.generate_migration_report()

        # レポート保存
        output_file = Path(
            "C:\\Users\\User\\Trae\\ORCH-Next\\handoff\\moc_dependency_analysis.json"
        )
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("\\n=== MOC依存関係分析完了 ===")
        print(f"レポート保存先: {output_file}")
        print("\\n概要:")
        print(f"  総依存関係数: {report['summary']['total_dependencies']}")
        print(f"  重要依存関係数: {report['summary']['critical_dependencies']}")
        print(f"  重要ファイル数: {report['summary']['critical_files']}")
        print(f"  競合数: {report['summary']['conflicts']}")

        if report["migration_recommendations"]:
            print("\\n推奨事項:")
            for rec in report["migration_recommendations"]:
                print(f"  - {rec}")

        return True

    except Exception as e:
        print(f"分析エラー: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
