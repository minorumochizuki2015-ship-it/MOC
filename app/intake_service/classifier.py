"""
学習インテーク・アプリ用ドメイン分類器
簡易規則ベースのドメイン推定
"""

from __future__ import annotations

import re
from typing import List, Set

from .schema import DomainType


class DomainClassifier:
    """ドメイン分類器"""
    
    def __init__(self) -> None:
        """分類器の初期化"""
        self._code_keywords: Set[str] = {
            # プログラミング言語
            "python", "javascript", "typescript", "java", "c++", "c#", "go", "rust",
            "php", "ruby", "swift", "kotlin", "scala", "clojure", "haskell",
            # フレームワーク・ライブラリ
            "django", "flask", "fastapi", "react", "vue", "angular", "spring",
            "express", "nodejs", "tensorflow", "pytorch", "pandas", "numpy",
            # 技術用語
            "function", "class", "method", "variable", "import", "export",
            "api", "database", "sql", "nosql", "redis", "mongodb", "postgresql",
            "docker", "kubernetes", "aws", "azure", "gcp", "ci/cd", "devops",
            "git", "github", "gitlab", "jenkins", "terraform", "ansible",
            "algorithm", "data structure", "recursion", "iteration", "loop",
            "exception", "error handling", "logging", "testing", "unit test",
            "integration test", "refactor", "optimization", "performance",
            "security", "authentication", "authorization", "encryption",
            "microservices", "rest", "graphql", "websocket", "http", "https"
        }
        
        self._write_keywords: Set[str] = {
            # 文書・ライティング
            "document", "documentation", "readme", "manual", "guide", "tutorial",
            "article", "blog", "post", "essay", "report", "proposal", "specification",
            "requirements", "design", "architecture", "planning", "strategy",
            "content", "copy", "text", "writing", "editorial", "proofreading",
            "translation", "localization", "markdown", "latex", "html", "css",
            "presentation", "slide", "deck", "pitch", "proposal", "brief",
            "email", "letter", "memo", "note", "summary", "abstract", "outline",
            "draft", "revision", "edit", "review", "feedback", "comment",
            "style", "tone", "voice", "brand", "messaging", "communication"
        }
        
        self._patent_keywords: Set[str] = {
            # 特許・知的財産
            "patent", "invention", "innovation", "intellectual property", "ip",
            "copyright", "trademark", "trade secret", "proprietary", "confidential",
            "novel", "non-obvious", "utility", "prior art", "claims", "specification",
            "drawings", "figures", "embodiments", "implementation", "methodology",
            "process", "system", "apparatus", "device", "composition", "formula",
            "algorithm", "software", "hardware", "circuit", "component", "module",
            "interface", "protocol", "standard", "specification", "compliance",
            "regulatory", "legal", "litigation", "infringement", "licensing",
            "royalty", "assignment", "filing", "examination", "prosecution",
            "grant", "maintenance", "renewal", "expiration", "abandonment"
        }
        
        # ファイル拡張子パターン
        self._code_extensions: Set[str] = {
            ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs", ".go", ".rs",
            ".php", ".rb", ".swift", ".kt", ".scala", ".clj", ".hs", ".ml",
            ".html", ".css", ".scss", ".sass", ".less", ".xml", ".json", ".yaml",
            ".yml", ".toml", ".ini", ".cfg", ".conf", ".sql", ".sh", ".bat",
            ".ps1", ".dockerfile", ".makefile", ".cmake", ".gradle", ".maven"
        }
        
        self._write_extensions: Set[str] = {
            ".md", ".txt", ".rst", ".tex", ".doc", ".docx", ".pdf", ".rtf",
            ".odt", ".pages", ".epub", ".mobi", ".azw", ".azw3"
        }

    def classify_domain(self, title: str, prompt: str, output: str, refs: List[str]) -> DomainType:
        """ドメインを分類"""
        # テキストを結合して小文字に変換
        text = f"{title} {prompt} {output}".lower()
        
        # 参照パスから拡張子を抽出
        extensions = set()
        for ref in refs:
            if "." in ref:
                ext = "." + ref.split(".")[-1].lower()
                extensions.add(ext)
        
        # スコア計算
        code_score = self._calculate_code_score(text, extensions)
        write_score = self._calculate_write_score(text, extensions)
        patent_score = self._calculate_patent_score(text)
        
        # 最高スコアのドメインを返す
        scores = {
            DomainType.CODE: code_score,
            DomainType.WRITE: write_score,
            DomainType.PATENT: patent_score
        }
        
        max_domain = max(scores, key=scores.get)
        max_score = scores[max_domain]
        
        # 閾値未満の場合はUNKNOWN
        if max_score < 0.1:
            return DomainType.UNKNOWN
        
        return max_domain

    def _calculate_code_score(self, text: str, extensions: Set[str]) -> float:
        """コードドメインのスコア計算"""
        score = 0.0
        
        # キーワードマッチング
        keyword_matches = sum(1 for keyword in self._code_keywords if keyword in text)
        score += keyword_matches * 0.1
        
        # 拡張子マッチング
        ext_matches = sum(1 for ext in extensions if ext in self._code_extensions)
        score += ext_matches * 0.3
        
        # コードパターンマッチング
        code_patterns = [
            r'\bdef\s+\w+',  # Python関数定義
            r'\bfunction\s+\w+',  # JavaScript関数定義
            r'\bclass\s+\w+',  # クラス定義
            r'\bimport\s+\w+',  # インポート文
            r'\bfrom\s+\w+\s+import',  # インポート文
            r'\bif\s+\(',  # 条件文
            r'\bfor\s+\(',  # ループ文
            r'\bwhile\s+\(',  # ループ文
            r'\btry\s*\{',  # 例外処理
            r'\bcatch\s*\(',  # 例外処理
            r'\bpublic\s+\w+',  # アクセス修飾子
            r'\bprivate\s+\w+',  # アクセス修飾子
            r'\bprotected\s+\w+',  # アクセス修飾子
            r'\bstatic\s+\w+',  # 静的修飾子
            r'\bfinal\s+\w+',  # 最終修飾子
            r'\bconst\s+\w+',  # 定数
            r'\blet\s+\w+',  # 変数宣言
            r'\bvar\s+\w+',  # 変数宣言
        ]
        
        pattern_matches = sum(1 for pattern in code_patterns if re.search(pattern, text))
        score += pattern_matches * 0.2
        
        return min(score, 1.0)  # 最大1.0に制限

    def _calculate_write_score(self, text: str, extensions: Set[str]) -> float:
        """ライティングドメインのスコア計算"""
        score = 0.0
        
        # キーワードマッチング
        keyword_matches = sum(1 for keyword in self._write_keywords if keyword in text)
        score += keyword_matches * 0.1
        
        # 拡張子マッチング
        ext_matches = sum(1 for ext in extensions if ext in self._write_extensions)
        score += ext_matches * 0.3
        
        # 文書パターンマッチング
        write_patterns = [
            r'\bchapter\s+\d+',  # 章番号
            r'\bsection\s+\d+',  # セクション番号
            r'\bparagraph\s+\d+',  # 段落番号
            r'\bfigure\s+\d+',  # 図番号
            r'\btable\s+\d+',  # 表番号
            r'\breference\s+\d+',  # 参照番号
            r'\bfootnote\s+\d+',  # 脚注番号
            r'\bappendix\s+\d+',  # 付録番号
            r'\bintroduction',  # 導入
            r'\bconclusion',  # 結論
            r'\babstract',  # 要約
            r'\bexecutive\s+summary',  # エグゼクティブサマリー
            r'\bmethodology',  # 方法論
            r'\bresults',  # 結果
            r'\bdiscussion',  # 議論
            r'\brecommendations',  # 推奨事項
        ]
        
        pattern_matches = sum(1 for pattern in write_patterns if re.search(pattern, text))
        score += pattern_matches * 0.2
        
        return min(score, 1.0)  # 最大1.0に制限

    def _calculate_patent_score(self, text: str) -> float:
        """特許ドメインのスコア計算"""
        score = 0.0
        
        # キーワードマッチング
        keyword_matches = sum(1 for keyword in self._patent_keywords if keyword in text)
        score += keyword_matches * 0.1
        
        # 特許パターンマッチング
        patent_patterns = [
            r'\bclaim\s+\d+',  # クレーム番号
            r'\bembodiment\s+\d+',  # 実施例番号
            r'\bfigure\s+\d+',  # 図番号
            r'\btable\s+\d+',  # 表番号
            r'\bprior\s+art',  # 先行技術
            r'\bnovel\s+and\s+non-obvious',  # 新規性・非自明性
            r'\butility\s+patent',  # 実用新案
            r'\bdesign\s+patent',  # 意匠
            r'\bplant\s+patent',  # 植物特許
            r'\bprovisional\s+application',  # 仮出願
            r'\bnon-provisional\s+application',  # 本出願
            r'\bcontinuation\s+application',  # 継続出願
            r'\bdivisional\s+application',  # 分割出願
            r'\bcontinuation-in-part',  # 部分継続出願
            r'\breexamination',  # 再審査
            r'\breissue',  # 再発行
            r'\babandonment',  # 放棄
            r'\bmaintenance\s+fee',  # 維持料
            r'\brenewal\s+fee',  # 更新料
        ]
        
        pattern_matches = sum(1 for pattern in patent_patterns if re.search(pattern, text))
        score += pattern_matches * 0.2
        
        return min(score, 1.0)  # 最大1.0に制限


# グローバルインスタンス
classifier = DomainClassifier()


def classify_domain(title: str, prompt: str, output: str, refs: List[str]) -> DomainType:
    """ドメイン分類の便利関数"""
    return classifier.classify_domain(title, prompt, output, refs)

