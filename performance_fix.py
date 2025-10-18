#!/usr/bin/env python3
"""
パフォーマンス問題の根本修正ツール
"""

import os
import re
import shutil
from datetime import datetime


class PerformanceFixer:
    def __init__(self, dashboard_file: str):
        self.dashboard_file = dashboard_file
        self.backup_file = f"{dashboard_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def create_backup(self):
        """バックアップ作成"""
        shutil.copy2(self.dashboard_file, self.backup_file)
        print(f"バックアップ作成: {self.backup_file}")

    def fix_slow_imports(self, content: str) -> str:
        """遅いインポートの修正"""
        # 不要なインポートの削除
        unnecessary_imports = [
            r"import matplotlib.*\n",
            r"import seaborn.*\n",
            r"import plotly.*\n",
            r"from plotly.*\n",
            r"import pandas.*\n",
            r"from pandas.*\n",
        ]

        for pattern in unnecessary_imports:
            content = re.sub(pattern, "", content)

        # 遅延インポートの追加
        lazy_import_block = '''
# 遅延インポート用の関数
def lazy_import_ml():
    """ML関連ライブラリの遅延インポート"""
    global np, pd
    try:
        import numpy as np
        import pandas as pd
    except ImportError:
        np = None
        pd = None

def lazy_import_plotting():
    """プロット関連ライブラリの遅延インポート"""
    global plt, sns
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        plt = None
        sns = None

# グローバル変数の初期化
np = None
pd = None
plt = None
sns = None
'''

        # インポートセクションの後に遅延インポートを追加
        import_end = content.find("\nclass")
        if import_end != -1:
            content = content[:import_end] + lazy_import_block + content[import_end:]

        return content

    def fix_slow_initialization(self, content: str) -> str:
        """遅い初期化処理の修正"""

        # __init__メソッドの最適化
        init_optimizations = [
            # 重い処理を遅延実行に変更
            (
                r"(\s+)self\.setup_ml_components\(\)",
                r"\1# self.setup_ml_components()  # 遅延実行に変更",
            ),
            (
                r"(\s+)self\.initialize_monitoring\(\)",
                r"\1# self.initialize_monitoring()  # 遅延実行に変更",
            ),
            (
                r"(\s+)self\.load_historical_data\(\)",
                r"\1# self.load_historical_data()  # 遅延実行に変更",
            ),
        ]

        for pattern, replacement in init_optimizations:
            content = re.sub(pattern, replacement, content)

        return content

    def add_lazy_loading(self, content: str) -> str:
        """遅延ローディングの追加"""

        lazy_loading_methods = '''
    def _ensure_ml_components(self):
        """ML コンポーネントの遅延初期化"""
        if not hasattr(self, '_ml_initialized'):
            lazy_import_ml()
            if np is not None:
                self.setup_ml_components()
            self._ml_initialized = True
    
    def _ensure_monitoring(self):
        """監視システムの遅延初期化"""
        if not hasattr(self, '_monitoring_initialized'):
            self.initialize_monitoring()
            self._monitoring_initialized = True
    
    def _ensure_historical_data(self):
        """履歴データの遅延ロード"""
        if not hasattr(self, '_historical_data_loaded'):
            self.load_historical_data()
            self._historical_data_loaded = True
'''

        # クラス定義の最後に遅延ローディングメソッドを追加
        class_end = content.rfind("    def run(")
        if class_end != -1:
            content = content[:class_end] + lazy_loading_methods + "\n" + content[class_end:]

        return content

    def optimize_route_handlers(self, content: str) -> str:
        """ルートハンドラーの最適化"""

        # 重い処理を含むルートの最適化
        route_optimizations = [
            # メインページの最適化
            (
                r"(@app\.route\(\'/\'\)\s+def index\(\):.*?)return render_template",
                r"\1# 遅延ローディングの適用\n        self._ensure_monitoring()\n        return render_template",
            ),
            # API ステータスの最適化
            (
                r"(@app\.route\(\'/api/status\'\)\s+def api_status\(\):.*?)(\s+)(.*?return jsonify)",
                r'\1\2# 軽量化されたステータス応答\n\2try:\n\2    status = {\n\2        "status": "running",\n\2        "timestamp": datetime.now().isoformat(),\n\2        "uptime": time.time() - self.start_time if hasattr(self, "start_time") else 0\n\2    }\n\2    \3',
            ),
        ]

        for pattern, replacement in route_optimizations:
            content = re.sub(pattern, replacement, content, flags=re.DOTALL)

        return content

    def add_caching_decorators(self, content: str) -> str:
        """キャッシュデコレーターの追加"""

        # キャッシュ設定の追加
        cache_config = '''
# キャッシュ設定
from functools import lru_cache
import time

# シンプルなメモリキャッシュ
_cache = {}
_cache_ttl = {}

def simple_cache(ttl=60):
    """シンプルなキャッシュデコレーター"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            now = time.time()
            
            if key in _cache and key in _cache_ttl:
                if now < _cache_ttl[key]:
                    return _cache[key]
            
            result = func(*args, **kwargs)
            _cache[key] = result
            _cache_ttl[key] = now + ttl
            return result
        return wrapper
    return decorator
'''

        # インポートセクションの後にキャッシュ設定を追加
        import_end = content.find("\nclass")
        if import_end != -1:
            content = content[:import_end] + cache_config + content[import_end:]

        # 重いメソッドにキャッシュを適用
        cached_methods = [
            (r"(\s+def get_system_status\(self\):)", r"\1\n    @simple_cache(ttl=30)"),
            (r"(\s+def get_task_summary\(self\):)", r"\1\n    @simple_cache(ttl=60)"),
            (r"(\s+def get_performance_metrics\(self\):)", r"\1\n    @simple_cache(ttl=120)"),
        ]

        for pattern, replacement in cached_methods:
            content = re.sub(pattern, replacement, content)

        return content

    def fix_database_queries(self, content: str) -> str:
        """データベースクエリの最適化"""

        # 重いクエリの最適化
        query_optimizations = [
            # LIMIT句の追加
            (r"SELECT \* FROM tasks", r"SELECT * FROM tasks LIMIT 100"),
            (r"SELECT \* FROM approvals", r"SELECT * FROM approvals LIMIT 100"),
            # インデックスヒントの追加
            (r"ORDER BY created_at DESC", r"ORDER BY created_at DESC LIMIT 50"),
        ]

        for pattern, replacement in query_optimizations:
            content = re.sub(pattern, replacement, content)

        return content

    def apply_all_fixes(self):
        """すべての修正を適用"""
        print("パフォーマンス修正を開始...")

        # バックアップ作成
        self.create_backup()

        # ファイル読み込み
        with open(self.dashboard_file, "r", encoding="utf-8") as f:
            content = f.read()

        print("1. 遅いインポートの修正...")
        content = self.fix_slow_imports(content)

        print("2. 初期化処理の最適化...")
        content = self.fix_slow_initialization(content)

        print("3. 遅延ローディングの追加...")
        content = self.add_lazy_loading(content)

        print("4. ルートハンドラーの最適化...")
        content = self.optimize_route_handlers(content)

        print("5. キャッシュの追加...")
        content = self.add_caching_decorators(content)

        print("6. データベースクエリの最適化...")
        content = self.fix_database_queries(content)

        # 修正されたファイルを保存
        with open(self.dashboard_file, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"パフォーマンス修正完了: {self.dashboard_file}")
        print(f"バックアップ: {self.backup_file}")


def main():
    dashboard_file = "orch_dashboard.py"

    if not os.path.exists(dashboard_file):
        print(f"エラー: {dashboard_file} が見つかりません")
        return

    fixer = PerformanceFixer(dashboard_file)
    fixer.apply_all_fixes()

    print("\n修正完了！ダッシュボードを再起動してください。")


if __name__ == "__main__":
    main()
