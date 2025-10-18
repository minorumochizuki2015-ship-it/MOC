#!/usr/bin/env python3
"""
データベースクエリ最適化ツール

SQLクエリのパフォーマンス分析と最適化提案を行います。
"""

import json
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class QueryAnalyzer:
    """SQLクエリ分析クラス"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "C:/Users/User/Trae/ORCH-Next/data/app.db"
        self.query_log = []
        self.slow_query_threshold = 0.1  # 100ms

        # ログ設定
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # クエリパターン
        self.query_patterns = {
            "select": re.compile(r"SELECT\s+(.+?)\s+FROM\s+(\w+)", re.IGNORECASE),
            "insert": re.compile(r"INSERT\s+INTO\s+(\w+)", re.IGNORECASE),
            "update": re.compile(r"UPDATE\s+(\w+)", re.IGNORECASE),
            "delete": re.compile(r"DELETE\s+FROM\s+(\w+)", re.IGNORECASE),
            "join": re.compile(r"JOIN\s+(\w+)", re.IGNORECASE),
            "where": re.compile(r"WHERE\s+(.+?)(?:\s+ORDER|\s+GROUP|\s+LIMIT|$)", re.IGNORECASE),
            "order_by": re.compile(r"ORDER\s+BY\s+(.+?)(?:\s+LIMIT|$)", re.IGNORECASE),
            "group_by": re.compile(r"GROUP\s+BY\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)", re.IGNORECASE),
            "limit": re.compile(r"LIMIT\s+(\d+)", re.IGNORECASE),
        }

    def analyze_query(self, query: str, execution_time: float = None) -> Dict[str, Any]:
        """クエリを分析"""
        analysis = {
            "query": query.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": execution_time,
            "type": self._get_query_type(query),
            "tables": self._extract_tables(query),
            "columns": self._extract_columns(query),
            "conditions": self._extract_conditions(query),
            "joins": self._extract_joins(query),
            "complexity_score": self._calculate_complexity(query),
            "optimization_suggestions": self._get_optimization_suggestions(query),
        }

        # スロークエリの場合は警告
        if execution_time and execution_time > self.slow_query_threshold:
            analysis["is_slow"] = True
            analysis["performance_impact"] = "high" if execution_time > 1.0 else "medium"
            self.logger.warning(f"スロークエリ検出: {execution_time:.3f}s - {query[:100]}...")
        else:
            analysis["is_slow"] = False
            analysis["performance_impact"] = "low"

        self.query_log.append(analysis)
        return analysis

    def _get_query_type(self, query: str) -> str:
        """クエリタイプを取得"""
        query_upper = query.upper().strip()
        if query_upper.startswith("SELECT"):
            return "SELECT"
        elif query_upper.startswith("INSERT"):
            return "INSERT"
        elif query_upper.startswith("UPDATE"):
            return "UPDATE"
        elif query_upper.startswith("DELETE"):
            return "DELETE"
        elif query_upper.startswith("CREATE"):
            return "CREATE"
        elif query_upper.startswith("DROP"):
            return "DROP"
        else:
            return "OTHER"

    def _extract_tables(self, query: str) -> List[str]:
        """テーブル名を抽出"""
        tables = set()

        # FROM句のテーブル
        from_match = re.search(r"FROM\s+(\w+)", query, re.IGNORECASE)
        if from_match:
            tables.add(from_match.group(1))

        # JOIN句のテーブル
        join_matches = self.query_patterns["join"].findall(query)
        tables.update(join_matches)

        # INSERT/UPDATE/DELETE のテーブル
        for pattern_name in ["insert", "update", "delete"]:
            match = self.query_patterns[pattern_name].search(query)
            if match:
                tables.add(match.group(1))

        return list(tables)

    def _extract_columns(self, query: str) -> List[str]:
        """カラム名を抽出"""
        columns = []

        # SELECT句のカラム
        select_match = self.query_patterns["select"].search(query)
        if select_match:
            select_part = select_match.group(1)
            if select_part.strip() != "*":
                # カンマで分割してカラム名を抽出
                cols = [col.strip() for col in select_part.split(",")]
                columns.extend(cols)

        return columns

    def _extract_conditions(self, query: str) -> List[str]:
        """WHERE条件を抽出"""
        conditions = []

        where_match = self.query_patterns["where"].search(query)
        if where_match:
            where_clause = where_match.group(1)
            # AND/ORで分割
            parts = re.split(r"\s+(?:AND|OR)\s+", where_clause, flags=re.IGNORECASE)
            conditions.extend([part.strip() for part in parts])

        return conditions

    def _extract_joins(self, query: str) -> List[str]:
        """JOIN情報を抽出"""
        joins = []

        # JOIN句を検索
        join_pattern = re.compile(
            r"((?:INNER|LEFT|RIGHT|FULL)?\s*JOIN\s+\w+\s+ON\s+[^)]+)", re.IGNORECASE
        )
        join_matches = join_pattern.findall(query)
        joins.extend(join_matches)

        return joins

    def _calculate_complexity(self, query: str) -> int:
        """クエリの複雑度を計算"""
        score = 0

        # 基本スコア
        score += 1

        # テーブル数
        tables = self._extract_tables(query)
        score += len(tables) * 2

        # JOIN数
        joins = self._extract_joins(query)
        score += len(joins) * 3

        # サブクエリ
        subquery_count = query.upper().count("SELECT") - 1
        score += subquery_count * 5

        # 集約関数
        aggregates = ["COUNT", "SUM", "AVG", "MAX", "MIN"]
        for agg in aggregates:
            score += query.upper().count(agg) * 2

        # GROUP BY
        if "GROUP BY" in query.upper():
            score += 3

        # ORDER BY
        if "ORDER BY" in query.upper():
            score += 2

        # HAVING
        if "HAVING" in query.upper():
            score += 4

        return score

    def _get_optimization_suggestions(self, query: str) -> List[str]:
        """最適化提案を生成"""
        suggestions = []

        # SELECT * の使用チェック
        if re.search(r"SELECT\s+\*", query, re.IGNORECASE):
            suggestions.append("SELECT * の代わりに必要なカラムのみを指定してください")

        # インデックスが必要そうなWHERE条件
        conditions = self._extract_conditions(query)
        for condition in conditions:
            if "=" in condition or "LIKE" in condition.upper():
                column = condition.split()[0]
                suggestions.append(f"カラム '{column}' にインデックスを検討してください")

        # LIMIT句がないSELECT
        if query.upper().startswith("SELECT") and "LIMIT" not in query.upper():
            suggestions.append("大量データの場合はLIMIT句の使用を検討してください")

        # ORDER BY without INDEX
        order_match = self.query_patterns["order_by"].search(query)
        if order_match:
            order_columns = order_match.group(1)
            suggestions.append(
                f"ORDER BY カラム '{order_columns}' にインデックスを検討してください"
            )

        # 複数テーブルJOINでのWHERE条件
        tables = self._extract_tables(query)
        joins = self._extract_joins(query)
        if len(tables) > 1 and len(joins) > 0:
            suggestions.append("JOIN条件とWHERE条件の最適化を検討してください")

        # サブクエリの最適化
        if query.upper().count("SELECT") > 1:
            suggestions.append("サブクエリをJOINに書き換えることで性能向上の可能性があります")

        return suggestions


class DatabaseOptimizer:
    """データベース最適化クラス"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "C:/Users/User/Trae/ORCH-Next/data/app.db"
        self.analyzer = QueryAnalyzer(db_path)

        # ログ設定
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def execute_with_analysis(self, query: str, params: Tuple = ()) -> Tuple[Any, Dict[str, Any]]:
        """クエリを実行して分析"""
        start_time = time.time()

        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                # Improve concurrency and reliability on this connection
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute("PRAGMA busy_timeout=5000;")
                    conn.execute("PRAGMA foreign_keys=ON;")
                except Exception:
                    # PRAGMA may fail on read-only or specific environments; ignore silently
                    pass
                with conn:
                    cursor = conn.cursor()
                    result = cursor.execute(query, params).fetchall()

            execution_time = time.time() - start_time
            analysis = self.analyzer.analyze_query(query, execution_time)

            return result, analysis

        except Exception as e:
            execution_time = time.time() - start_time
            analysis = self.analyzer.analyze_query(query, execution_time)
            analysis["error"] = str(e)

            self.logger.error(f"クエリ実行エラー: {e}")
            raise

    def analyze_database_schema(self) -> Dict[str, Any]:
        """データベーススキーマを分析"""
        schema_info = {"tables": {}, "indexes": {}, "statistics": {}, "recommendations": []}

        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                # Ensure connection has recommended PRAGMA settings
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute("PRAGMA busy_timeout=5000;")
                    conn.execute("PRAGMA foreign_keys=ON;")
                except Exception:
                    pass
                with conn:
                    cursor = conn.cursor()

                    # テーブル一覧
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]

                    for table in tables:
                        # テーブル情報
                        cursor.execute(f"PRAGMA table_info({table})")
                        columns = cursor.fetchall()

                        # レコード数
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]

                        schema_info["tables"][table] = {
                            "columns": [
                                {
                                    "name": col[1],
                                    "type": col[2],
                                    "not_null": bool(col[3]),
                                    "default": col[4],
                                    "primary_key": bool(col[5]),
                                }
                                for col in columns
                            ],
                            "row_count": row_count,
                        }

                    # インデックス一覧
                    cursor.execute(
                        "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'"
                    )
                    indexes = cursor.fetchall()

                    for index in indexes:
                        if index[0] and not index[0].startswith("sqlite_"):
                            schema_info["indexes"][index[0]] = {"table": index[1], "sql": index[2]}

                    # 統計情報
                    schema_info["statistics"] = {
                        "total_tables": len(tables),
                        "total_indexes": len(schema_info["indexes"]),
                        "total_rows": sum(
                            info["row_count"] for info in schema_info["tables"].values()
                        ),
                    }

                    # 推奨事項
                    schema_info["recommendations"] = self._generate_schema_recommendations(
                        schema_info
                    )

        except Exception as e:
            self.logger.error(f"スキーマ分析エラー: {e}")
            schema_info["error"] = str(e)

        return schema_info

    def _generate_schema_recommendations(self, schema_info: Dict[str, Any]) -> List[str]:
        """スキーマ最適化推奨事項を生成"""
        recommendations = []

        for table_name, table_info in schema_info["tables"].items():
            # 主キーがないテーブル
            has_primary_key = any(col["primary_key"] for col in table_info["columns"])
            if not has_primary_key:
                recommendations.append(f"テーブル '{table_name}' に主キーの追加を検討してください")

            # 大量データテーブルのインデックス
            if table_info["row_count"] > 10000:
                recommendations.append(
                    f"テーブル '{table_name}' ({table_info['row_count']} 行) のインデックス最適化を検討してください"
                )

        # インデックスが少ない場合
        if schema_info["statistics"]["total_indexes"] < schema_info["statistics"]["total_tables"]:
            recommendations.append(
                "インデックス数が少ない可能性があります。クエリパフォーマンスを確認してください"
            )

        return recommendations

    def generate_performance_report(self) -> Dict[str, Any]:
        """パフォーマンスレポートを生成"""
        query_stats = defaultdict(list)
        slow_queries = []

        # クエリログを分析
        for log_entry in self.analyzer.query_log:
            query_type = log_entry["type"]
            query_stats[query_type].append(log_entry)

            if log_entry.get("is_slow", False):
                slow_queries.append(log_entry)

        # 統計計算
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_queries": len(self.analyzer.query_log),
                "slow_queries": len(slow_queries),
                # クエリタイプの一覧（dict()ではなくlist()でキーを列挙）
                "query_types": list(query_stats.keys()),
            },
            "performance_metrics": {},
            "slow_queries": slow_queries[:10],  # 上位10件
            "optimization_opportunities": [],
            "schema_analysis": self.analyze_database_schema(),
        }

        # タイプ別統計
        for query_type, queries in query_stats.items():
            execution_times = [q["execution_time"] for q in queries if q["execution_time"]]

            if execution_times:
                report["performance_metrics"][query_type] = {
                    "count": len(queries),
                    "avg_time": sum(execution_times) / len(execution_times),
                    "max_time": max(execution_times),
                    "min_time": min(execution_times),
                }

        # 最適化機会の特定
        all_suggestions = []
        for log_entry in self.analyzer.query_log:
            all_suggestions.extend(log_entry.get("optimization_suggestions", []))

        # 重複を除去して頻度順にソート
        suggestion_counts = defaultdict(int)
        for suggestion in all_suggestions:
            suggestion_counts[suggestion] += 1

        report["optimization_opportunities"] = [
            {"suggestion": suggestion, "frequency": count}
            for suggestion, count in sorted(
                suggestion_counts.items(), key=lambda x: x[1], reverse=True
            )
        ][:10]

        return report

    def export_report(self, filepath: str):
        """レポートをファイルにエクスポート"""
        report = self.generate_performance_report()

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.logger.info(f"パフォーマンスレポートをエクスポート: {filepath}")

    def suggest_indexes(self) -> List[Dict[str, Any]]:
        """インデックス提案を生成"""
        suggestions = []

        # クエリログからWHERE条件を分析
        column_usage = defaultdict(int)

        for log_entry in self.analyzer.query_log:
            conditions = log_entry.get("conditions", [])
            for condition in conditions:
                # 簡単なカラム抽出（実際はより複雑な解析が必要）
                parts = condition.split()
                if len(parts) >= 3:
                    column = parts[0]
                    column_usage[column] += 1

        # 使用頻度の高いカラムにインデックスを提案
        for column, usage_count in sorted(column_usage.items(), key=lambda x: x[1], reverse=True):
            if usage_count >= 5:  # 5回以上使用されている
                suggestions.append(
                    {
                        "column": column,
                        "usage_count": usage_count,
                        "suggested_index": f"CREATE INDEX idx_{column} ON table_name ({column})",
                        "reason": f"WHERE条件で {usage_count} 回使用されています",
                    }
                )

        return suggestions[:10]  # 上位10件


# 使用例とテスト
if __name__ == "__main__":
    print("データベース最適化ツールテスト開始")

    # テスト用データベース作成
    test_db = "C:/Users/User/Trae/ORCH-Next/data/test_optimization.db"

    # 既存のテストDBがある場合は削除して毎回クリーンな状態で開始
    try:
        if os.path.exists(test_db):
            os.remove(test_db)
    except Exception:
        # Windowsのファイルロックなどで削除できない場合は、テーブルをクリーンアップ
        pass

    with closing(sqlite3.connect(test_db)) as conn:
        with conn:
            cursor = conn.cursor()

            # テストテーブル作成
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    amount REAL,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """
            )

            # テストデータ挿入
            # 再実行時の重複を避けるため、既存データをクリア
            cursor.execute("DELETE FROM orders")
            cursor.execute("DELETE FROM users")
            for i in range(100):
                cursor.execute(
                    "INSERT INTO users (name, email) VALUES (?, ?)",
                    (f"User{i}", f"user{i}@example.com"),
                )
                cursor.execute(
                    "INSERT INTO orders (user_id, amount, status) VALUES (?, ?, ?)",
                    (i % 50 + 1, 100.0 + i, "completed" if i % 2 == 0 else "pending"),
                )

            # Connection context will commit automatically

    # 最適化ツールテスト
    optimizer = DatabaseOptimizer(test_db)

    # テストクエリ実行
    test_queries = [
        "SELECT * FROM users WHERE email = 'user1@example.com'",
        "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id",
        "SELECT * FROM orders WHERE status = 'completed' ORDER BY created_at DESC",
        "SELECT AVG(amount) FROM orders WHERE user_id IN (SELECT id FROM users WHERE name LIKE 'User1%')",
    ]

    print("\nテストクエリ実行と分析:")
    for query in test_queries:
        try:
            result, analysis = optimizer.execute_with_analysis(query)
            print(f"\nクエリ: {query[:50]}...")
            print(f"実行時間: {analysis['execution_time']:.4f}秒")
            print(f"複雑度スコア: {analysis['complexity_score']}")
            print(f"最適化提案数: {len(analysis['optimization_suggestions'])}")
        except Exception as e:
            print(f"エラー: {e}")

    # スキーマ分析
    print("\nスキーマ分析:")
    schema_analysis = optimizer.analyze_database_schema()
    print(f"テーブル数: {schema_analysis['statistics']['total_tables']}")
    print(f"インデックス数: {schema_analysis['statistics']['total_indexes']}")
    print(f"総レコード数: {schema_analysis['statistics']['total_rows']}")

    # パフォーマンスレポート生成
    print("\nパフォーマンスレポート生成:")
    report_path = "C:/Users/User/Trae/ORCH-Next/data/test_results/db_performance_report.json"
    optimizer.export_report(report_path)

    # インデックス提案
    print("\nインデックス提案:")
    index_suggestions = optimizer.suggest_indexes()
    for suggestion in index_suggestions[:3]:
        print(f"- {suggestion['column']}: {suggestion['reason']}")

    print("\n✓ データベース最適化ツールテスト完了")
