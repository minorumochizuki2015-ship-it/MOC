#!/usr/bin/env python3
"""
自動承認システム (Automated Approval System)
ルールベース判定による承認プロセスの自動化

機能:
- 承認要求の自動分析
- リスク評価とルールベース判定
- 承認/拒否の自動決定
- 監査ログの生成
"""

import datetime
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalDecision(Enum):
    APPROVE = "approved"
    REJECT = "rejected"
    ESCALATE = "escalate"


@dataclass
class ApprovalRule:
    """承認ルール定義"""

    rule_id: str
    name: str
    condition: str
    risk_level: RiskLevel
    auto_approve: bool
    description: str


@dataclass
class ApprovalRequest:
    """承認要求データ"""

    appr_id: str
    task_id: str
    operation: str
    requested_by: str
    evidence_path: str
    timestamp: str
    metadata: Dict


class AutomatedApprovalSystem:
    """自動承認システム"""

    def __init__(self, db_path: str = "data/automated_approval.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        self._load_rules()

    def _init_database(self):
        """データベース初期化"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 承認履歴テーブル
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appr_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                applied_rules TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                evidence_hash TEXT,
                notes TEXT
            )
        """
        )

        # ルール適用履歴テーブル
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appr_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                matched BOOLEAN NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL
            )
        """
        )

        conn.commit()
        conn.close()

    def _load_rules(self):
        """承認ルールの読み込み"""
        self.rules = [
            ApprovalRule(
                rule_id="R001",
                name="低リスク操作",
                condition="operation in ['read', 'view', 'list', 'status']",
                risk_level=RiskLevel.LOW,
                auto_approve=True,
                description="読み取り専用操作は自動承認",
            ),
            ApprovalRule(
                rule_id="R002",
                name="テストファイル変更",
                condition="evidence_path contains 'test' and file_changes < 50",
                risk_level=RiskLevel.LOW,
                auto_approve=True,
                description="小規模なテストファイル変更は自動承認",
            ),
            ApprovalRule(
                rule_id="R003",
                name="設定ファイル変更",
                condition="evidence_path contains 'config' or evidence_path contains '.env'",
                risk_level=RiskLevel.HIGH,
                auto_approve=False,
                description="設定ファイル変更は手動承認必須",
            ),
            ApprovalRule(
                rule_id="R004",
                name="保護対象ファイル",
                condition="evidence_path contains 'dispatcher.py' or evidence_path contains 'hive_mind.py'",
                risk_level=RiskLevel.CRITICAL,
                auto_approve=False,
                description="保護対象ファイルは手動承認必須",
            ),
            ApprovalRule(
                rule_id="R005",
                name="大規模変更",
                condition="file_changes > 200 or lines_changed > 500",
                risk_level=RiskLevel.HIGH,
                auto_approve=False,
                description="大規模変更は手動承認必須",
            ),
            ApprovalRule(
                rule_id="R006",
                name="ドキュメント更新",
                condition="evidence_path contains '.md' and file_changes < 20",
                risk_level=RiskLevel.LOW,
                auto_approve=True,
                description="小規模なドキュメント更新は自動承認",
            ),
        ]

    def analyze_request(
        self, request: ApprovalRequest
    ) -> Tuple[ApprovalDecision, RiskLevel, float, List[str]]:
        """承認要求の分析"""
        # エビデンスファイルの分析
        evidence_analysis = self._analyze_evidence(request.evidence_path)

        # ルール適用
        matched_rules = []
        risk_scores = []

        for rule in self.rules:
            confidence = self._evaluate_rule(rule, request, evidence_analysis)
            if confidence > 0.5:  # ルールが適用される閾値
                matched_rules.append(rule.rule_id)
                risk_scores.append(self._risk_to_score(rule.risk_level))

                # ルール適用履歴を記録
                self._log_rule_application(request.appr_id, rule.rule_id, True, confidence)

        # 総合リスク評価
        if not risk_scores:
            # ルールにマッチしない場合はデフォルトでMEDIUMリスク
            overall_risk = RiskLevel.MEDIUM
            confidence = 0.5
        else:
            avg_risk_score = sum(risk_scores) / len(risk_scores)
            overall_risk = self._score_to_risk(avg_risk_score)
            confidence = min(risk_scores) if risk_scores else 0.5

        # 決定ロジック
        decision = self._make_decision(matched_rules, overall_risk, evidence_analysis)

        return decision, overall_risk, confidence, matched_rules

    def _analyze_evidence(self, evidence_path: str) -> Dict:
        """エビデンスファイルの分析"""
        analysis = {
            "file_exists": False,
            "file_size": 0,
            "line_count": 0,
            "file_changes": 0,
            "lines_changed": 0,
            "contains_sensitive": False,
            "file_hash": None,
        }

        try:
            evidence_file = Path(evidence_path)
            if evidence_file.exists():
                analysis["file_exists"] = True
                analysis["file_size"] = evidence_file.stat().st_size

                content = evidence_file.read_text(encoding="utf-8")
                analysis["line_count"] = len(content.splitlines())
                analysis["file_hash"] = hashlib.sha256(content.encode()).hexdigest()

                # 差分行数の推定（+/-行をカウント）
                diff_lines = [line for line in content.splitlines() if line.startswith(("+", "-"))]
                analysis["lines_changed"] = len(diff_lines)

                # ファイル変更数の推定（diff内のファイル名をカウント）
                file_patterns = re.findall(r"^\+\+\+ b/(.+)$", content, re.MULTILINE)
                analysis["file_changes"] = len(set(file_patterns))

                # 機密情報の検出
                sensitive_patterns = ["password", "secret", "key", "token", "api_key"]
                analysis["contains_sensitive"] = any(
                    pattern in content.lower() for pattern in sensitive_patterns
                )

        except Exception as e:
            print(f"Evidence analysis error: {e}")

        return analysis

    def _evaluate_rule(self, rule: ApprovalRule, request: ApprovalRequest, evidence: Dict) -> float:
        """ルール評価"""
        try:
            # 簡単な条件評価（実際の実装ではより高度な評価が必要）
            condition = rule.condition

            # 変数の置換
            context = {
                "operation": request.operation,
                "evidence_path": request.evidence_path,
                "file_changes": evidence.get("file_changes", 0),
                "lines_changed": evidence.get("lines_changed", 0),
                "contains_sensitive": evidence.get("contains_sensitive", False),
            }

            # 安全な条件評価
            if self._safe_eval_condition(condition, context):
                return 0.9  # 高い信頼度
            else:
                return 0.1  # 低い信頼度

        except Exception:
            return 0.0

    def _safe_eval_condition(self, condition: str, context: Dict) -> bool:
        """安全な条件評価"""
        try:
            # 簡単な文字列マッチング評価
            if "contains" in condition:
                # "evidence_path contains 'test'" のような条件
                parts = condition.split(" contains ")
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    search_term = parts[1].strip().strip("'\"")
                    return search_term in str(context.get(var_name, ""))

            elif " in " in condition:
                # "operation in ['read', 'view']" のような条件
                parts = condition.split(" in ")
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    values_str = parts[1].strip()
                    if values_str.startswith("[") and values_str.endswith("]"):
                        values = [v.strip().strip("'\"") for v in values_str[1:-1].split(",")]
                        return str(context.get(var_name, "")) in values

            elif ">" in condition:
                # "file_changes > 200" のような条件
                parts = condition.split(">")
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    threshold = float(parts[1].strip())
                    return float(context.get(var_name, 0)) > threshold

            elif "or" in condition:
                # 複数条件のOR評価
                sub_conditions = condition.split(" or ")
                return any(
                    self._safe_eval_condition(sub_cond.strip(), context)
                    for sub_cond in sub_conditions
                )

            elif "and" in condition:
                # 複数条件のAND評価
                sub_conditions = condition.split(" and ")
                return all(
                    self._safe_eval_condition(sub_cond.strip(), context)
                    for sub_cond in sub_conditions
                )

        except Exception:
            pass

        return False

    def _risk_to_score(self, risk_level: RiskLevel) -> float:
        """リスクレベルをスコアに変換"""
        mapping = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 1.0,
        }
        return mapping.get(risk_level, 0.5)

    def _score_to_risk(self, score: float) -> RiskLevel:
        """スコアをリスクレベルに変換"""
        if score >= 0.9:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _make_decision(
        self, matched_rules: List[str], risk_level: RiskLevel, evidence: Dict
    ) -> ApprovalDecision:
        """承認決定"""
        # 保護対象ファイルや高リスク操作は必ずエスカレーション
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            return ApprovalDecision.ESCALATE

        # 機密情報が含まれる場合はエスカレーション
        if evidence.get("contains_sensitive", False):
            return ApprovalDecision.ESCALATE

        # 低リスクで自動承認可能なルールがマッチした場合
        auto_approve_rules = [
            rule for rule in self.rules if rule.rule_id in matched_rules and rule.auto_approve
        ]
        if auto_approve_rules and risk_level == RiskLevel.LOW:
            return ApprovalDecision.APPROVE

        # その他の場合はエスカレーション
        return ApprovalDecision.ESCALATE

    def _log_rule_application(self, appr_id: str, rule_id: str, matched: bool, confidence: float):
        """ルール適用履歴の記録"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO rule_applications (appr_id, rule_id, matched, confidence, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
            (appr_id, rule_id, matched, confidence, datetime.datetime.utcnow().isoformat()),
        )

        conn.commit()
        conn.close()

    def process_approval(self, request: ApprovalRequest) -> Dict:
        """承認処理の実行"""
        decision, risk_level, confidence, matched_rules = self.analyze_request(request)

        # 承認履歴の記録
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        evidence_analysis = self._analyze_evidence(request.evidence_path)

        cursor.execute(
            """
            INSERT INTO approval_history 
            (appr_id, task_id, operation, requested_by, decision, risk_level, 
             applied_rules, confidence, timestamp, evidence_hash, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                request.appr_id,
                request.task_id,
                request.operation,
                request.requested_by,
                decision.value,
                risk_level.value,
                ",".join(matched_rules),
                confidence,
                datetime.datetime.utcnow().isoformat(),
                evidence_analysis.get("file_hash"),
                f"Auto-processed by rule engine",
            ),
        )

        conn.commit()
        conn.close()

        return {
            "appr_id": request.appr_id,
            "decision": decision.value,
            "risk_level": risk_level.value,
            "confidence": confidence,
            "matched_rules": matched_rules,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "reasoning": self._generate_reasoning(decision, risk_level, matched_rules),
        }

    def _generate_reasoning(
        self, decision: ApprovalDecision, risk_level: RiskLevel, matched_rules: List[str]
    ) -> str:
        """決定理由の生成"""
        rule_names = [rule.name for rule in self.rules if rule.rule_id in matched_rules]

        if decision == ApprovalDecision.APPROVE:
            return f"低リスク操作として自動承認。適用ルール: {', '.join(rule_names)}"
        elif decision == ApprovalDecision.ESCALATE:
            return f"リスクレベル {risk_level.value} のため手動承認が必要。適用ルール: {', '.join(rule_names)}"
        else:
            return f"自動拒否。適用ルール: {', '.join(rule_names)}"

    def get_approval_stats(self) -> Dict:
        """承認統計の取得"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 決定別統計
        cursor.execute(
            """
            SELECT decision, COUNT(*) as count
            FROM approval_history
            GROUP BY decision
        """
        )
        decision_stats = dict(cursor.fetchall())

        # リスクレベル別統計
        cursor.execute(
            """
            SELECT risk_level, COUNT(*) as count
            FROM approval_history
            GROUP BY risk_level
        """
        )
        risk_stats = dict(cursor.fetchall())

        # 最近の処理件数
        cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM approval_history
            WHERE timestamp > datetime('now', '-24 hours')
        """
        )
        recent_count = cursor.fetchone()[0]

        conn.close()

        return {
            "decision_stats": decision_stats,
            "risk_stats": risk_stats,
            "recent_24h": recent_count,
            "total_processed": sum(decision_stats.values()),
        }


def main():
    """メイン実行関数"""
    print("=== 自動承認システム テスト ===")

    # システム初期化
    approval_system = AutomatedApprovalSystem()

    # テストケース
    test_cases = [
        ApprovalRequest(
            appr_id="A004",
            task_id="004",
            operation="update",
            requested_by="WORK",
            evidence_path="ORCH/patches/2024-01/004-A004.diff.md",
            timestamp=datetime.datetime.utcnow().isoformat(),
            metadata={"type": "documentation"},
        ),
        ApprovalRequest(
            appr_id="A005",
            task_id="005",
            operation="modify",
            requested_by="WORK",
            evidence_path="src/dispatcher.py",
            timestamp=datetime.datetime.utcnow().isoformat(),
            metadata={"type": "core_system"},
        ),
        ApprovalRequest(
            appr_id="A006",
            task_id="006",
            operation="read",
            requested_by="AUDIT",
            evidence_path="data/logs/current/test.log",
            timestamp=datetime.datetime.utcnow().isoformat(),
            metadata={"type": "monitoring"},
        ),
    ]

    # テスト実行
    for i, request in enumerate(test_cases, 1):
        print(f"\n--- テストケース {i} ---")
        print(f"承認ID: {request.appr_id}")
        print(f"操作: {request.operation}")
        print(f"対象: {request.evidence_path}")

        result = approval_system.process_approval(request)

        print(f"決定: {result['decision']}")
        print(f"リスクレベル: {result['risk_level']}")
        print(f"信頼度: {result['confidence']:.3f}")
        print(f"適用ルール: {result['matched_rules']}")
        print(f"理由: {result['reasoning']}")

    # 統計表示
    print("\n=== 承認統計 ===")
    stats = approval_system.get_approval_stats()
    print(f"総処理件数: {stats['total_processed']}")
    print(f"24時間以内: {stats['recent_24h']}")
    print(f"決定別統計: {stats['decision_stats']}")
    print(f"リスク別統計: {stats['risk_stats']}")


if __name__ == "__main__":
    main()
