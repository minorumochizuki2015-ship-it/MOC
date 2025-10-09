#!/usr/bin/env python3
"""
品質メトリクス/リソースメトリクスのシンセティックデータ生成スクリプト
既存DB(data/quality_metrics.db)に多様ケースを追加投入し、学習の安定性を高める。
"""

import sys
from datetime import datetime

sys.path.append(".")


def main():
    from src.ai_prediction import QualityPredictor

    qp = QualityPredictor()
    # 追加生成ボリューム: 5000件（品質+リソース）
    qp.generate_test_data(num_samples=5000)
    print(f"[{datetime.now().isoformat()}] Synthetic data generation completed.")


if __name__ == "__main__":
    main()
