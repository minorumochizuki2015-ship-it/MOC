#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
スタイル管理機能統合テストレポート生成
"""

import json
import os
from datetime import datetime


class TestReportGenerator:
    def __init__(self):
        self.test_files = [
            ("test_results.json", "基本UI機能テスト"),
            ("api_test_results.json", "API機能テスト"),
            ("element_selection_test_results.json", "要素選択機能テスト"),
            ("visual_editing_test_results.json", "ビジュアル編集機能テスト"),
        ]

    def load_test_results(self):
        """全てのテスト結果を読み込み"""
        all_results = {}

        for filename, description in self.test_files:
            if os.path.exists(filename):
                try:
                    with open(filename, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        all_results[description] = data
                        print(f"✓ {description} 結果を読み込みました")
                except Exception as e:
                    print(f"✗ {description} 読み込みエラー: {e}")
                    all_results[description] = {"error": str(e)}
            else:
                print(f"⚠️ {description} ファイルが見つかりません: {filename}")
                all_results[description] = {"error": "ファイルが見つかりません"}

        return all_results

    def generate_html_report(self, all_results):
        """HTMLレポートを生成"""
        html_content = f"""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>スタイル管理機能テストレポート</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .summary {{
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #495057;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .pass {{ color: #28a745; }}
        .fail {{ color: #dc3545; }}
        .skip {{ color: #ffc107; }}
        .total {{ color: #007bff; }}
        .test-section {{
            padding: 30px;
            border-bottom: 1px solid #e9ecef;
        }}
        .test-section:last-child {{
            border-bottom: none;
        }}
        .test-section h2 {{
            margin: 0 0 20px 0;
            color: #495057;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }}
        .test-result {{
            margin: 15px 0;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid;
        }}
        .test-result.pass {{
            background: #d4edda;
            border-color: #28a745;
        }}
        .test-result.fail {{
            background: #f8d7da;
            border-color: #dc3545;
        }}
        .test-result.skip {{
            background: #fff3cd;
            border-color: #ffc107;
        }}
        .test-result h4 {{
            margin: 0 0 8px 0;
            font-size: 1.1em;
        }}
        .test-result p {{
            margin: 0;
            color: #666;
        }}
        .error {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }}
        .timestamp {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }}
        .status-icon {{
            font-size: 1.2em;
            margin-right: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎨 スタイル管理機能テストレポート</h1>
            <p>統合機能テスト結果 - {datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")}</p>
        </div>
        
        <div class="summary">
            <h2>📊 テスト結果サマリー</h2>
            <div class="summary-grid">
"""

        # 全体のサマリーを計算
        total_passed = 0
        total_failed = 0
        total_skipped = 0
        total_tests = 0

        for test_name, results in all_results.items():
            if "error" not in results and "summary" in results:
                summary = results["summary"]
                total_passed += summary.get("passed", 0)
                total_failed += summary.get("failed", 0)
                total_skipped += summary.get("skipped", 0)

        total_tests = total_passed + total_failed + total_skipped

        html_content += f"""
                <div class="summary-card">
                    <h3>✅ 成功</h3>
                    <div class="number pass">{total_passed}</div>
                </div>
                <div class="summary-card">
                    <h3>❌ 失敗</h3>
                    <div class="number fail">{total_failed}</div>
                </div>
                <div class="summary-card">
                    <h3>⏭️ スキップ</h3>
                    <div class="number skip">{total_skipped}</div>
                </div>
                <div class="summary-card">
                    <h3>📊 合計</h3>
                    <div class="number total">{total_tests}</div>
                </div>
            </div>
        </div>
"""

        # 各テストセクションの詳細
        for test_name, results in all_results.items():
            html_content += f"""
        <div class="test-section">
            <h2>{test_name}</h2>
"""

            if "error" in results:
                html_content += f"""
            <div class="error">
                <strong>エラー:</strong> {results["error"]}
            </div>
"""
            else:
                if "summary" in results:
                    summary = results["summary"]
                    html_content += f"""
            <p><strong>結果:</strong> 
               ✅ {summary.get("passed", 0)} 成功, 
               ❌ {summary.get("failed", 0)} 失敗, 
               ⏭️ {summary.get("skipped", 0)} スキップ
            </p>
"""

                if "results" in results:
                    for result in results["results"]:
                        status = result.get("status", "UNKNOWN").lower()
                        status_icon = (
                            "✅" if status == "pass" else "❌" if status == "fail" else "⏭️"
                        )

                        html_content += f"""
            <div class="test-result {status}">
                <h4><span class="status-icon">{status_icon}</span>{result.get("test", "Unknown Test")}</h4>
                <p>{result.get("message", "No message")}</p>
            </div>
"""

        html_content += f"""
        </div>
        
        <div class="timestamp">
            レポート生成日時: {datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")}
        </div>
    </div>
</body>
</html>
"""

        return html_content

    def generate_json_report(self, all_results):
        """JSON統合レポートを生成"""
        # 全体のサマリーを計算
        total_passed = 0
        total_failed = 0
        total_skipped = 0

        for test_name, results in all_results.items():
            if "error" not in results and "summary" in results:
                summary = results["summary"]
                total_passed += summary.get("passed", 0)
                total_failed += summary.get("failed", 0)
                total_skipped += summary.get("skipped", 0)

        integrated_report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "overall_summary": {
                "total_passed": total_passed,
                "total_failed": total_failed,
                "total_skipped": total_skipped,
                "total_tests": total_passed + total_failed + total_skipped,
                "success_rate": (
                    round((total_passed / (total_passed + total_failed + total_skipped)) * 100, 2)
                    if (total_passed + total_failed + total_skipped) > 0
                    else 0
                ),
            },
            "test_suites": all_results,
        }

        return integrated_report

    def generate_report(self):
        """統合レポートを生成"""
        print("🚀 スタイル管理機能統合テストレポート生成開始")
        print("=" * 60)

        # テスト結果を読み込み
        all_results = self.load_test_results()

        # HTMLレポートを生成
        html_content = self.generate_html_report(all_results)
        with open("style_manager_test_report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        print("✓ HTMLレポートを生成しました: style_manager_test_report.html")

        # JSON統合レポートを生成
        json_report = self.generate_json_report(all_results)
        with open("integrated_test_report.json", "w", encoding="utf-8") as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)
        print("✓ JSON統合レポートを生成しました: integrated_test_report.json")

        # サマリーを表示
        print("\n📊 統合テスト結果サマリー")
        print("=" * 60)
        overall = json_report["overall_summary"]
        print(f"✅ 成功: {overall['total_passed']}")
        print(f"❌ 失敗: {overall['total_failed']}")
        print(f"⏭️ スキップ: {overall['total_skipped']}")
        print(f"📊 合計: {overall['total_tests']}")
        print(f"📈 成功率: {overall['success_rate']}%")

        print(f"\n💾 詳細レポートファイル:")
        print(f"  - HTML: style_manager_test_report.html")
        print(f"  - JSON: integrated_test_report.json")


if __name__ == "__main__":
    generator = TestReportGenerator()
    generator.generate_report()
