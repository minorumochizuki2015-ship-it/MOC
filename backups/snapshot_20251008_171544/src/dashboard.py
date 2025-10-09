"""
品質監視ダッシュボード
AI予測結果とメトリクスの可視化
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

import pandas as pd
from flask import Flask, jsonify, render_template_string

from src.ai_prediction import QualityPredictor

app = Flask(__name__)


class QualityDashboard:
    """品質ダッシュボードクラス"""

    def __init__(self, db_path: str = "data/quality_metrics.db"):
        self.db_path = Path(db_path)
        self.predictor = QualityPredictor(db_path)

    def get_recent_metrics(self, days: int = 7) -> List[Dict]:
        """最近のメトリクス取得"""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query(
                """
                SELECT * FROM quality_metrics
                WHERE datetime(timestamp) >= datetime('now', '-{} days')
                ORDER BY timestamp DESC
            """.format(
                    days
                ),
                conn,
            )

        return df.to_dict("records")

    def get_prediction_summary(self) -> Dict:
        """予測サマリー取得"""
        try:
            if not self.predictor.is_trained:
                self.predictor.train_model()

            # 最新メトリクスで予測
            recent_data = self.get_recent_metrics(1)
            if not recent_data:
                return {"error": "No recent data available"}

            latest = recent_data[0]
            metrics = {
                "test_coverage": latest["test_coverage"],
                "code_complexity": latest["code_complexity"],
                "error_rate": latest["error_rate"],
                "performance_score": latest["performance_score"],
            }

            prediction = self.predictor.predict_quality_issue(metrics)

            return {
                "current_metrics": metrics,
                "prediction": prediction,
                "feature_importance": self.predictor.get_feature_importance(),
            }
        except Exception as e:
            return {"error": str(e)}

    def get_trend_data(self, days: int = 30) -> Dict:
        """トレンドデータ取得"""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query(
                """
                SELECT 
                    DATE(timestamp) as date,
                    AVG(test_coverage) as avg_coverage,
                    AVG(code_complexity) as avg_complexity,
                    AVG(error_rate) as avg_error_rate,
                    AVG(performance_score) as avg_performance,
                    SUM(quality_issue) as issue_count,
                    COUNT(*) as total_count
                FROM quality_metrics
                WHERE datetime(timestamp) >= datetime('now', '-{} days')
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            """.format(
                    days
                ),
                conn,
            )

        return {
            "dates": df["date"].tolist(),
            "coverage_trend": df["avg_coverage"].tolist(),
            "complexity_trend": df["avg_complexity"].tolist(),
            "error_trend": df["avg_error_rate"].tolist(),
            "performance_trend": df["avg_performance"].tolist(),
            "issue_rate": (df["issue_count"] / df["total_count"]).tolist(),
        }


# Flask routes
@app.route("/")
def dashboard():
    """メインダッシュボード"""
    dashboard_obj = QualityDashboard()

    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ORCH-Next Quality Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
            .metric-card { text-align: center; padding: 15px; border-radius: 8px; }
            .metric-value { font-size: 2em; font-weight: bold; margin: 10px 0; }
            .good { background: #d4edda; color: #155724; }
            .warning { background: #fff3cd; color: #856404; }
            .danger { background: #f8d7da; color: #721c24; }
            .chart-container { position: relative; height: 400px; margin: 20px 0; }
            .prediction-box { border-left: 4px solid #007bff; padding: 15px; background: #f8f9fa; }
            .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
            .status-normal { background: #28a745; }
            .status-issue { background: #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎯 ORCH-Next Quality Dashboard</h1>
                <p>AI予測機能による品質監視システム</p>
            </div>
            
            <div class="card">
                <h2>📊 現在の品質状況</h2>
                <div id="current-status">Loading...</div>
            </div>
            
            <div class="card">
                <h2>📈 品質トレンド (30日間)</h2>
                <div class="chart-container">
                    <canvas id="trendChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>🤖 AI予測結果</h2>
                <div id="prediction-results">Loading...</div>
            </div>
            
            <div class="card">
                <h2>📋 最近のメトリクス</h2>
                <div id="recent-metrics">Loading...</div>
            </div>
        </div>
        
        <script>
            // データ取得と表示
            async function loadDashboard() {
                try {
                    // 予測サマリー取得
                    const predictionResponse = await fetch('/api/prediction');
                    const predictionData = await predictionResponse.json();
                    displayPrediction(predictionData);
                    
                    // トレンドデータ取得
                    const trendResponse = await fetch('/api/trends');
                    const trendData = await trendResponse.json();
                    displayTrends(trendData);
                    
                    // 最近のメトリクス取得
                    const metricsResponse = await fetch('/api/metrics');
                    const metricsData = await metricsResponse.json();
                    displayMetrics(metricsData);
                    
                } catch (error) {
                    console.error('Error loading dashboard:', error);
                }
            }
            
            function displayPrediction(data) {
                const container = document.getElementById('prediction-results');
                
                if (data.error) {
                    container.innerHTML = `<div class="danger">Error: ${data.error}</div>`;
                    return;
                }
                
                const prediction = data.prediction;
                const statusClass = prediction.prediction === 0 ? 'good' : 'danger';
                const statusText = prediction.prediction === 0 ? '正常' : '問題あり';
                const statusIcon = prediction.prediction === 0 ? 'status-normal' : 'status-issue';
                
                container.innerHTML = `
                    <div class="prediction-box">
                        <h3><span class="status-indicator ${statusIcon}"></span>予測結果: ${statusText}</h3>
                        <p><strong>信頼度:</strong> ${(prediction.confidence * 100).toFixed(1)}%</p>
                        <p><strong>推奨アクション:</strong> ${prediction.recommendation}</p>
                    </div>
                    
                    <div class="metrics-grid">
                        <div class="metric-card ${data.current_metrics.test_coverage >= 0.8 ? 'good' : 'warning'}">
                            <div>テストカバレッジ</div>
                            <div class="metric-value">${(data.current_metrics.test_coverage * 100).toFixed(1)}%</div>
                        </div>
                        <div class="metric-card ${data.current_metrics.code_complexity <= 3.0 ? 'good' : 'warning'}">
                            <div>コード複雑度</div>
                            <div class="metric-value">${data.current_metrics.code_complexity.toFixed(2)}</div>
                        </div>
                        <div class="metric-card ${data.current_metrics.error_rate <= 0.05 ? 'good' : 'danger'}">
                            <div>エラー率</div>
                            <div class="metric-value">${(data.current_metrics.error_rate * 100).toFixed(2)}%</div>
                        </div>
                        <div class="metric-card ${data.current_metrics.performance_score >= 0.8 ? 'good' : 'warning'}">
                            <div>パフォーマンス</div>
                            <div class="metric-value">${(data.current_metrics.performance_score * 100).toFixed(1)}%</div>
                        </div>
                    </div>
                `;
            }
            
            function displayTrends(data) {
                const ctx = document.getElementById('trendChart').getContext('2d');
                
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.dates.reverse(),
                        datasets: [
                            {
                                label: 'テストカバレッジ',
                                data: data.coverage_trend.reverse(),
                                borderColor: '#28a745',
                                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'パフォーマンス',
                                data: data.performance_trend.reverse(),
                                borderColor: '#007bff',
                                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'エラー率',
                                data: data.error_trend.reverse(),
                                borderColor: '#dc3545',
                                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 1
                            }
                        }
                    }
                });
            }
            
            function displayMetrics(data) {
                const container = document.getElementById('recent-metrics');
                
                if (data.length === 0) {
                    container.innerHTML = '<p>No recent metrics available</p>';
                    return;
                }
                
                const tableRows = data.slice(0, 10).map(metric => `
                    <tr>
                        <td>${new Date(metric.timestamp).toLocaleString()}</td>
                        <td>${(metric.test_coverage * 100).toFixed(1)}%</td>
                        <td>${metric.code_complexity.toFixed(2)}</td>
                        <td>${(metric.error_rate * 100).toFixed(2)}%</td>
                        <td>${(metric.performance_score * 100).toFixed(1)}%</td>
                        <td><span class="status-indicator ${metric.quality_issue ? 'status-issue' : 'status-normal'}"></span></td>
                    </tr>
                `).join('');
                
                container.innerHTML = `
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f8f9fa;">
                                <th style="padding: 10px; border: 1px solid #ddd;">時刻</th>
                                <th style="padding: 10px; border: 1px solid #ddd;">カバレッジ</th>
                                <th style="padding: 10px; border: 1px solid #ddd;">複雑度</th>
                                <th style="padding: 10px; border: 1px solid #ddd;">エラー率</th>
                                <th style="padding: 10px; border: 1px solid #ddd;">パフォーマンス</th>
                                <th style="padding: 10px; border: 1px solid #ddd;">状態</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${tableRows}
                        </tbody>
                    </table>
                `;
            }
            
            // 初期読み込み
            loadDashboard();
            
            // 30秒ごとに更新
            setInterval(loadDashboard, 30000);
        </script>
    </body>
    </html>
    """

    return render_template_string(template)


@app.route("/api/prediction")
def api_prediction():
    """予測API"""
    dashboard_obj = QualityDashboard()
    return jsonify(dashboard_obj.get_prediction_summary())


@app.route("/api/trends")
def api_trends():
    """トレンドAPI"""
    dashboard_obj = QualityDashboard()
    return jsonify(dashboard_obj.get_trend_data())


@app.route("/api/metrics")
def api_metrics():
    """メトリクスAPI"""
    dashboard_obj = QualityDashboard()
    return jsonify(dashboard_obj.get_recent_metrics())


@app.route("/health")
def health():
    """ダッシュボードの健全性チェック"""
    status = {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "db": False,
        "predictor_ready": False,
        "version": "v1",
    }
    # DB接続確認
    try:
        db_path = Path("data/quality_metrics.db")
        if db_path.exists():
            with sqlite3.connect(db_path.as_posix()) as conn:
                conn.execute("SELECT 1")
            status["db"] = True
        else:
            status["db"] = False
    except Exception:
        status["db"] = False

    # 予測器初期化確認
    try:
        qp = QualityPredictor()
        status["predictor_ready"] = True if qp is not None else False
    except Exception:
        status["predictor_ready"] = False

    return jsonify(status), (200 if status["db"] else 503)


def main():
    """メイン実行関数"""
    print("Starting Quality Dashboard...")
    print("Access: http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
