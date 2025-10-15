"""
機械学習によるパターン認識とゲームロジック抽出システム
"""
import os
import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import pickle
import re
from collections import Counter, defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import joblib

logger = logging.getLogger(__name__)

class MLPatternRecognition:
    """機械学習によるパターン認識システム"""
    
    def __init__(self, model_dir: str = "data/ml_models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # 学習済みモデル
        self.models = {
            "api_classifier": None,
            "game_logic_extractor": None,
            "anomaly_detector": None,
            "pattern_clusterer": None
        }
        
        # 特徴量抽出器
        self.vectorizers = {
            "api_vectorizer": TfidfVectorizer(max_features=1000),
            "code_vectorizer": TfidfVectorizer(max_features=2000, ngram_range=(1, 3))
        }
        
        # スケーラー
        self.scalers = {
            "feature_scaler": StandardScaler(),
            "memory_scaler": StandardScaler()
        }
        
        # パターンデータベース
        self.pattern_database = {
            "common_patterns": [],
            "game_logic_patterns": [],
            "api_usage_patterns": [],
            "memory_patterns": []
        }
        
        self._load_models()
    
    def train_api_classifier(self, training_data: List[Dict]) -> bool:
        """API分類器の訓練"""
        try:
            if not training_data:
                logger.warning("訓練データが空です")
                return False
            
            # 特徴量とラベルの準備
            api_calls = [item["api_call"] for item in training_data]
            labels = [item["category"] for item in training_data]
            
            # テキスト特徴量の抽出
            X = self.vectorizers["api_vectorizer"].fit_transform(api_calls)
            
            # 分類器の訓練
            self.models["api_classifier"] = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            self.models["api_classifier"].fit(X, labels)
            
            # モデルの保存
            self._save_model("api_classifier")
            self._save_vectorizer("api_vectorizer")
            
            logger.info(f"API分類器を訓練しました（サンプル数: {len(training_data)}）")
            return True
            
        except Exception as e:
            logger.error(f"API分類器訓練エラー: {e}")
            return False
    
    def train_game_logic_extractor(self, code_samples: List[Dict]) -> bool:
        """ゲームロジック抽出器の訓練"""
        try:
            if not code_samples:
                logger.warning("コードサンプルが空です")
                return False
            
            # コード特徴量の抽出
            features = []
            labels = []
            
            for sample in code_samples:
                code_text = sample.get("code", "")
                is_game_logic = sample.get("is_game_logic", False)
                
                # コード特徴量の計算
                code_features = self._extract_code_features(code_text)
                features.append(code_features)
                labels.append(1 if is_game_logic else 0)
            
            # 特徴量の正規化
            X = self.scalers["feature_scaler"].fit_transform(features)
            
            # 分類器の訓練
            self.models["game_logic_extractor"] = RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                random_state=42
            )
            self.models["game_logic_extractor"].fit(X, labels)
            
            # モデルの保存
            self._save_model("game_logic_extractor")
            self._save_scaler("feature_scaler")
            
            logger.info(f"ゲームロジック抽出器を訓練しました（サンプル数: {len(code_samples)}）")
            return True
            
        except Exception as e:
            logger.error(f"ゲームロジック抽出器訓練エラー: {e}")
            return False
    
    def train_anomaly_detector(self, normal_behavior_data: List[Dict]) -> bool:
        """異常検知器の訓練"""
        try:
            if not normal_behavior_data:
                logger.warning("正常動作データが空です")
                return False
            
            # 動作特徴量の抽出
            features = []
            for data in normal_behavior_data:
                behavior_features = self._extract_behavior_features(data)
                features.append(behavior_features)
            
            # 特徴量の正規化
            X = self.scalers["memory_scaler"].fit_transform(features)
            
            # 異常検知器の訓練
            self.models["anomaly_detector"] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            self.models["anomaly_detector"].fit(X)
            
            # モデルの保存
            self._save_model("anomaly_detector")
            self._save_scaler("memory_scaler")
            
            logger.info(f"異常検知器を訓練しました（サンプル数: {len(normal_behavior_data)}）")
            return True
            
        except Exception as e:
            logger.error(f"異常検知器訓練エラー: {e}")
            return False
    
    def analyze_api_patterns(self, api_calls: List[str]) -> Dict:
        """API呼び出しパターンの解析"""
        try:
            if not api_calls:
                return {"patterns": [], "categories": {}}
            
            # API分類
            categories = {}
            if self.models["api_classifier"]:
                X = self.vectorizers["api_vectorizer"].transform(api_calls)
                predictions = self.models["api_classifier"].predict(X)
                probabilities = self.models["api_classifier"].predict_proba(X)
                
                for i, (api, category, prob) in enumerate(zip(api_calls, predictions, probabilities)):
                    categories[api] = {
                        "category": category,
                        "confidence": float(np.max(prob))
                    }
            
            # パターンクラスタリング
            patterns = self._cluster_api_patterns(api_calls)
            
            # 頻度分析
            frequency_analysis = self._analyze_api_frequency(api_calls)
            
            return {
                "patterns": patterns,
                "categories": categories,
                "frequency_analysis": frequency_analysis,
                "total_apis": len(api_calls),
                "unique_apis": len(set(api_calls))
            }
            
        except Exception as e:
            logger.error(f"APIパターン解析エラー: {e}")
            return {"patterns": [], "categories": {}}
    
    def extract_game_logic(self, code_data: List[Dict]) -> Dict:
        """ゲームロジックの抽出"""
        try:
            if not code_data:
                return {"game_logic_methods": [], "confidence_scores": {}}
            
            game_logic_methods = []
            confidence_scores = {}
            
            for code_item in code_data:
                method_name = code_item.get("method_name", "")
                code_text = code_item.get("code", "")
                
                if not code_text:
                    continue
                
                # コード特徴量の抽出
                code_features = self._extract_code_features(code_text)
                
                # ゲームロジック判定
                if self.models["game_logic_extractor"]:
                    X = self.scalers["feature_scaler"].transform([code_features])
                    prediction = self.models["game_logic_extractor"].predict(X)[0]
                    probability = self.models["game_logic_extractor"].predict_proba(X)[0]
                    
                    confidence = float(np.max(probability))
                    confidence_scores[method_name] = confidence
                    
                    if prediction == 1 and confidence > 0.7:
                        game_logic_methods.append({
                            "method_name": method_name,
                            "code": code_text,
                            "confidence": confidence,
                            "logic_type": self._classify_game_logic_type(code_text)
                        })
            
            # ゲームロジックの重要度順にソート
            game_logic_methods.sort(key=lambda x: x["confidence"], reverse=True)
            
            return {
                "game_logic_methods": game_logic_methods,
                "confidence_scores": confidence_scores,
                "total_methods": len(code_data),
                "game_logic_count": len(game_logic_methods)
            }
            
        except Exception as e:
            logger.error(f"ゲームロジック抽出エラー: {e}")
            return {"game_logic_methods": [], "confidence_scores": {}}
    
    def detect_anomalies(self, behavior_data: List[Dict]) -> Dict:
        """異常動作の検出"""
        try:
            if not behavior_data or not self.models["anomaly_detector"]:
                return {"anomalies": [], "anomaly_score": 0.0}
            
            # 動作特徴量の抽出
            features = []
            for data in behavior_data:
                behavior_features = self._extract_behavior_features(data)
                features.append(behavior_features)
            
            # 異常検知
            X = self.scalers["memory_scaler"].transform(features)
            anomaly_predictions = self.models["anomaly_detector"].predict(X)
            anomaly_scores = self.models["anomaly_detector"].decision_function(X)
            
            # 異常データの特定
            anomalies = []
            for i, (prediction, score, data) in enumerate(zip(anomaly_predictions, anomaly_scores, behavior_data)):
                if prediction == -1:  # 異常
                    anomalies.append({
                        "index": i,
                        "data": data,
                        "anomaly_score": float(score),
                        "timestamp": data.get("timestamp", "")
                    })
            
            return {
                "anomalies": anomalies,
                "anomaly_count": len(anomalies),
                "total_samples": len(behavior_data),
                "anomaly_rate": len(anomalies) / len(behavior_data) if behavior_data else 0.0
            }
            
        except Exception as e:
            logger.error(f"異常検知エラー: {e}")
            return {"anomalies": [], "anomaly_score": 0.0}
    
    def _extract_code_features(self, code_text: str) -> List[float]:
        """コードから特徴量を抽出"""
        features = []
        
        # 基本的な統計特徴量
        features.append(len(code_text))  # コード長
        features.append(len(code_text.split('\n')))  # 行数
        features.append(len(re.findall(r'\w+', code_text)))  # 単語数
        
        # キーワード頻度
        game_keywords = [
            'score', 'point', 'level', 'player', 'enemy', 'health', 'damage',
            'weapon', 'item', 'inventory', 'quest', 'mission', 'achievement',
            'collision', 'physics', 'animation', 'sound', 'music', 'effect'
        ]
        
        for keyword in game_keywords:
            count = len(re.findall(rf'\b{keyword}\b', code_text.lower()))
            features.append(count)
        
        # 制御構造の数
        features.append(len(re.findall(r'\bif\b', code_text)))
        features.append(len(re.findall(r'\bfor\b', code_text)))
        features.append(len(re.findall(r'\bwhile\b', code_text)))
        features.append(len(re.findall(r'\bswitch\b', code_text)))
        
        # 関数呼び出しの数
        features.append(len(re.findall(r'\w+\s*\(', code_text)))
        
        # 数値リテラルの数
        features.append(len(re.findall(r'\b\d+\.?\d*\b', code_text)))
        
        return features
    
    def _extract_behavior_features(self, behavior_data: Dict) -> List[float]:
        """動作データから特徴量を抽出"""
        features = []
        
        # メモリ使用量関連
        if "memory_usage" in behavior_data:
            memory = behavior_data["memory_usage"]
            features.extend([
                memory.get("percent", 0),
                memory.get("used", 0),
                memory.get("available", 0)
            ])
        else:
            features.extend([0, 0, 0])
        
        # API呼び出し頻度
        api_calls = behavior_data.get("api_calls", [])
        features.append(len(api_calls))
        
        # ネットワーク活動
        network = behavior_data.get("network_activity", {})
        features.extend([
            network.get("bytes_sent", 0),
            network.get("bytes_recv", 0),
            network.get("packets_sent", 0),
            network.get("packets_recv", 0)
        ])
        
        # ファイル操作数
        file_ops = behavior_data.get("file_operations", [])
        features.append(len(file_ops))
        
        # ゲームイベント数
        game_events = behavior_data.get("game_events", [])
        features.append(len(game_events))
        
        return features
    
    def _cluster_api_patterns(self, api_calls: List[str]) -> List[Dict]:
        """API呼び出しパターンのクラスタリング"""
        try:
            if len(api_calls) < 5:
                return []
            
            # API呼び出しの特徴量化
            X = self.vectorizers["api_vectorizer"].transform(api_calls)
            
            # クラスタリング
            n_clusters = min(5, len(set(api_calls)))
            kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            cluster_labels = kmeans.fit_predict(X)
            
            # クラスターごとのパターン分析
            patterns = []
            for cluster_id in range(n_clusters):
                cluster_apis = [api for i, api in enumerate(api_calls) if cluster_labels[i] == cluster_id]
                
                if cluster_apis:
                    pattern = {
                        "cluster_id": cluster_id,
                        "apis": cluster_apis,
                        "size": len(cluster_apis),
                        "representative_api": Counter(cluster_apis).most_common(1)[0][0],
                        "pattern_type": self._classify_api_pattern_type(cluster_apis)
                    }
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            logger.error(f"APIパターンクラスタリングエラー: {e}")
            return []
    
    def _analyze_api_frequency(self, api_calls: List[str]) -> Dict:
        """API呼び出し頻度の分析"""
        counter = Counter(api_calls)
        total_calls = len(api_calls)
        
        return {
            "most_frequent": counter.most_common(10),
            "total_unique": len(counter),
            "frequency_distribution": {
                api: count / total_calls for api, count in counter.items()
            }
        }
    
    def _classify_game_logic_type(self, code_text: str) -> str:
        """ゲームロジックのタイプ分類"""
        code_lower = code_text.lower()
        
        # スコア関連
        if any(keyword in code_lower for keyword in ['score', 'point', 'reward']):
            return "scoring"
        
        # 物理・衝突関連
        if any(keyword in code_lower for keyword in ['collision', 'physics', 'velocity', 'position']):
            return "physics"
        
        # プレイヤー制御関連
        if any(keyword in code_lower for keyword in ['player', 'input', 'control', 'move']):
            return "player_control"
        
        # AI・敵関連
        if any(keyword in code_lower for keyword in ['enemy', 'ai', 'behavior', 'patrol']):
            return "ai_behavior"
        
        # ゲーム状態管理
        if any(keyword in code_lower for keyword in ['state', 'level', 'stage', 'scene']):
            return "state_management"
        
        # UI関連
        if any(keyword in code_lower for keyword in ['ui', 'menu', 'button', 'display']):
            return "ui_logic"
        
        return "general"
    
    def _classify_api_pattern_type(self, api_calls: List[str]) -> str:
        """APIパターンのタイプ分類"""
        api_text = " ".join(api_calls).lower()
        
        if "render" in api_text or "draw" in api_text:
            return "rendering"
        elif "input" in api_text or "touch" in api_text:
            return "input_handling"
        elif "audio" in api_text or "sound" in api_text:
            return "audio"
        elif "network" in api_text or "http" in api_text:
            return "networking"
        elif "file" in api_text or "storage" in api_text:
            return "file_io"
        else:
            return "general"
    
    def _save_model(self, model_name: str):
        """モデルの保存"""
        if model_name in self.models and self.models[model_name]:
            model_path = self.model_dir / f"{model_name}.pkl"
            joblib.dump(self.models[model_name], model_path)
    
    def _save_vectorizer(self, vectorizer_name: str):
        """ベクタライザーの保存"""
        if vectorizer_name in self.vectorizers:
            vectorizer_path = self.model_dir / f"{vectorizer_name}.pkl"
            joblib.dump(self.vectorizers[vectorizer_name], vectorizer_path)
    
    def _save_scaler(self, scaler_name: str):
        """スケーラーの保存"""
        if scaler_name in self.scalers:
            scaler_path = self.model_dir / f"{scaler_name}.pkl"
            joblib.dump(self.scalers[scaler_name], scaler_path)
    
    def _load_models(self):
        """保存されたモデルの読み込み"""
        try:
            for model_name in self.models.keys():
                model_path = self.model_dir / f"{model_name}.pkl"
                if model_path.exists():
                    self.models[model_name] = joblib.load(model_path)
            
            for vectorizer_name in self.vectorizers.keys():
                vectorizer_path = self.model_dir / f"{vectorizer_name}.pkl"
                if vectorizer_path.exists():
                    self.vectorizers[vectorizer_name] = joblib.load(vectorizer_path)
            
            for scaler_name in self.scalers.keys():
                scaler_path = self.model_dir / f"{scaler_name}.pkl"
                if scaler_path.exists():
                    self.scalers[scaler_name] = joblib.load(scaler_path)
                    
        except Exception as e:
            logger.error(f"モデル読み込みエラー: {e}")
    
    def generate_training_data_from_analysis(self, analysis_results: List[Dict]) -> Dict:
        """解析結果から訓練データを生成"""
        try:
            training_data = {
                "api_training": [],
                "code_training": [],
                "behavior_training": []
            }
            
            for result in analysis_results:
                # API訓練データ
                if "api_calls" in result:
                    for api_call in result["api_calls"]:
                        training_data["api_training"].append({
                            "api_call": api_call.get("data", ""),
                            "category": self._infer_api_category(api_call.get("data", ""))
                        })
                
                # コード訓練データ
                if "extracted_methods" in result:
                    for method in result["extracted_methods"]:
                        training_data["code_training"].append({
                            "code": method.get("code", ""),
                            "method_name": method.get("name", ""),
                            "is_game_logic": self._infer_game_logic_label(method.get("code", ""))
                        })
                
                # 動作訓練データ
                if "monitoring_data" in result:
                    training_data["behavior_training"].append(result["monitoring_data"])
            
            return training_data
            
        except Exception as e:
            logger.error(f"訓練データ生成エラー: {e}")
            return {"api_training": [], "code_training": [], "behavior_training": []}
    
    def _infer_api_category(self, api_call: str) -> str:
        """API呼び出しのカテゴリを推測"""
        api_lower = api_call.lower()
        
        if any(keyword in api_lower for keyword in ['render', 'draw', 'graphics']):
            return "rendering"
        elif any(keyword in api_lower for keyword in ['input', 'touch', 'key']):
            return "input"
        elif any(keyword in api_lower for keyword in ['audio', 'sound', 'music']):
            return "audio"
        elif any(keyword in api_lower for keyword in ['network', 'http', 'request']):
            return "network"
        elif any(keyword in api_lower for keyword in ['file', 'storage', 'save']):
            return "storage"
        else:
            return "system"
    
    def _infer_game_logic_label(self, code: str) -> bool:
        """コードがゲームロジックかどうかを推測"""
        code_lower = code.lower()
        
        game_indicators = [
            'score', 'point', 'level', 'player', 'enemy', 'health', 'damage',
            'collision', 'physics', 'game', 'play', 'win', 'lose', 'achievement'
        ]
        
        return any(indicator in code_lower for indicator in game_indicators)
    
    def auto_train_from_analysis_results(self, analysis_results_dir: str) -> bool:
        """解析結果から自動的にモデルを訓練"""
        try:
            results_path = Path(analysis_results_dir)
            if not results_path.exists():
                logger.warning(f"解析結果ディレクトリが存在しません: {analysis_results_dir}")
                return False
            
            # 解析結果ファイルの読み込み
            analysis_results = []
            for result_file in results_path.glob("*.json"):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                        analysis_results.append(result_data)
                except Exception as e:
                    logger.error(f"結果ファイル読み込みエラー {result_file}: {e}")
            
            if not analysis_results:
                logger.warning("有効な解析結果が見つかりません")
                return False
            
            # 訓練データの生成
            training_data = self.generate_training_data_from_analysis(analysis_results)
            
            # モデルの訓練
            success_count = 0
            
            if training_data["api_training"]:
                if self.train_api_classifier(training_data["api_training"]):
                    success_count += 1
            
            if training_data["code_training"]:
                if self.train_game_logic_extractor(training_data["code_training"]):
                    success_count += 1
            
            if training_data["behavior_training"]:
                if self.train_anomaly_detector(training_data["behavior_training"]):
                    success_count += 1
            
            logger.info(f"自動訓練完了: {success_count}個のモデルを訓練しました")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"自動訓練エラー: {e}")
            return False