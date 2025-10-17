"""
MobSF統合モジュール - CompleteCloneGeneratorへの機能拡張
"""
import os
import json
import logging
import requests
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib

logger = logging.getLogger(__name__)

class MobSFIntegration:
    """MobSF機能をCompleteCloneGeneratorに統合するクラス"""
    
    def __init__(self, mobsf_url: str = "http://localhost:8000", api_key: str = None):
        self.mobsf_url = mobsf_url.rstrip('/')
        self.api_key = api_key or os.getenv('MOBSF_API_KEY', '')
        self.session = requests.Session()
        
        # APIヘッダーの設定
        if self.api_key:
            self.session.headers.update({
                'Authorization': self.api_key,
                'Content-Type': 'application/json'
            })
    
    def enhanced_static_analysis(self, apk_path: str) -> Dict[str, Any]:
        """MobSFを使用した拡張静的解析"""
        try:
            logger.info(f"MobSF拡張静的解析を開始: {apk_path}")
            
            # APKファイルをMobSFにアップロード
            upload_result = self._upload_file(apk_path)
            if not upload_result.get('success'):
                return self._fallback_static_analysis(apk_path)
            
            file_hash = upload_result['hash']
            
            # 静的解析を実行
            scan_result = self._perform_static_scan(file_hash)
            if not scan_result.get('success'):
                return self._fallback_static_analysis(apk_path)
            
            # 詳細レポートを取得
            report_data = self._get_detailed_report(file_hash)
            
            # CompleteCloneGenerator用にデータを変換
            enhanced_data = self._transform_mobsf_data(report_data)
            
            return {
                'success': True,
                'source': 'mobsf_enhanced',
                'data': enhanced_data,
                'raw_mobsf_data': report_data
            }
            
        except Exception as e:
            logger.warning(f"MobSF拡張解析エラー: {str(e)}")
            return self._fallback_static_analysis(apk_path)
    
    def security_vulnerability_analysis(self, apk_path: str) -> Dict[str, Any]:
        """セキュリティ脆弱性解析"""
        try:
            upload_result = self._upload_file(apk_path)
            if not upload_result.get('success'):
                return {'success': False, 'vulnerabilities': []}
            
            file_hash = upload_result['hash']
            scan_result = self._perform_static_scan(file_hash)
            
            if scan_result.get('success'):
                report_data = self._get_detailed_report(file_hash)
                vulnerabilities = self._extract_vulnerabilities(report_data)
                
                return {
                    'success': True,
                    'vulnerabilities': vulnerabilities,
                    'security_score': self._calculate_security_score(vulnerabilities)
                }
            
            return {'success': False, 'vulnerabilities': []}
            
        except Exception as e:
            logger.error(f"セキュリティ解析エラー: {str(e)}")
            return {'success': False, 'vulnerabilities': [], 'error': str(e)}
    
    def code_quality_analysis(self, apk_path: str) -> Dict[str, Any]:
        """コード品質解析"""
        try:
            upload_result = self._upload_file(apk_path)
            if not upload_result.get('success'):
                return {'success': False, 'quality_metrics': {}}
            
            file_hash = upload_result['hash']
            scan_result = self._perform_static_scan(file_hash)
            
            if scan_result.get('success'):
                report_data = self._get_detailed_report(file_hash)
                quality_metrics = self._extract_code_quality(report_data)
                
                return {
                    'success': True,
                    'quality_metrics': quality_metrics,
                    'recommendations': self._generate_quality_recommendations(quality_metrics)
                }
            
            return {'success': False, 'quality_metrics': {}}
            
        except Exception as e:
            logger.error(f"コード品質解析エラー: {str(e)}")
            return {'success': False, 'quality_metrics': {}, 'error': str(e)}
    
    def _upload_file(self, file_path: str) -> Dict[str, Any]:
        """ファイルをMobSFにアップロード"""
        try:
            upload_url = f"{self.mobsf_url}/api/v1/upload"
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                
                # Content-Typeヘッダーを一時的に削除（multipart/form-dataのため）
                headers = dict(self.session.headers)
                if 'Content-Type' in headers:
                    del headers['Content-Type']
                
                response = requests.post(upload_url, files=files, headers=headers)
                
                if response.status_code == 200:
                    result = response.json()
                    return {
                        'success': True,
                        'hash': result.get('hash'),
                        'scan_type': result.get('scan_type')
                    }
                else:
                    logger.error(f"アップロード失敗: {response.status_code}")
                    return {'success': False, 'error': f"HTTP {response.status_code}"}
                    
        except Exception as e:
            logger.error(f"ファイルアップロードエラー: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _perform_static_scan(self, file_hash: str) -> Dict[str, Any]:
        """静的スキャンを実行"""
        try:
            scan_url = f"{self.mobsf_url}/api/v1/scan"
            data = {
                'hash': file_hash,
                'scan_type': 'apk'
            }
            
            response = self.session.post(scan_url, json=data)
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
                
        except Exception as e:
            logger.error(f"静的スキャンエラー: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_detailed_report(self, file_hash: str) -> Dict[str, Any]:
        """詳細レポートを取得"""
        try:
            report_url = f"{self.mobsf_url}/api/v1/report_json"
            data = {'hash': file_hash}
            
            response = self.session.post(report_url, json=data)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"レポート取得失敗: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"レポート取得エラー: {str(e)}")
            return {}
    
    def _transform_mobsf_data(self, mobsf_data: Dict) -> Dict[str, Any]:
        """MobSFデータをCompleteCloneGenerator形式に変換"""
        transformed = {
            'app_info': {
                'package_name': mobsf_data.get('packagename', ''),
                'app_name': mobsf_data.get('appname', ''),
                'version_name': mobsf_data.get('version_name', ''),
                'version_code': mobsf_data.get('version_code', ''),
                'min_sdk': mobsf_data.get('min_sdk', ''),
                'target_sdk': mobsf_data.get('target_sdk', ''),
                'max_sdk': mobsf_data.get('max_sdk', '')
            },
            'permissions': mobsf_data.get('permissions', {}),
            'activities': mobsf_data.get('activities', []),
            'services': mobsf_data.get('services', []),
            'receivers': mobsf_data.get('receivers', []),
            'providers': mobsf_data.get('providers', []),
            'libraries': mobsf_data.get('libraries', []),
            'certificate_info': mobsf_data.get('certificate_analysis', {}),
            'network_security': mobsf_data.get('network_security', {}),
            'code_analysis': {
                'findings': mobsf_data.get('code_analysis', {}),
                'urls': mobsf_data.get('urls', []),
                'domains': mobsf_data.get('domains', []),
                'emails': mobsf_data.get('emails', [])
            },
            'file_analysis': mobsf_data.get('file_analysis', {}),
            'android_api': mobsf_data.get('android_api', {}),
            'trackers': mobsf_data.get('trackers', {}),
            'playstore_details': mobsf_data.get('playstore_details', {})
        }
        
        return transformed
    
    def _extract_vulnerabilities(self, report_data: Dict) -> List[Dict]:
        """脆弱性情報を抽出"""
        vulnerabilities = []
        
        # コード解析からの脆弱性
        code_analysis = report_data.get('code_analysis', {})
        for category, findings in code_analysis.items():
            if isinstance(findings, list):
                for finding in findings:
                    if isinstance(finding, dict) and finding.get('severity'):
                        vulnerabilities.append({
                            'category': category,
                            'title': finding.get('title', ''),
                            'severity': finding.get('severity', 'info'),
                            'description': finding.get('description', ''),
                            'file': finding.get('file', ''),
                            'line': finding.get('line', 0)
                        })
        
        # 権限関連の脆弱性
        permissions = report_data.get('permissions', {})
        dangerous_permissions = permissions.get('dangerous', [])
        for perm in dangerous_permissions:
            vulnerabilities.append({
                'category': 'permissions',
                'title': f'Dangerous Permission: {perm}',
                'severity': 'medium',
                'description': f'App requests dangerous permission: {perm}',
                'file': 'AndroidManifest.xml',
                'line': 0
            })
        
        return vulnerabilities
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """セキュリティスコアを計算"""
        if not vulnerabilities:
            return 100
        
        score = 100
        severity_weights = {
            'critical': 20,
            'high': 15,
            'medium': 10,
            'low': 5,
            'info': 2
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            score -= severity_weights.get(severity, 2)
        
        return max(0, score)
    
    def _extract_code_quality(self, report_data: Dict) -> Dict[str, Any]:
        """コード品質メトリクスを抽出"""
        quality_metrics = {
            'total_files': 0,
            'code_lines': 0,
            'complexity_score': 0,
            'maintainability_index': 0,
            'technical_debt_ratio': 0,
            'code_smells': [],
            'duplicated_code_blocks': 0
        }
        
        # ファイル解析から品質情報を抽出
        file_analysis = report_data.get('file_analysis', {})
        if isinstance(file_analysis, dict):
            quality_metrics['total_files'] = len(file_analysis)
        
        # コード解析から品質問題を抽出
        code_analysis = report_data.get('code_analysis', {})
        code_smells = []
        
        for category, findings in code_analysis.items():
            if 'quality' in category.lower() or 'smell' in category.lower():
                if isinstance(findings, list):
                    code_smells.extend(findings)
        
        quality_metrics['code_smells'] = code_smells
        quality_metrics['maintainability_index'] = max(0, 100 - len(code_smells) * 5)
        
        return quality_metrics
    
    def _generate_quality_recommendations(self, quality_metrics: Dict) -> List[str]:
        """品質改善推奨事項を生成"""
        recommendations = []
        
        if quality_metrics.get('maintainability_index', 100) < 70:
            recommendations.append("コードの保守性を向上させるためのリファクタリングを検討してください")
        
        if len(quality_metrics.get('code_smells', [])) > 10:
            recommendations.append("コードスメルの修正を優先的に行ってください")
        
        if quality_metrics.get('technical_debt_ratio', 0) > 0.3:
            recommendations.append("技術的負債の削減に取り組んでください")
        
        recommendations.extend([
            "単体テストのカバレッジを向上させてください",
            "コードレビュープロセスを強化してください",
            "静的解析ツールを継続的に使用してください"
        ])
        
        return recommendations
    
    def _fallback_static_analysis(self, apk_path: str) -> Dict[str, Any]:
        """MobSF利用不可時のフォールバック解析"""
        logger.info("MobSF利用不可のため、基本的な静的解析を実行")
        
        try:
            import zipfile
            
            basic_analysis = {
                'success': True,
                'source': 'fallback_basic',
                'data': {
                    'app_info': {'package_name': 'unknown'},
                    'permissions': {},
                    'activities': [],
                    'services': [],
                    'file_count': 0
                }
            }
            
            # APKファイルの基本情報を取得
            with zipfile.ZipFile(apk_path, 'r') as apk:
                file_list = apk.namelist()
                basic_analysis['data']['file_count'] = len(file_list)
                
                # AndroidManifest.xmlの存在確認
                if 'AndroidManifest.xml' in file_list:
                    basic_analysis['data']['manifest_found'] = True
                
                # classes.dexの存在確認
                dex_files = [f for f in file_list if f.endswith('.dex')]
                basic_analysis['data']['dex_files'] = len(dex_files)
            
            return basic_analysis
            
        except Exception as e:
            logger.error(f"フォールバック解析エラー: {str(e)}")
            return {
                'success': False,
                'source': 'fallback_failed',
                'error': str(e)
            }
    
    def is_mobsf_available(self) -> bool:
        """MobSFサーバーの可用性をチェック"""
        try:
            response = requests.get(f"{self.mobsf_url}/api/v1/health", timeout=5)
            return response.status_code == 200
        except:
            return False