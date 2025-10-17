#!/usr/bin/env python3
"""
Trae Intake API Server
データ受信用の軽量HTTPサーバー
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from flask import Flask, request, jsonify

app = Flask(__name__)

# 設定
INTAKE_DIR = Path("data/intake/accepted")
INTAKE_DIR.mkdir(parents=True, exist_ok=True)

@app.route('/intake/post', methods=['POST'])
def intake_post():
    """Traeからのデータを受信"""
    try:
        data = request.get_json()
        
        # 必須フィールドの検証
        required_fields = ['source', 'title', 'domain', 'task_type', 'success', 'prompt', 'output']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # プロンプト長チェック
        if len(data['prompt']) < 16:
            return jsonify({'error': 'Prompt must be at least 16 characters'}), 400
        
        # タイムスタンプ追加
        data['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        data['intake_id'] = str(uuid.uuid4())
        
        # ファイル保存
        filename = f"trae_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}.json"
        filepath = INTAKE_DIR / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return jsonify({
            'status': 'success',
            'intake_id': data['intake_id'],
            'filename': filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/intake/status', methods=['GET'])
def intake_status():
    """システム状態を返す"""
    return jsonify({
        'status': 'running',
        'intake_dir': str(INTAKE_DIR),
        'server': 'trae-intake-api',
        'version': '1.0.0'
    })

if __name__ == '__main__':
    port = int(os.environ.get('INTAKE_PORT', 8787))
    app.run(host='127.0.0.1', port=port, debug=False)