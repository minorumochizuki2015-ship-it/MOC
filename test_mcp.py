#!/usr/bin/env python3
"""MCP認証テスト用スクリプト"""

import os
import sys
sys.path.insert(0, '.')

from src.dashboard import app

def test_mcp_auth():
    print(f"ORCH_MCP_TOKEN in environment: {repr(os.environ.get('ORCH_MCP_TOKEN'))}")
    
    with app.test_client() as client:
        response = client.get('/mcp/ping')
        print(f"Status: {response.status_code}")
        print(f"Data: {response.get_json()}")
        print(f"Headers: {dict(response.headers)}")

if __name__ == "__main__":
    test_mcp_auth()