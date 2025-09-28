#!/usr/bin/env python3
"""モバイルプレビュー用Webサーバー"""

import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Dict, Any, Optional
import asyncio
import threading
import time

# FastAPI関連のインポート
try:
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ImportError:
    print("❌ FastAPIまたはuvicornがインストールされていません")
    print("以下のコマンドでインストールしてください:")
    print("pip install fastapi uvicorn")
    sys.exit(1)

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from src.ui.mobile_adapter import MobileAdapter, ResponsiveLayout
    from src.core.kernel import Kernel
except ImportError as e:
    print(f"❌ モジュールのインポートに失敗: {e}")
    print("プロジェクト構造を確認してください")
    sys.exit(1)

# FastAPIアプリケーション
app = FastAPI(title="MOC Mobile Preview", version="1.0.0")

# グローバル変数
mobile_adapter: Optional[MobileAdapter] = None
kernel: Optional[Kernel] = None
connected_clients = set()

def get_mobile_html() -> str:
    """モバイル最適化HTMLを生成"""
    return """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>MOC - モバイルプレビュー</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 10px;
            color: white;
        }
        
        .container {
            max-width: 100%;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .title {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.8;
        }
        
        .game-area {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 15px;
            padding: 30px;
            margin: 20px 0;
            text-align: center;
            min-height: 300px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        
        .game-button {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            border: none;
            border-radius: 50px;
            padding: 20px 40px;
            font-size: 1.5em;
            font-weight: bold;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            margin: 10px;
            min-width: 200px;
            min-height: 60px;
        }
        
        .game-button:hover, .game-button:active {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
        }
        
        .game-button:active {
            transform: translateY(0);
        }
        
        .status {
            margin: 20px 0;
            padding: 15px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            font-size: 1.1em;
        }
        
        .controls {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-top: 20px;
        }
        
        .control-button {
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 15px;
            padding: 15px;
            color: white;
            font-size: 1.1em;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .control-button:hover, .control-button:active {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            opacity: 0.7;
            font-size: 0.9em;
        }
        
        /* レスポンシブ対応 */
        @media (max-width: 480px) {
            .title {
                font-size: 2em;
            }
            
            .game-button {
                font-size: 1.3em;
                padding: 15px 30px;
                min-width: 180px;
            }
            
            .controls {
                grid-template-columns: 1fr;
            }
        }
        
        /* タッチフィードバック */
        .touch-feedback {
            animation: pulse 0.3s ease-in-out;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">はい！ドーン！</div>
            <div class="subtitle">モバイル版プレビュー</div>
        </div>
        
        <div class="game-area">
            <div class="status" id="status">
                ゲームを開始する準備ができました！
            </div>
            
            <button class="game-button" id="startButton" onclick="startGame()">
                🎮 ゲーム開始
            </button>
            
            <button class="game-button" id="actionButton" onclick="performAction()" style="display: none;">
                ⚡ アクション！
            </button>
        </div>
        
        <div class="controls">
            <button class="control-button" onclick="showSettings()">
                ⚙️ 設定
            </button>
            <button class="control-button" onclick="showStats()">
                📊 統計
            </button>
            <button class="control-button" onclick="showHelp()">
                ❓ ヘルプ
            </button>
            <button class="control-button" onclick="resetGame()">
                🔄 リセット
            </button>
        </div>
        
        <div class="footer">
            MOC Mobile Preview v1.0<br>
            タッチ操作最適化済み
        </div>
    </div>

    <script>
        let gameState = 'ready';
        let ws = null;
        
        // WebSocket接続
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function(event) {
                console.log('WebSocket接続成功');
                updateStatus('サーバーに接続しました');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleServerMessage(data);
            };
            
            ws.onclose = function(event) {
                console.log('WebSocket接続終了');
                updateStatus('サーバーとの接続が切断されました');
                setTimeout(connectWebSocket, 3000); // 3秒後に再接続
            };
            
            ws.onerror = function(error) {
                console.error('WebSocketエラー:', error);
                updateStatus('接続エラーが発生しました');
            };
        }
        
        function sendMessage(message) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
        }
        
        function handleServerMessage(data) {
            if (data.type === 'status_update') {
                updateStatus(data.message);
            } else if (data.type === 'game_state') {
                gameState = data.state;
                updateUI();
            }
        }
        
        function updateStatus(message) {
            document.getElementById('status').textContent = message;
        }
        
        function updateUI() {
            const startButton = document.getElementById('startButton');
            const actionButton = document.getElementById('actionButton');
            
            if (gameState === 'ready') {
                startButton.style.display = 'block';
                actionButton.style.display = 'none';
            } else if (gameState === 'playing') {
                startButton.style.display = 'none';
                actionButton.style.display = 'block';
            }
        }
        
        function startGame() {
            addTouchFeedback(event.target);
            gameState = 'playing';
            updateStatus('ゲーム開始！タイミングを見計らってアクションボタンを押してください');
            updateUI();
            
            sendMessage({
                type: 'game_action',
                action: 'start'
            });
        }
        
        function performAction() {
            addTouchFeedback(event.target);
            updateStatus('アクション実行！');
            
            sendMessage({
                type: 'game_action',
                action: 'perform'
            });
        }
        
        function showSettings() {
            addTouchFeedback(event.target);
            updateStatus('設定画面（開発中）');
        }
        
        function showStats() {
            addTouchFeedback(event.target);
            updateStatus('統計画面（開発中）');
        }
        
        function showHelp() {
            addTouchFeedback(event.target);
            updateStatus('ヘルプ: タイミングゲームです。適切なタイミングでアクションボタンを押してください！');
        }
        
        function resetGame() {
            addTouchFeedback(event.target);
            gameState = 'ready';
            updateStatus('ゲームをリセットしました');
            updateUI();
            
            sendMessage({
                type: 'game_action',
                action: 'reset'
            });
        }
        
        function addTouchFeedback(element) {
            element.classList.add('touch-feedback');
            setTimeout(() => {
                element.classList.remove('touch-feedback');
            }, 300);
        }
        
        // タッチイベントの最適化
        document.addEventListener('touchstart', function(e) {
            // タッチ開始時の処理
        }, { passive: true });
        
        document.addEventListener('touchend', function(e) {
            // タッチ終了時の処理
        }, { passive: true });
        
        // ページ読み込み時にWebSocket接続
        window.addEventListener('load', function() {
            connectWebSocket();
            updateStatus('モバイルプレビューが読み込まれました');
        });
        
        // ページの向き変更対応
        window.addEventListener('orientationchange', function() {
            setTimeout(() => {
                updateStatus('画面の向きが変更されました');
            }, 100);
        });
    </script>
</body>
</html>
    """

@app.get("/", response_class=HTMLResponse)
async def get_mobile_preview():
    """モバイルプレビューページを返す"""
    return get_mobile_html()

@app.get("/api/status")
async def get_status():
    """システム状態を返す"""
    return JSONResponse({
        "status": "running",
        "mobile_adapter": mobile_adapter is not None,
        "kernel": kernel is not None,
        "connected_clients": len(connected_clients),
        "timestamp": time.time()
    })

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket接続処理"""
    await websocket.accept()
    connected_clients.add(websocket)
    
    try:
        # 接続通知
        await websocket.send_json({
            "type": "status_update",
            "message": "WebSocket接続が確立されました"
        })
        
        while True:
            # クライアントからのメッセージを受信
            data = await websocket.receive_json()
            
            # メッセージ処理
            if data.get("type") == "game_action":
                action = data.get("action")
                
                if action == "start":
                    await websocket.send_json({
                        "type": "game_state",
                        "state": "playing"
                    })
                    await websocket.send_json({
                        "type": "status_update",
                        "message": "ゲームが開始されました！"
                    })
                
                elif action == "perform":
                    await websocket.send_json({
                        "type": "status_update",
                        "message": "アクション実行！ナイスタイミング！"
                    })
                
                elif action == "reset":
                    await websocket.send_json({
                        "type": "game_state",
                        "state": "ready"
                    })
                    await websocket.send_json({
                        "type": "status_update",
                        "message": "ゲームがリセットされました"
                    })
    
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        print(f"クライアントが切断されました。残り接続数: {len(connected_clients)}")

def initialize_components():
    """コンポーネントの初期化"""
    global mobile_adapter, kernel
    
    try:
        # ダミーのTkinterルートを作成（実際のUIは使用しない）
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # ウィンドウを非表示
        
        # MobileAdapterの初期化
        mobile_adapter = MobileAdapter(root)
        print("✓ MobileAdapter初期化完了")
        
        # Kernelの初期化（可能であれば）
        try:
            kernel = Kernel()
            print("✓ Kernel初期化完了")
        except Exception as e:
            print(f"⚠️ Kernel初期化失敗: {e}")
            kernel = None
        
    except Exception as e:
        print(f"❌ コンポーネント初期化エラー: {e}")

def open_browser(url: str, delay: float = 2.0):
    """ブラウザを自動で開く"""
    def open_after_delay():
        time.sleep(delay)
        try:
            webbrowser.open(url)
            print(f"✓ ブラウザでプレビューを開きました: {url}")
        except Exception as e:
            print(f"⚠️ ブラウザの自動起動に失敗: {e}")
    
    thread = threading.Thread(target=open_after_delay, daemon=True)
    thread.start()

def main():
    """メイン関数"""
    print("🚀 MOC モバイルプレビューサーバーを起動中...")
    print("=" * 50)
    
    # コンポーネント初期化
    initialize_components()
    
    # サーバー設定
    host = "0.0.0.0"  # 外部からのアクセスを許可
    port = 8888
    
    print(f"📱 モバイルプレビューサーバー情報:")
    print(f"   - ローカルアクセス: http://localhost:{port}")
    print(f"   - ネットワークアクセス: http://[PCのIPアドレス]:{port}")
    print(f"   - モバイル対応: {'✓' if mobile_adapter and mobile_adapter.is_mobile else '○'}")
    print(f"   - タッチサポート: {'✓' if mobile_adapter and mobile_adapter.touch_enabled else '○'}")
    print("=" * 50)
    
    # ブラウザ自動起動
    open_browser(f"http://localhost:{port}")
    
    # サーバー起動
    try:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n🛑 サーバーを停止しています...")
    except Exception as e:
        print(f"❌ サーバー起動エラー: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())