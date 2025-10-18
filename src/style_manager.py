"""
リアルタイムCSS調整システム
文字色や配置を動的に変更できる管理機能
"""

import json
import os
from typing import Any, Dict

from flask import Flask, jsonify, render_template_string, request


class StyleManager:
    def __init__(self):
        self.config_file = "static/css/dynamic_styles.json"
        self.css_file = "static/css/dynamic_overrides.css"
        self.default_styles = {
            "table_text_color": "#ffffff",
            "table_bg_color": "rgba(255,255,255,0.03)",
            "table_header_color": "#ffffff",
            "table_header_bg": "rgba(255,255,255,0.08)",
            "button_text_color": "#ffffff",
            "nav_text_color": "#d8e1ff",
            "accent_color": "#00eaff",
            "muted_text_color": "#8aa0c8",
        }
        self.load_styles()

    def load_styles(self) -> Dict[str, str]:
        """保存されたスタイル設定を読み込み"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    self.styles = json.load(f)
            except:
                self.styles = self.default_styles.copy()
        else:
            self.styles = self.default_styles.copy()
        return self.styles

    def save_styles(self) -> bool:
        """スタイル設定を保存"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.styles, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"スタイル保存エラー: {e}")
            return False

    def update_style(self, key: str, value: str) -> bool:
        """個別スタイルを更新"""
        if key in self.default_styles:
            self.styles[key] = value
            self.generate_css()
            return self.save_styles()
        return False

    def update_multiple_styles(self, updates: Dict[str, str]) -> bool:
        """複数スタイルを一括更新"""
        for key, value in updates.items():
            if key in self.default_styles:
                self.styles[key] = value
        self.generate_css()
        return self.save_styles()

    def reset_to_defaults(self) -> bool:
        """デフォルトスタイルにリセット"""
        self.styles = self.default_styles.copy()
        self.generate_css()
        return self.save_styles()

    def generate_css(self) -> str:
        """動的CSSファイルを生成"""
        css_content = f"""
/* 動的スタイルオーバーライド - リアルタイム調整可能 */
/* このファイルは自動生成されます */

:root {{
  --dynamic-table-text: {self.styles['table_text_color']};
  --dynamic-table-bg: {self.styles['table_bg_color']};
  --dynamic-table-header-text: {self.styles['table_header_color']};
  --dynamic-table-header-bg: {self.styles['table_header_bg']};
  --dynamic-button-text: {self.styles['button_text_color']};
  --dynamic-nav-text: {self.styles['nav_text_color']};
  --dynamic-accent: {self.styles['accent_color']};
  --dynamic-muted: {self.styles['muted_text_color']};
}}

/* テーブル関連の動的スタイル */
table th, table td {{
  color: var(--dynamic-table-text) !important;
}}

table th {{
  background: var(--dynamic-table-header-bg) !important;
  color: var(--dynamic-table-header-text) !important;
}}

table td {{
  background: var(--dynamic-table-bg) !important;
}}

/* ボタンの動的スタイル */
.btn, button, td .btn, td button {{
  color: var(--dynamic-button-text) !important;
}}

/* ナビゲーションの動的スタイル */
.nav a {{
  color: var(--dynamic-nav-text) !important;
}}

/* アクセントカラーの動的適用 */
.nav a.active, .nav a:hover {{
  color: var(--dynamic-accent) !important;
  border-color: var(--dynamic-accent) !important;
}}

/* ミュートテキストの動的スタイル */
.muted {{
  color: var(--dynamic-muted) !important;
}}

/* 強制適用クラス */
.force-white-text {{
  color: #ffffff !important;
}}

.force-black-text {{
  color: #000000 !important;
}}

.force-visible {{
  color: #ffffff !important;
  background: rgba(0,0,0,0.8) !important;
  padding: 2px 4px !important;
  border-radius: 3px !important;
}}
"""

        try:
            os.makedirs(os.path.dirname(self.css_file), exist_ok=True)
            with open(self.css_file, "w", encoding="utf-8") as f:
                f.write(css_content)
            return css_content
        except Exception as e:
            print(f"CSS生成エラー: {e}")
            return ""


def create_style_api(app: Flask):
    """FlaskアプリにスタイルAPIエンドポイントを追加"""
    style_manager = StyleManager()

    @app.route("/api/styles", methods=["GET"])
    def get_styles():
        """現在のスタイル設定を取得（ETag対応）"""
        import json as _json
        from hashlib import sha256

        body_text = _json.dumps(style_manager.styles, sort_keys=True, ensure_ascii=False)
        body = body_text.encode("utf-8")
        etag = sha256(body).hexdigest()
        # If-None-Match は引用符や weak/strong ETag を含むため、Werkzeugの ETags を使って比較
        inm = getattr(request, "if_none_match", None)
        from flask import make_response

        # request.if_none_match は ETags オブジェクト（contains で引用符の扱いを抽象化）
        if inm and hasattr(inm, "contains") and inm.contains(etag):
            resp = make_response("", 304)
        else:
            resp = make_response(body, 200)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        resp.headers["X-Source"] = "style_manager"
        try:
            resp.set_etag(etag)
        except Exception:
            resp.headers["ETag"] = etag
        return resp

    @app.route("/api/styles", methods=["POST"])
    def update_styles():
        """スタイル設定を更新"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "データが必要です"}), 400

            if "key" in data and "value" in data:
                # 単一更新
                success = style_manager.update_style(data["key"], data["value"])
            elif "styles" in data:
                # 一括更新
                success = style_manager.update_multiple_styles(data["styles"])
            else:
                return jsonify({"error": "無効なデータ形式"}), 400

            if success:
                return jsonify(
                    {
                        "success": True,
                        "styles": style_manager.styles,
                        "message": "スタイルが更新されました",
                    }
                )
            else:
                return jsonify({"error": "スタイル更新に失敗しました"}), 500

        except Exception as e:
            return jsonify({"error": f"エラー: {str(e)}"}), 500

    @app.route("/api/styles/reset", methods=["POST"])
    def reset_styles():
        """スタイルをデフォルトにリセット"""
        try:
            success = style_manager.reset_to_defaults()
            if success:
                return jsonify(
                    {
                        "success": True,
                        "styles": style_manager.styles,
                        "message": "デフォルトスタイルにリセットしました",
                    }
                )
            else:
                return jsonify({"error": "リセットに失敗しました"}), 500
        except Exception as e:
            return jsonify({"error": f"エラー: {str(e)}"}), 500

    @app.route("/api/pages", methods=["GET"])
    def get_available_pages():
        """利用可能なページ一覧を取得（新スキーマを互換フィールドと併記）"""
        raw = [
            ("/dashboard", "ダッシュボード", "メインダッシュボード画面", False),
            ("/tasks", "タスク管理", "タスク一覧と管理画面", False),
            ("/agents", "エージェント", "AI エージェント管理画面", False),
            ("/style-manager", "スタイル管理", "UIスタイル管理画面", True),
        ]
        pages = []
        for p, t, d, prot in raw:
            pages.append(
                {
                    # 既存互換フィールド
                    "url": p,
                    "name": t,
                    "description": d,
                    # 契約フィールド
                    "path": p,
                    "title": t,
                    "protected": prot,
                }
            )
        resp = jsonify(pages)
        try:
            resp.headers["X-Pages-Source"] = "style_manager"
        except Exception:
            pass
        return resp

    @app.route("/style-manager")
    def style_manager_page():
        """スタイル管理画面"""
        return render_template_string(STYLE_MANAGER_TEMPLATE)

    # 初期CSS生成
    style_manager.generate_css()

    return style_manager


# スタイル管理画面のHTMLテンプレート
STYLE_MANAGER_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>スタイル管理 - ORION Dashboard</title>
    <link rel="stylesheet" href="/static/css/orion.css">
    <link rel="stylesheet" href="/static/css/dynamic_overrides.css">
    <style>
        /* 接続設定UI */
        .connection-panel {
            margin: 12px 0 20px 0;
            padding: 12px;
            background: rgba(0,234,255,0.05);
            border: 1px solid rgba(0,234,255,0.3);
            border-radius: 8px;
        }
        .connection-panel .status {
            margin-top: 8px;
            font-size: 12px;
            color: #8aa0c8;
        }
        .style-control {
            margin: 12px 0;
            padding: 12px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .style-control label {
            display: block;
            margin-bottom: 4px;
            color: #ffffff;
            font-weight: 600;
        }
        .style-control input {
            width: 100%;
            padding: 8px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 6px;
            color: #ffffff;
        }
        .preview-box {
            margin: 16px 0;
            padding: 16px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            position: relative;
            transition: all 0.3s ease;
        }
        .preview-box.highlight {
            border-color: #00eaff;
            box-shadow: 0 0 15px rgba(0,234,255,0.3);
            background: rgba(0,234,255,0.05);
        }
        .preview-label {
            position: absolute;
            top: -8px;
            left: 12px;
            background: #1a2332;
            color: #00eaff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        .change-indicator {
            position: absolute;
            top: 8px;
            right: 8px;
            background: #ff6464;
            color: white;
            border-radius: 50%;
            width: 16px;
            height: 16px;
            font-size: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        .change-indicator.active {
            opacity: 1;
        }
        .action-buttons {
            display: flex;
            gap: 12px;
            margin: 16px 0;
        }
        .btn-apply {
            background: linear-gradient(180deg, rgba(0,234,255,0.35), rgba(0,234,255,0.15));
            border-color: #00eaff;
        }
        .btn-reset {
            background: linear-gradient(180deg, rgba(255,100,100,0.35), rgba(255,100,100,0.15));
            border-color: #ff6464;
        }
        
        /* ドロップダウンのオプション要素のスタイル改善 */
        #pageSelect option {
            background: #2a3441 !important;
            color: #ffffff !important;
            padding: 8px !important;
        }
        
        #pageSelect option:hover {
            background: #3a4451 !important;
            color: #00eaff !important;
        }
        
        #pageSelect option:checked {
            background: #00eaff !important;
            color: #000000 !important;
        }
        
        /* 新しいビジュアル編集インターフェースのスタイル */
        .edit-mode-btn {
            flex: 1;
            padding: 8px 4px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 4px;
            color: #8aa0c8;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .edit-mode-btn:hover {
            background: rgba(255,255,255,0.1);
            color: #ffffff;
        }
        
        .edit-mode-btn.active {
            background: rgba(0,234,255,0.2);
            border-color: #00eaff;
            color: #00eaff;
        }
        
        .color-preset {
            width: 24px;
            height: 24px;
            border-radius: 4px;
            cursor: pointer;
            border: 2px solid rgba(255,255,255,0.2);
            transition: all 0.2s ease;
        }
        
        .color-preset:hover {
            border-color: #00eaff;
            transform: scale(1.1);
        }
        
        .font-style-btn {
            width: 32px;
            height: 32px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 4px;
            color: #ffffff;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.2s ease;
        }
        
        .font-style-btn:hover {
            background: rgba(255,255,255,0.1);
            border-color: #00eaff;
        }
        
        .font-style-btn.active {
            background: rgba(0,234,255,0.2);
            border-color: #00eaff;
            color: #00eaff;
        }
        
        /* 選択要素のハイライト */
        .element-highlight {
            position: fixed;
            border: 2px solid #00eaff;
            background: rgba(0,234,255,0.1);
            pointer-events: none;
            z-index: 10000;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }
        
        .element-highlight::before {
            content: attr(data-element-type);
            position: absolute;
            top: -24px;
            left: 0;
            background: #00eaff;
            color: #000;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            white-space: nowrap;
        }
        
        /* リサイズハンドル */
        .resize-handle {
            position: absolute;
            width: 8px;
            height: 8px;
            background: #00eaff;
            border: 1px solid #ffffff;
            border-radius: 50%;
            cursor: pointer;
            z-index: 1001;
        }
        
        .resize-handle.nw { top: -4px; left: -4px; cursor: nw-resize; }
        .resize-handle.ne { top: -4px; right: -4px; cursor: ne-resize; }
        .resize-handle.sw { bottom: -4px; left: -4px; cursor: sw-resize; }
        .resize-handle.se { bottom: -4px; right: -4px; cursor: se-resize; }
        .resize-handle.n { top: -4px; left: 50%; transform: translateX(-50%); cursor: n-resize; }
        .resize-handle.s { bottom: -4px; left: 50%; transform: translateX(-50%); cursor: s-resize; }
        .resize-handle.w { top: 50%; left: -4px; transform: translateY(-50%); cursor: w-resize; }
        .resize-handle.e { top: 50%; right: -4px; transform: translateY(-50%); cursor: e-resize; }
        
        /* ドラッグ中のスタイル */
        .dragging {
            opacity: 0.7;
            z-index: 1002;
        }
        
        /* ドロップゾーンのハイライト */
        .drop-zone {
            border: 2px dashed #00eaff !important;
            background: rgba(0,234,255,0.05) !important;
        }
    </style>
</head>
<body class="orion">
    <div class="container">
        <div class="header">
            <h1>🎨 スタイル管理システム</h1>
            <div class="nav">
                <a href="/dashboard">ダッシュボード</a>
                <a href="/tasks">タスク</a>
                <a href="/style-manager" class="active">スタイル管理</a>
            </div>
        </div>

        <!-- 新しいレイアウト: 左側にツールパネル、右側に大きな編集エリア -->
        <div style="display: flex; gap: 16px; height: calc(100vh - 120px);">
            <!-- 左側: コンパクトなツールパネル -->
            <div class="card" style="width: 320px; display: flex; flex-direction: column;">
                <h3>🔗 接続設定</h3>
                <div class="connection-panel">
                    <div class="style-control">
                        <label for="baseUrlInput">ベースURL（例: http://style.local:5001）</label>
                        <input id="baseUrlInput" type="text" placeholder="http://style.local:5001">
                    </div>
                    <div class="action-buttons">
                        <button id="saveBaseUrlBtn" class="btn btn-primary">保存</button>
                        <button id="pingBtn" class="btn">接続テスト</button>
                    </div>
                    <div id="baseUrlStatus" class="status">未設定。現在のホストに対して相対パスを使用します。</div>
                </div>
                <h3>📄 ページ選択</h3>
                <div class="page-selector">
                    <select id="pageSelect" style="width: 100%; padding: 8px; margin-bottom: 12px; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; color: #ffffff;">
                        <option value="">ページを選択...</option>
                    </select>
                    <button id="loadPageBtn" class="btn btn-primary" style="width: 100%;">ページを読み込み</button>
                </div>

                <h3 style="margin-top: 20px;">🎨 ビジュアル編集ツール</h3>
                
                <!-- 編集モード切り替え -->
                <div style="margin-bottom: 16px;">
                    <div style="display: flex; gap: 4px; background: rgba(255,255,255,0.05); border-radius: 6px; padding: 4px;">
                        <button id="selectModeBtn" class="edit-mode-btn active" onclick="setEditMode('select')">🎯 選択</button>
                        <button id="colorModeBtn" class="edit-mode-btn" onclick="setEditMode('color')">🎨 色</button>
                        <button id="textModeBtn" class="edit-mode-btn" onclick="setEditMode('text')">📝 文字</button>
                        <button id="moveModeBtn" class="edit-mode-btn" onclick="setEditMode('move')">↔️ 移動</button>
                    </div>
                </div>

                <!-- カラーピッカー（色モード時に表示） -->
                <div id="colorTools" style="display: none; margin-bottom: 16px;">
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                        <input type="color" id="quickColorPicker" style="width: 40px; height: 40px; border: none; border-radius: 6px; cursor: pointer;">
                        <div style="flex: 1;">
                            <div style="font-size: 11px; color: #8aa0c8; margin-bottom: 2px;">選択した色</div>
                            <div id="selectedColorValue" style="font-size: 12px; font-family: monospace;">#00eaff</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                        <div class="color-preset" style="background: #00eaff;" onclick="applyQuickColor('#00eaff')"></div>
                        <div class="color-preset" style="background: #ff6464;" onclick="applyQuickColor('#ff6464')"></div>
                        <div class="color-preset" style="background: #64ff64;" onclick="applyQuickColor('#64ff64')"></div>
                        <div class="color-preset" style="background: #ffff64;" onclick="applyQuickColor('#ffff64')"></div>
                        <div class="color-preset" style="background: #ff64ff;" onclick="applyQuickColor('#ff64ff')"></div>
                        <div class="color-preset" style="background: #64ffff;" onclick="applyQuickColor('#64ffff')"></div>
                        <div class="color-preset" style="background: #ffffff;" onclick="applyQuickColor('#ffffff')"></div>
                        <div class="color-preset" style="background: #000000;" onclick="applyQuickColor('#000000')"></div>
                    </div>
                </div>

                <!-- フォントツール（文字モード時に表示） -->
                <div id="fontTools" style="display: none; margin-bottom: 16px;">
                    <!-- フォントファミリー選択 -->
                    <div style="margin-bottom: 12px;">
                        <label style="font-size: 11px; color: #8aa0c8; display: block; margin-bottom: 4px;">フォントファミリー</label>
                        <select id="fontFamilySelect" style="width: 100%; padding: 4px; background: #1a2332; color: #fff; border: 1px solid #00eaff; border-radius: 4px;" onchange="updateFontFamily(this.value)">
                            <option value="Arial, sans-serif">Arial</option>
                            <option value="'Times New Roman', serif">Times New Roman</option>
                            <option value="'Courier New', monospace">Courier New</option>
                            <option value="Helvetica, sans-serif">Helvetica</option>
                            <option value="Georgia, serif">Georgia</option>
                            <option value="Verdana, sans-serif">Verdana</option>
                            <option value="'Comic Sans MS', cursive">Comic Sans MS</option>
                            <option value="Impact, sans-serif">Impact</option>
                            <option value="'Trebuchet MS', sans-serif">Trebuchet MS</option>
                            <option value="'Lucida Console', monospace">Lucida Console</option>
                        </select>
                        <div style="margin-top: 4px; display: flex; gap: 4px;">
                            <input type="text" id="customFontInput" placeholder="カスタムフォント名" style="flex: 1; padding: 2px 4px; background: #1a2332; color: #fff; border: 1px solid #444; border-radius: 3px; font-size: 11px;">
                            <button onclick="addCustomFont()" style="padding: 2px 6px; background: #00eaff; color: #000; border: none; border-radius: 3px; font-size: 10px; cursor: pointer;">追加</button>
                        </div>
                    </div>
                    
                    <!-- Google Fonts読み込み -->
                    <div style="margin-bottom: 12px;">
                        <label style="font-size: 11px; color: #8aa0c8; display: block; margin-bottom: 4px;">Google Fonts</label>
                        <div style="display: flex; gap: 4px; margin-bottom: 4px;">
                            <input type="text" id="googleFontInput" placeholder="例: Roboto, Noto Sans JP" style="flex: 1; padding: 2px 4px; background: #1a2332; color: #fff; border: 1px solid #444; border-radius: 3px; font-size: 11px;">
                            <button onclick="loadGoogleFont()" style="padding: 2px 6px; background: #4CAF50; color: #fff; border: none; border-radius: 3px; font-size: 10px; cursor: pointer;">読込</button>
                        </div>
                        <div style="font-size: 10px; color: #666;">
                            人気フォント: 
                            <span onclick="loadPopularFont('Roboto')" style="color: #00eaff; cursor: pointer; text-decoration: underline;">Roboto</span> | 
                            <span onclick="loadPopularFont('Noto Sans JP')" style="color: #00eaff; cursor: pointer; text-decoration: underline;">Noto Sans JP</span> | 
                            <span onclick="loadPopularFont('Open Sans')" style="color: #00eaff; cursor: pointer; text-decoration: underline;">Open Sans</span>
                        </div>
                    </div>
                    
                    <!-- フォントサイズ -->
                    <div style="margin-bottom: 8px;">
                        <label style="font-size: 11px; color: #8aa0c8;">フォントサイズ</label>
                        <input type="range" id="fontSizeSlider" min="8" max="48" value="14" style="width: 100%;" oninput="updateFontSize(this.value)">
                        <div style="text-align: center; font-size: 11px; color: #8aa0c8;"><span id="fontSizeValue">14</span>px</div>
                    </div>
                    
                    <!-- フォントスタイル -->
                    <div style="display: flex; gap: 4px; margin-bottom: 8px;">
                        <button class="font-style-btn" onclick="toggleFontStyle('bold')"><b>B</b></button>
                        <button class="font-style-btn" onclick="toggleFontStyle('italic')"><i>I</i></button>
                        <button class="font-style-btn" onclick="toggleFontStyle('underline')"><u>U</u></button>
                    </div>
                    
                    <!-- テキスト選択の保存・復元 -->
                    <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #444;">
                        <label style="font-size: 11px; color: #8aa0c8; display: block; margin-bottom: 4px;">テキスト選択</label>
                        <div style="display: flex; gap: 4px;">
                            <button onclick="saveTextSelection()" style="flex: 1; padding: 4px 8px; background: #4CAF50; color: #fff; border: none; border-radius: 3px; font-size: 10px; cursor: pointer;">💾 保存</button>
                            <button onclick="restoreTextSelection()" style="flex: 1; padding: 4px 8px; background: #2196F3; color: #fff; border: none; border-radius: 3px; font-size: 10px; cursor: pointer;">🔄 復元</button>
                            <button onclick="clearSavedTextSelection()" style="flex: 1; padding: 4px 8px; background: #ff4444; color: #fff; border: none; border-radius: 3px; font-size: 10px; cursor: pointer;">🗑️ クリア</button>
                        </div>
                    </div>
                </div>

                <!-- 従来のスタイル調整（折りたたみ可能） -->
                <details style="margin-top: 16px;">
                    <summary style="cursor: pointer; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 6px; margin-bottom: 8px;">⚙️ 詳細設定</summary>
                    
                    <div class="style-control">
                        <label>テーブル文字色</label>
                        <input type="color" id="table_text_color" value="#ffffff">
                    </div>
                    
                    <div class="style-control">
                        <label>テーブル背景色</label>
                        <input type="color" id="table_bg_color" value="#0a0f1a">
                    </div>
                    
                    <div class="style-control">
                        <label>テーブルヘッダー文字色</label>
                        <input type="color" id="table_header_color" value="#ffffff">
                    </div>
                    
                    <div class="style-control">
                        <label>テーブルヘッダー背景色</label>
                        <input type="color" id="table_header_bg" value="#1a2332">
                    </div>
                    
                    <div class="style-control">
                        <label>ボタン文字色</label>
                        <input type="color" id="button_text_color" value="#ffffff">
                    </div>
                    
                    <div class="style-control">
                        <label>ナビゲーション文字色</label>
                        <input type="color" id="nav_text_color" value="#d8e1ff">
                    </div>
                    
                    <div class="style-control">
                        <label>アクセントカラー</label>
        <input type="color" id="accent_color" value="#00eaff" data-sem-role="color-input" data-sem-intent="accent_color">
                    </div>
                    
                    <div class="style-control">
                        <label>ミュートテキスト色</label>
                        <input type="color" id="muted_text_color" value="#8aa0c8">
                    </div>
                    
                    <div class="action-buttons">
                        <button class="btn btn-apply" onclick="applyStyles()">✅ 適用</button>
                        <button class="btn btn-reset" onclick="resetStyles()">🔄 リセット</button>
                        <button class="btn" onclick="loadCurrentStyles()">📥 現在値読込</button>
                    </div>
                </details>
            </div>

            <!-- 右側: 大きなメイン編集エリア -->
            <div class="card" style="flex: 1; display: flex; flex-direction: column;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <h3>🖥️ ライブ編集画面</h3>
                    <div style="display: flex; gap: 8px;">
                        <button id="toggleComparisonBtn" class="btn btn-secondary" onclick="toggleComparison()">
                            🔄 比較表示
                        </button>
                        <button class="btn btn-secondary" onclick="resetZoom()">🔍 ズームリセット</button>
                    </div>
                </div>
                
                <!-- 編集状態インジケーター -->
                <div id="editModeIndicator" style="padding: 8px; background: rgba(0,234,255,0.1); border: 1px solid rgba(0,234,255,0.3); border-radius: 6px; margin-bottom: 12px; font-size: 12px;">
                    <span id="editModeText">🎯 選択モード: 要素をクリックして選択してください</span>
                </div>

                <!-- メインiframeエリア -->
                <div class="iframe-container" style="flex: 1; border: 2px solid rgba(255,255,255,0.2); border-radius: 8px; overflow: hidden; position: relative; min-height: 500px;">
                    <iframe id="previewFrame" style="width: 100%; height: 100%; border: none; background: white; transform-origin: top left; transition: transform 0.3s ease;"></iframe>
                    
                    <!-- 選択要素のオーバーレイ -->
                    <div id="selectionOverlay" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; pointer-events: none; z-index: 9999;">
                        <!-- 選択ハイライトとリサイズハンドルがここに動的に追加される -->
                    </div>
                </div>

                <!-- 比較表示エリア -->
                <div id="comparison-view" style="display: none; margin-top: 16px;">
                    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                        <div style="flex: 1; text-align: center; padding: 6px; background: rgba(255,100,100,0.1); border-radius: 4px; font-size: 11px;">
                            <strong>変更前</strong>
                        </div>
                        <div style="flex: 1; text-align: center; padding: 6px; background: rgba(100,255,100,0.1); border-radius: 4px; font-size: 11px;">
                            <strong>変更後</strong>
                        </div>
                    </div>
                    
                    <div id="comparison-content" style="display: flex; gap: 8px; height: 300px;">
                        <div id="before-preview" style="flex: 1; border: 1px solid rgba(255,100,100,0.3); border-radius: 4px; overflow: hidden;">
                            <iframe style="width: 100%; height: 100%; border: none; transform: scale(0.5); transform-origin: top left;"></iframe>
                        </div>
                        <div id="after-preview" style="flex: 1; border: 1px solid rgba(100,255,100,0.3); border-radius: 4px; overflow: hidden;">
                            <iframe style="width: 100%; height: 100%; border: none; transform: scale(0.5); transform-origin: top left;"></iframe>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 選択要素情報パネル -->
        <div id="selectionInfoPanel" class="card" style="position: fixed; top: 20px; right: 20px; width: 300px; max-height: 400px; overflow-y: auto; z-index: 10001; display: none; background: rgba(30, 30, 30, 0.95); backdrop-filter: blur(10px); border: 1px solid #00eaff;">
            <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 12px;">
                <h3 style="margin: 0; color: #00eaff;">🎯 選択要素情報</h3>
                <button id="closeSelectionPanel" class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px;">✕</button>
            </div>
            
            <div id="selectionList" style="max-height: 300px; overflow-y: auto;">
                <!-- 選択された要素の情報がここに表示される -->
            </div>
            
            <div style="margin-top: 12px; display: flex; gap: 8px;">
                <button id="clearAllSelectionsBtn" class="btn btn-danger" style="flex: 1; font-size: 12px;">
                    🗑️ 全て解除
                </button>
                <button id="exportSelectionsBtn" class="btn btn-secondary" style="flex: 1; font-size: 12px;">
                    📋 エクスポート
                </button>
            </div>
        </div>

        <!-- 隠されたプレビューエリア（従来の機能との互換性のため） -->
        <div style="display: none;">
            <div class="card" style="flex: 1;">
                <h3>📋 プレビュー</h3>
                
                <div style="margin-bottom: 16px;">
                    <button id="toggleComparisonBtn" class="btn btn-secondary" style="width: 100%; font-size: 12px;">
                        🔄 変更前後の比較を表示
                    </button>
                </div>
                
                <div id="comparison-view" style="display: none;">
                    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                        <div style="flex: 1; text-align: center; padding: 6px; background: rgba(255,100,100,0.1); border-radius: 4px; font-size: 11px;">
                            <strong>変更前</strong>
                        </div>
                        <div style="flex: 1; text-align: center; padding: 6px; background: rgba(100,255,100,0.1); border-radius: 4px; font-size: 11px;">
                            <strong>変更後</strong>
                        </div>
                    </div>
                    
                    <div id="comparison-content" style="display: flex; gap: 8px; font-size: 10px;">
                        <div id="before-preview" style="flex: 1; border: 1px solid rgba(255,100,100,0.3); border-radius: 4px; padding: 6px;">
                            <!-- 変更前のプレビューがここに表示される -->
                        </div>
                        <div id="after-preview" style="flex: 1; border: 1px solid rgba(100,255,100,0.3); border-radius: 4px; padding: 6px;">
                            <!-- 変更後のプレビューがここに表示される -->
                        </div>
                    </div>
                </div>
                
                <div id="single-preview">
                    <div class="preview-box" id="table-preview">
                        <div class="preview-label">📊 テーブル</div>
                        <div class="change-indicator" id="table-indicator">!</div>
                        <table style="width: 100%; font-size: 12px;">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>タイトル</th>
                                    <th>ステータス</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>1</td>
                                    <td>サンプルタスク</td>
                                    <td><span class="badge">WORK</span></td>
                                </tr>
                                <tr>
                                    <td>2</td>
                                    <td>テスト項目</td>
                                    <td><button class="btn" style="font-size: 10px;">編集</button></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="preview-box" id="nav-preview">
                        <div class="preview-label">🧭 ナビゲーション</div>
                        <div class="change-indicator" id="nav-indicator">!</div>
                        <div class="nav">
                            <a href="#">ホーム</a>
                            <a href="#" class="active">アクティブ</a>
                            <a href="#">設定</a>
                        </div>
                    </div>
                    
                    <div class="preview-box" id="text-preview">
                        <div class="preview-label">📝 テキスト</div>
                        <div class="change-indicator" id="text-indicator">!</div>
                        <p>通常テキスト</p>
                        <p class="muted">ミュートテキスト</p>
                        <button class="btn">サンプルボタン</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card space-md">
            <h3>📊 ステータス</h3>
            <div id="status-message" style="padding: 8px; border-radius: 6px; background: rgba(0,234,255,0.1); color: #00eaff;">
                準備完了 - 上記の色を調整して「適用」ボタンを押してください
            </div>
        </div>
    </div>

    <script>
        let currentStyles = {};
        let originalValues = {};
        let isComparisonMode = false;
        
        // 新しいビジュアル編集機能の変数
        let currentEditMode = 'select';
        let selectedElement = null;
        let isDragging = false;
        let isResizing = false;
        let dragStartPos = { x: 0, y: 0 };
        let elementStartPos = { x: 0, y: 0 };
        let resizeStartSize = { width: 0, height: 0 };
        let currentResizeHandle = null;

        // 接続先ベースURLヘルパー（正規化含む）
        function normalizeBase(raw) {
            if (!raw) return '';
            try {
                const u = new URL(raw.trim());
                // パス付きベースは origin 固定（http://host:port/）
                return u.origin + '/';
            } catch (e) {
                return '';
            }
        }

        function api(path) {
            // ベースURLはダッシュボードと同一キーに統一: 'STYLE_BASE_URL'
            const base = normalizeBase(localStorage.getItem('STYLE_BASE_URL') || '');
            const b = base ? base.replace(/\/$/, '') : '';
            return b ? b + path : path;
        }

        function updateBaseUrlStatus() {
            const raw = (localStorage.getItem('STYLE_BASE_URL') || '').trim();
            const el = document.getElementById('baseUrlStatus');
            if (!el) return;
            if (!raw) {
                el.textContent = '未設定。現在のホストに対して相対パスを使用します。';
            } else {
                el.textContent = `現在の接続先: ${raw}`;
            }
        }

        // ページ読み込み時に現在のスタイルを取得
        window.onload = function() {
            // Base URL 初期値
            const input = document.getElementById('baseUrlInput');
            if (input) {
                input.value = (localStorage.getItem('STYLE_BASE_URL') || '').trim();
            }
            updateBaseUrlStatus();

            loadCurrentStyles();
            loadAvailablePages();
            setupEventListeners();
        };
        
        function loadCurrentStyles() {
            fetch(api('/api/styles'))
                .then(response => response.json())
                .then(data => {
                    currentStyles = data;
                    originalValues = {...data}; // オリジナル値を保存
                    updateInputs(data);
                    showStatus('現在のスタイルを読み込みました', 'success');
                })
                .catch(error => {
                    showStatus('スタイル読み込みエラー: ' + error, 'error');
                });
        }

        function loadAvailablePages() {
            fetch(api('/api/pages'))
                .then(response => response.json())
                .then(pages => {
                    const select = document.getElementById('pageSelect');
                    select.innerHTML = '<option value="">ページを選択...</option>';
                    
                    pages.forEach(page => {
                        const option = document.createElement('option');
                        option.value = page.url;
                        option.textContent = `${page.name} - ${page.description}`;
                        select.appendChild(option);
                    });
                })
                .catch(error => {
                    showStatus('ページ一覧の読み込みエラー: ' + error, 'error');
                });
        }
        
        function setupEventListeners() {
            // ページ読み込みボタン
            document.getElementById('loadPageBtn').addEventListener('click', loadSelectedPage);
            
            // 比較表示切り替えボタン
            document.getElementById('toggleComparisonBtn').addEventListener('click', toggleComparison);
            
            // リアルタイムプレビュー用のイベントリスナー
            const inputs = document.querySelectorAll('.style-control input');
            inputs.forEach(input => {
                input.addEventListener('input', updatePreviewRealtime);
            });
            
            // 新しいビジュアル編集機能のイベントリスナー
            setupVisualEditingListeners();

            // 接続設定イベント
            const saveBtn = document.getElementById('saveBaseUrlBtn');
            const pingBtn = document.getElementById('pingBtn');
            if (saveBtn) {
                saveBtn.addEventListener('click', () => {
                    const v = document.getElementById('baseUrlInput').value.trim();
                    const norm = normalizeBase(v);
                    if (!norm) { showStatus('URLが不正です', 'error'); return; }
                    localStorage.setItem('STYLE_BASE_URL', norm);
                    updateBaseUrlStatus();
                    showStatus('接続先ベースURLを保存しました', 'success');
                });
            }
            if (pingBtn) {
                pingBtn.addEventListener('click', async () => {
                    try {
                        const url = api('/api/pages');
                        // 認証サイト想定で include/omit の両系検証
                        const res = await fetch(url, { credentials: 'include' });
                        const okCreds = res.ok &&
                          res.headers.get('access-control-allow-origin') !== '*' &&
                          res.headers.get('access-control-allow-credentials') === 'true';
                        const res2 = await fetch(url, { credentials: 'omit' });
                        const okOmit = res2.ok;
                        if (okCreds || okOmit) {
                            showStatus('接続テスト成功', 'success');
                        } else {
                            showStatus('接続テスト失敗: ' + (res.status || res2.status), 'error');
                        }
                    } catch (e) {
                        showStatus('接続テストエラー: ' + e, 'error');
                    }
                });
            }
        }
        
        // ビジュアル編集機能のセットアップ
        function setupVisualEditingListeners() {
            // カラーピッカーのイベント
            const quickColorPicker = document.getElementById('quickColorPicker');
            if (quickColorPicker) {
                quickColorPicker.addEventListener('input', function(e) {
                    document.getElementById('selectedColorValue').textContent = e.target.value;
                    if (selectedElement && currentEditMode === 'color') {
                        applyColorToSelectedElement(e.target.value);
                    }
                });
            }
            
            // フォントサイズスライダー
            const fontSizeSlider = document.getElementById('fontSizeSlider');
            if (fontSizeSlider) {
                fontSizeSlider.addEventListener('input', function(e) {
                    document.getElementById('fontSizeValue').textContent = e.target.value;
                    if (selectedElement && currentEditMode === 'text') {
                        applyFontSizeToSelectedElement(e.target.value + 'px');
                    }
                });
            }
            
            // iframe内の要素選択
            setupIframeInteraction();
        }
        
        // 編集モードの切り替え
        function setEditMode(mode) {
            currentEditMode = mode;
            
            // ボタンのアクティブ状態を更新
            document.querySelectorAll('.edit-mode-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(mode + 'ModeBtn').classList.add('active');
            
            // ツールパネルの表示/非表示
            document.getElementById('colorTools').style.display = mode === 'color' ? 'block' : 'none';
            document.getElementById('fontTools').style.display = mode === 'text' ? 'block' : 'none';
            
            // 編集状態インジケーターの更新
            const modeTexts = {
                'select': '🎯 選択モード: 要素をクリックして選択してください',
                'color': '🎨 色編集モード: 要素を選択して色を変更してください',
                'text': '📝 文字編集モード: テキスト要素を選択してフォントを調整してください',
                'move': '↔️ 移動モード: 要素をドラッグして位置を変更してください'
            };
            document.getElementById('editModeText').textContent = modeTexts[mode];
            
            // カーソルスタイルの更新
            updateCursorStyle(mode);
        }
        
        // カーソルスタイルの更新
        function updateCursorStyle(mode) {
            const iframe = document.getElementById('previewFrame');
            if (iframe && iframe.contentDocument) {
                const body = iframe.contentDocument.body;
                const cursors = {
                    'select': 'pointer',
                    'color': 'crosshair',
                    'text': 'text',
                    'move': 'move'
                };
                body.style.cursor = cursors[mode] || 'default';
            }
        }
        
        // iframe内のインタラクションセットアップ（統合版）
        function setupIframeInteraction() {
            const iframe = document.getElementById('previewFrame');
            if (!iframe) {
                console.log('Preview iframe not found');
                return;
            }
            
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            if (!iframeDoc) {
                console.log('Cannot access iframe document');
                return;
            }
            
            console.log('Setting up iframe interaction...');
            
            // iframe内の全要素にイベントリスナーを追加
            const allElements = iframeDoc.querySelectorAll('*');
            console.log('Found', allElements.length, 'elements in iframe');
            
            allElements.forEach((element, index) => {
                // クリックイベント（要素選択）
                element.addEventListener('click', function(e) {
                    console.log('Element clicked:', element.tagName, element.className || 'no-class');
                    
                    // テキスト選択がある場合は要素選択をスキップ
                    const selection = iframeDoc.getSelection();
                    if (selection && selection.toString().length > 0) {
                        console.log('Text selection detected, skipping element selection');
                        return;
                    }
                    
                    // 要素選択を実行
                    e.preventDefault();
                    e.stopPropagation();
                    selectElement(element);
                });
                
                // マウスオーバーイベント（ハイライト）
                element.addEventListener('mouseenter', function(e) {
                    if (element.tagName !== 'HTML' && element.tagName !== 'BODY') {
                        element.style.outline = '2px solid #00eaff';
                        element.style.outlineOffset = '2px';
                    }
                });
                
                element.addEventListener('mouseleave', function(e) {
                    element.style.outline = '';
                    element.style.outlineOffset = '';
                });
                
                // 要素を選択可能にするためのスタイル調整
                element.style.cursor = 'pointer';
            });
            
            // テキスト選択の自動保存機能
            iframeDoc.addEventListener('selectionchange', function() {
                setTimeout(() => {
                    const selection = iframeDoc.getSelection();
                    if (selection && selection.toString().length > 0) {
                        saveTextSelection();
                    }
                }, 100);
            });
            
            console.log('Iframe interaction setup completed');
        }
        
        // 選択された要素の履歴を管理
        let selectedElements = [];
        let elementCounter = 0;
        
        // 要素の選択
        function selectElement(element) {
            console.log('selectElement called with:', element.tagName, element.className);
            
            // 既に選択されている場合は選択解除
            const existingSelection = selectedElements.find(sel => sel.element === element);
            if (existingSelection) {
                console.log('Element already selected, deselecting:', element.tagName);
                deselectElement(existingSelection);
                return;
            }
            
            elementCounter++;
            const selectionData = {
                id: elementCounter,
                element: element,
                originalStyles: {
                    backgroundColor: element.style.backgroundColor || getComputedStyle(element).backgroundColor,
                    color: element.style.color || getComputedStyle(element).color,
                    fontSize: element.style.fontSize || getComputedStyle(element).fontSize,
                    fontWeight: element.style.fontWeight || getComputedStyle(element).fontWeight,
                    fontStyle: element.style.fontStyle || getComputedStyle(element).fontStyle,
                    textDecoration: element.style.textDecoration || getComputedStyle(element).textDecoration,
                    width: element.style.width || getComputedStyle(element).width,
                    height: element.style.height || getComputedStyle(element).height,
                    position: element.style.position || getComputedStyle(element).position,
                    top: element.style.top || getComputedStyle(element).top,
                    left: element.style.left || getComputedStyle(element).left
                },
                timestamp: new Date().toLocaleTimeString()
            };
            
            selectedElements.push(selectionData);
            selectedElement = element; // 最後に選択された要素を保持
            
            // 選択ハイライトを表示（番号付き）
            showElementSelection(element, selectionData.id);
            
            // 選択情報パネルを更新
            updateSelectionInfoPanel();
            
            // ステータス表示
            showStatus(`要素 #${selectionData.id} を選択しました (${element.tagName.toLowerCase()})`, 'success');
            
            console.log('Element selected:', element.tagName, 'ID:', selectionData.id);
            
            // 現在のモードに応じた処理
            switch (currentEditMode) {
                case 'color':
                    showColorTools(element);
                    break;
                case 'text':
                    showFontTools(element);
                    break;
                case 'move':
                    enableElementMoving(element);
                    break;
            }
        }
        
        // 要素の選択解除
        function deselectElement(selectionId) {
            // 選択データを取得
            const selectionData = selectedElements.find(sel => sel.id === selectionId);
            if (!selectionData) return;
            
            // 選択リストから削除
            selectedElements = selectedElements.filter(sel => sel.id !== selectionId);
            
            // ハイライトを削除
            const highlight = document.getElementById('selection-' + selectionId);
            if (highlight) {
                highlight.remove();
            }
            
            // 最後に選択された要素を更新
            if (selectedElements.length > 0) {
                selectedElement = selectedElements[selectedElements.length - 1].element;
            } else {
                selectedElement = null;
            }
            
            // 選択情報パネルを更新
            updateSelectionInfoPanel();
            
            console.log('Element deselected:', selectionId);
        }
        
        // すべての選択を解除
        function clearAllSelections() {
            selectedElements.forEach(selectionData => {
                const highlight = document.getElementById('selection-' + selectionData.id);
                if (highlight) {
                    highlight.remove();
                }
            });
            selectedElements = [];
            selectedElement = null;
            
            // 選択情報パネルを更新
            updateSelectionInfoPanel();
        }
        
        // 要素のハイライト
        function highlightElement(element, show) {
            if (show) {
                element.style.outline = '2px solid #00eaff';
                element.style.outlineOffset = '1px';
                element.style.backgroundColor = 'rgba(0, 234, 255, 0.1)';
                console.log('Highlighting element:', element.tagName, element.className);
            } else {
                element.style.outline = '';
                element.style.outlineOffset = '';
                element.style.backgroundColor = '';
            }
        }
        
        // 要素選択の表示（番号付き）
        function showElementSelection(element, selectionId) {
            const iframe = document.getElementById('previewFrame');
            const overlay = document.getElementById('selectionOverlay');
            
            if (!iframe || !overlay) {
                console.error('iframe or overlay not found');
                return;
            }
            
            // iframe内の要素の位置を取得
            const rect = element.getBoundingClientRect();
            const iframeRect = iframe.getBoundingClientRect();
            
            console.log('Element rect:', rect);
            console.log('Iframe rect:', iframeRect);
            
            // 選択ハイライトを作成
            const highlight = document.createElement('div');
            highlight.className = 'element-highlight';
            highlight.id = 'selection-' + selectionId;
            highlight.setAttribute('data-element-type', element.tagName.toLowerCase());
            highlight.setAttribute('data-selection-id', selectionId);
            
            // iframe内の座標をページ座標に変換
            const absoluteLeft = rect.left + iframeRect.left;
            const absoluteTop = rect.top + iframeRect.top;
            
            highlight.style.position = 'fixed';
            highlight.style.left = absoluteLeft + 'px';
            highlight.style.top = absoluteTop + 'px';
            highlight.style.width = rect.width + 'px';
            highlight.style.height = rect.height + 'px';
            highlight.style.border = '3px solid #00eaff';
            highlight.style.backgroundColor = 'rgba(0, 234, 255, 0.15)';
            highlight.style.pointerEvents = 'none';
            highlight.style.zIndex = '10000';
            highlight.style.boxSizing = 'border-box';
            highlight.style.borderRadius = '4px';
            
            // 選択番号を表示するバッジを追加
            const badge = document.createElement('div');
            badge.className = 'selection-badge';
            badge.textContent = selectionId;
            badge.style.position = 'absolute';
            badge.style.top = '-12px';
            badge.style.left = '-12px';
            badge.style.width = '24px';
            badge.style.height = '24px';
            badge.style.backgroundColor = '#00eaff';
            badge.style.color = '#000';
            badge.style.borderRadius = '50%';
            badge.style.display = 'flex';
            badge.style.alignItems = 'center';
            badge.style.justifyContent = 'center';
            badge.style.fontSize = '12px';
            badge.style.fontWeight = 'bold';
            badge.style.border = '2px solid #fff';
            badge.style.boxShadow = '0 2px 4px rgba(0,0,0,0.3)';
            
            highlight.appendChild(badge);
            
            console.log('Highlight positioned at:', absoluteLeft, absoluteTop, 'with ID:', selectionId);
            
            overlay.appendChild(highlight);
            
            // リサイズハンドルを追加
            if (currentEditMode === 'move') {
                addResizeHandles(highlight);
            }
        }
        
        // 選択解除
        function clearElementSelection() {
            const overlay = document.getElementById('selectionOverlay');
            overlay.innerHTML = '';
            selectedElement = null;
        }
        
        // リサイズハンドルの追加
        function addResizeHandles(highlight) {
            const handles = ['nw', 'ne', 'sw', 'se', 'n', 's', 'w', 'e'];
            handles.forEach(direction => {
                const handle = document.createElement('div');
                handle.className = `resize-handle ${direction}`;
                handle.addEventListener('mousedown', function(e) {
                    startResize(e, direction);
                });
                highlight.appendChild(handle);
            });
        }
        
        // クイックカラー適用
        function applyQuickColor(color) {
            document.getElementById('quickColorPicker').value = color;
            document.getElementById('selectedColorValue').textContent = color;
            
            if (selectedElement && currentEditMode === 'color') {
                applyColorToSelectedElement(color);
            }
        }
        
        // 選択要素に色を適用
        function applyColorToSelectedElement(color) {
            if (!selectedElement) return;
            
            // 要素の種類に応じて適切なスタイルを適用
            const tagName = selectedElement.tagName.toLowerCase();
            
            if (tagName === 'button' || selectedElement.classList.contains('btn')) {
                selectedElement.style.backgroundColor = color;
            } else if (tagName === 'a') {
                selectedElement.style.color = color;
            } else {
                // テキスト要素の場合は文字色、その他は背景色
                if (selectedElement.textContent.trim()) {
                    selectedElement.style.color = color;
                } else {
                    selectedElement.style.backgroundColor = color;
                }
            }
            
            showStatus(`色を ${color} に変更しました`, 'success');
        }
        
        // フォントサイズの更新
        function updateFontSize(size) {
            document.getElementById('fontSizeValue').textContent = size;
            if (selectedElement && currentEditMode === 'text') {
                applyFontSizeToSelectedElement(size + 'px');
            }
        }
        
        // 選択要素にフォントサイズを適用
        function applyFontSizeToSelectedElement(size) {
            if (!selectedElement) return;
            selectedElement.style.fontSize = size;
            showStatus(`フォントサイズを ${size} に変更しました`, 'success');
        }
        
        // フォントファミリーの更新
        function updateFontFamily(fontFamily) {
            if (selectedElement && currentEditMode === 'text') {
                selectedElement.style.fontFamily = fontFamily;
                showStatus(`フォントを ${fontFamily.split(',')[0]} に変更しました`, 'success');
            }
        }
        
        // カスタムフォントの追加
        function addCustomFont() {
            const input = document.getElementById('customFontInput');
            const fontName = input.value.trim();
            if (!fontName) return;
            
            const select = document.getElementById('fontFamilySelect');
            const option = document.createElement('option');
            option.value = `'${fontName}', sans-serif`;
            option.textContent = fontName;
            select.appendChild(option);
            select.value = option.value;
            
            updateFontFamily(option.value);
            input.value = '';
            showStatus(`カスタムフォント "${fontName}" を追加しました`, 'success');
        }
        
        // Google Fontsの読み込み
        function loadGoogleFont() {
            const input = document.getElementById('googleFontInput');
            const fontName = input.value.trim();
            if (!fontName) return;
            
            loadGoogleFontByName(fontName);
            input.value = '';
        }
        
        // 人気フォントの読み込み
        function loadPopularFont(fontName) {
            loadGoogleFontByName(fontName);
        }
        
        // Google Fontsを名前で読み込み
        function loadGoogleFontByName(fontName) {
            // Google Fonts APIを使用してフォントを読み込み
            const link = document.createElement('link');
            link.href = `https://fonts.googleapis.com/css2?family=${encodeURIComponent(fontName)}:wght@300;400;500;700&display=swap`;
            link.rel = 'stylesheet';
            document.head.appendChild(link);
            
            // フォント選択リストに追加
            const select = document.getElementById('fontFamilySelect');
            const option = document.createElement('option');
            option.value = `'${fontName}', sans-serif`;
            option.textContent = fontName;
            select.appendChild(option);
            select.value = option.value;
            
            // 選択要素に適用
            updateFontFamily(option.value);
            
            showStatus(`Google Font "${fontName}" を読み込みました`, 'success');
        }
        
        // フォントスタイルの切り替え
        function toggleFontStyle(style) {
            if (!selectedElement || currentEditMode !== 'text') return;
            
            const button = event.target;
            const isActive = button.classList.contains('active');
            
            switch (style) {
                case 'bold':
                    selectedElement.style.fontWeight = isActive ? 'normal' : 'bold';
                    break;
                case 'italic':
                    selectedElement.style.fontStyle = isActive ? 'normal' : 'italic';
                    break;
                case 'underline':
                    selectedElement.style.textDecoration = isActive ? 'none' : 'underline';
                    break;
            }
            
            button.classList.toggle('active');
            showStatus(`フォント${style}を${isActive ? '解除' : '適用'}しました`, 'success');
        }
        
        // テキスト選択の保存と復元
        let savedTextSelection = null;
        
        function saveTextSelection() {
            const iframe = document.getElementById('previewFrame');
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            const selection = iframeDoc.getSelection();
            
            if (selection.rangeCount > 0) {
                savedTextSelection = {
                    range: selection.getRangeAt(0).cloneRange(),
                    text: selection.toString()
                };
                console.log('Text selection saved:', savedTextSelection.text);
                showStatus(`テキスト選択を保存しました: "${savedTextSelection.text.substring(0, 20)}..."`, 'info');
            }
        }
        
        function restoreTextSelection() {
            if (!savedTextSelection) return;
            
            const iframe = document.getElementById('previewFrame');
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            const selection = iframeDoc.getSelection();
            
            try {
                selection.removeAllRanges();
                selection.addRange(savedTextSelection.range);
                console.log('Text selection restored:', savedTextSelection.text);
                showStatus(`テキスト選択を復元しました: "${savedTextSelection.text.substring(0, 20)}..."`, 'success');
            } catch (e) {
                console.error('Failed to restore text selection:', e);
                showStatus('テキスト選択の復元に失敗しました', 'error');
            }
        }
        
        function clearSavedTextSelection() {
            savedTextSelection = null;
            showStatus('保存されたテキスト選択をクリアしました', 'info');
        }
        
        // ズームリセット
        function resetZoom() {
            const iframe = document.getElementById('previewFrame');
            iframe.style.transform = 'scale(1)';
            showStatus('ズームをリセットしました', 'success');
        }
        
        // 要素情報の表示
        function showElementInfo(element) {
            const tagName = element.tagName.toLowerCase();
            const className = element.className ? ` (${element.className})` : '';
            const text = element.textContent ? ` - "${element.textContent.substring(0, 20)}..."` : '';
            
            showStatus(`選択: ${tagName}${className}${text}`, 'info');
        }
        
        // ドラッグ&ドロップのセットアップ
        function setupDragAndDrop(iframeDoc) {
            iframeDoc.addEventListener('mousedown', function(e) {
                if (currentEditMode !== 'move' || !selectedElement) return;
                
                isDragging = true;
                dragStartPos = { x: e.clientX, y: e.clientY };
                
                const computedStyle = window.getComputedStyle(selectedElement);
                elementStartPos = {
                    x: parseInt(computedStyle.left) || 0,
                    y: parseInt(computedStyle.top) || 0
                };
                
                // 要素を絶対位置に変更
                if (computedStyle.position === 'static') {
                    selectedElement.style.position = 'relative';
                }
                
                selectedElement.classList.add('dragging');
                e.preventDefault();
            });
            
            iframeDoc.addEventListener('mousemove', function(e) {
                if (!isDragging || !selectedElement) return;
                
                const deltaX = e.clientX - dragStartPos.x;
                const deltaY = e.clientY - dragStartPos.y;
                
                const newX = elementStartPos.x + deltaX;
                const newY = elementStartPos.y + deltaY;
                
                selectedElement.style.left = newX + 'px';
                selectedElement.style.top = newY + 'px';
                
                // 選択ハイライトも更新
                updateSelectionHighlight();
                
                e.preventDefault();
            });
            
            iframeDoc.addEventListener('mouseup', function(e) {
                if (isDragging) {
                    isDragging = false;
                    if (selectedElement) {
                        selectedElement.classList.remove('dragging');
                        showStatus('要素の位置を変更しました', 'success');
                    }
                }
            });
        }
        
        // リサイズ開始
        function startResize(e, direction) {
            if (!selectedElement) return;
            
            isResizing = true;
            currentResizeHandle = direction;
            dragStartPos = { x: e.clientX, y: e.clientY };
            
            const rect = selectedElement.getBoundingClientRect();
            resizeStartSize = {
                width: rect.width,
                height: rect.height,
                left: rect.left,
                top: rect.top
            };
            
            selectedElement.classList.add('resizing');
            
            // グローバルマウスイベントを追加
            document.addEventListener('mousemove', handleResize);
            document.addEventListener('mouseup', stopResize);
            
            e.preventDefault();
            e.stopPropagation();
        }
        
        // リサイズ処理
        function handleResize(e) {
            if (!isResizing || !selectedElement) return;
            
            const deltaX = e.clientX - dragStartPos.x;
            const deltaY = e.clientY - dragStartPos.y;
            
            let newWidth = resizeStartSize.width;
            let newHeight = resizeStartSize.height;
            let newLeft = resizeStartSize.left;
            let newTop = resizeStartSize.top;
            
            // リサイズハンドルの方向に応じて計算
            switch (currentResizeHandle) {
                case 'se': // 右下
                    newWidth = resizeStartSize.width + deltaX;
                    newHeight = resizeStartSize.height + deltaY;
                    break;
                case 'sw': // 左下
                    newWidth = resizeStartSize.width - deltaX;
                    newHeight = resizeStartSize.height + deltaY;
                    newLeft = resizeStartSize.left + deltaX;
                    break;
                case 'ne': // 右上
                    newWidth = resizeStartSize.width + deltaX;
                    newHeight = resizeStartSize.height - deltaY;
                    newTop = resizeStartSize.top + deltaY;
                    break;
                case 'nw': // 左上
                    newWidth = resizeStartSize.width - deltaX;
                    newHeight = resizeStartSize.height - deltaY;
                    newLeft = resizeStartSize.left + deltaX;
                    newTop = resizeStartSize.top + deltaY;
                    break;
                case 'e': // 右
                    newWidth = resizeStartSize.width + deltaX;
                    break;
                case 'w': // 左
                    newWidth = resizeStartSize.width - deltaX;
                    newLeft = resizeStartSize.left + deltaX;
                    break;
                case 's': // 下
                    newHeight = resizeStartSize.height + deltaY;
                    break;
                case 'n': // 上
                    newHeight = resizeStartSize.height - deltaY;
                    newTop = resizeStartSize.top + deltaY;
                    break;
            }
            
            // 最小サイズを制限
            newWidth = Math.max(20, newWidth);
            newHeight = Math.max(20, newHeight);
            
            // 要素のスタイルを更新
            selectedElement.style.width = newWidth + 'px';
            selectedElement.style.height = newHeight + 'px';
            
            if (newLeft !== resizeStartSize.left) {
                selectedElement.style.left = (newLeft - resizeStartSize.left) + 'px';
            }
            if (newTop !== resizeStartSize.top) {
                selectedElement.style.top = (newTop - resizeStartSize.top) + 'px';
            }
            
            // 選択ハイライトを更新
            updateSelectionHighlight();
        }
        
        // リサイズ終了
        function stopResize(e) {
            if (isResizing) {
                isResizing = false;
                currentResizeHandle = null;
                
                if (selectedElement) {
                    selectedElement.classList.remove('resizing');
                    showStatus('要素のサイズを変更しました', 'success');
                }
                
                // グローバルイベントリスナーを削除
                document.removeEventListener('mousemove', handleResize);
                document.removeEventListener('mouseup', stopResize);
            }
        }
        
        // 選択ハイライトの更新
        function updateSelectionHighlight() {
            if (!selectedElement) return;
            
            const highlight = document.getElementById('current-selection');
            if (!highlight) return;
            
            const rect = selectedElement.getBoundingClientRect();
            const iframe = document.getElementById('previewFrame');
            const iframeRect = iframe.getBoundingClientRect();
            
            highlight.style.left = (rect.left) + 'px';
            highlight.style.top = (rect.top) + 'px';
            highlight.style.width = rect.width + 'px';
            highlight.style.height = rect.height + 'px';
        }
        
        // 初期化時にデフォルトモードを設定
        document.addEventListener('DOMContentLoaded', function() {
            setEditMode('select');
        });
        
        function toggleComparison() {
            isComparisonMode = !isComparisonMode;
            const comparisonView = document.getElementById('comparison-view');
            const singleView = document.getElementById('single-preview');
            const toggleBtn = document.getElementById('toggleComparisonBtn');
            
            if (isComparisonMode) {
                comparisonView.style.display = 'block';
                singleView.style.display = 'none';
                toggleBtn.textContent = '📋 通常プレビューに戻る';
                updateComparisonView();
            } else {
                comparisonView.style.display = 'none';
                singleView.style.display = 'block';
                toggleBtn.textContent = '🔄 変更前後の比較を表示';
            }
        }
        
        function updateComparisonView() {
            const beforePreview = document.getElementById('before-preview');
            const afterPreview = document.getElementById('after-preview');
            
            // 変更前のプレビューを生成（オリジナル値使用）
            beforePreview.innerHTML = generateComparisonPreview(originalValues);
            
            // 変更後のプレビューを生成（現在の値使用）
            const currentValues = getCurrentInputValues();
            afterPreview.innerHTML = generateComparisonPreview(currentValues);
        }
        
        function generateComparisonPreview(values) {
            return `
                <div style="margin-bottom: 8px;">
                    <strong style="font-size: 10px;">📊 テーブル</strong>
                    <table style="width: 100%; font-size: 9px; color: ${values.table_text_color || '#ffffff'}; background: ${values.table_bg_color || '#0a0f1a'};">
                        <thead>
                            <tr style="background: ${values.table_header_bg || '#1a2332'}; color: ${values.table_header_color || '#ffffff'};">
                                <th style="padding: 2px;">ID</th>
                                <th style="padding: 2px;">タイトル</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="padding: 2px;">1</td>
                                <td style="padding: 2px;">サンプル</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div style="margin-bottom: 8px;">
                    <strong style="font-size: 10px;">🧭 ナビ</strong>
                    <div style="display: flex; gap: 4px; font-size: 9px;">
                        <span style="color: ${values.nav_text_color || '#d8e1ff'};">ホーム</span>
                        <span style="color: ${values.accent_color || '#00eaff'};">アクティブ</span>
                    </div>
                </div>
                <div>
                    <strong style="font-size: 10px;">📝 テキスト</strong>
                    <p style="font-size: 9px; margin: 2px 0;">通常テキスト</p>
                    <p style="font-size: 9px; margin: 2px 0; color: ${values.muted_text_color || '#8aa0c8'};">ミュート</p>
                    <button style="font-size: 8px; padding: 2px 4px; color: ${values.button_text_color || '#ffffff'}; border: 1px solid ${values.accent_color || '#00eaff'}; background: transparent;">ボタン</button>
                </div>
            `;
        }
        
        function getCurrentInputValues() {
            const values = {};
            const inputs = document.querySelectorAll('.style-control input');
            inputs.forEach(input => {
                values[input.id] = input.value;
            });
            return values;
        }
        
        function loadSelectedPage() {
            const select = document.getElementById('pageSelect');
            const selectedUrl = select.value;
            
            if (!selectedUrl) {
                showStatus('ページを選択してください', 'error');
                return;
            }
            
            const iframe = document.getElementById('previewFrame');
            const container = document.querySelector('.iframe-container');
            
            // 同一オリジン化のため /preview 経由で読み込む
            const base = (localStorage.getItem('STYLE_BASE_URL') || '').trim();
            const full = base ? base.replace(/\/$/, '') + selectedUrl : (window.location.origin + selectedUrl);
            // 観測強化: UI 側の STYLE_BASE_URL をクエリに付与し、FixLog で相関可能にする
            const styleBase = (base || window.location.origin).trim();
            const styleParam = `&style_base_url=${encodeURIComponent(styleBase)}`;
            iframe.src = '/preview?target=' + encodeURIComponent(full) + styleParam;
            container.style.display = 'block';
            
            // iframe読み込み完了時の処理
            iframe.onload = function() {
                try {
                    setupIframeInteraction();
                    showStatus(`${select.options[select.selectedIndex].text} を読み込みました`, 'success');
                } catch (error) {
                    showStatus('iframe設定エラー: ' + error.message, 'error');
                }
            };
        }
        

        
        function highlightElementForEditing(element) {
            // 編集対象要素をハイライト
            const tagName = element.tagName.toLowerCase();
            let styleCategory = '';
            
            if (tagName === 'table' || tagName === 'th' || tagName === 'td') {
                styleCategory = 'table';
            } else if (tagName === 'button') {
                styleCategory = 'button';
            } else if (tagName === 'nav' || element.classList.contains('nav')) {
                styleCategory = 'nav';
            }
            
            if (styleCategory) {
                showStatus(`${styleCategory} 要素が選択されました。左側のコントロールで調整してください。`, 'info');
                
                // 対応するコントロールをハイライト
                highlightRelevantControls(styleCategory);
            }
        }
        
        function highlightRelevantControls(category) {
            // すべてのコントロールのハイライトをクリア
            document.querySelectorAll('.style-control').forEach(control => {
                control.style.border = '1px solid rgba(255,255,255,0.1)';
            });
            
            // 関連するコントロールをハイライト
            const relevantIds = [];
            if (category === 'table') {
                relevantIds.push('table_text_color', 'table_bg_color', 'table_header_color', 'table_header_bg');
            } else if (category === 'button') {
                relevantIds.push('button_text_color');
            } else if (category === 'nav') {
                relevantIds.push('nav_text_color');
            }
            
            relevantIds.forEach(id => {
                const control = document.getElementById(id)?.closest('.style-control');
                if (control) {
                    control.style.border = '2px solid #00eaff';
                    control.style.boxShadow = '0 0 10px rgba(0,234,255,0.3)';
                }
            });
        }
        
        function updateInputs(styles) {
            for (const [key, value] of Object.entries(styles)) {
                const input = document.getElementById(key);
                if (input) {
                    input.value = value;
                }
            }
        }
        
        function applyStyles() {
            const styles = {};
            const inputs = document.querySelectorAll('.style-control input');
            
            inputs.forEach(input => {
                styles[input.id] = input.value;
            });
            
            fetch(api('/api/styles'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ styles: styles })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showStatus('スタイルが適用されました！ページを更新してください。', 'success');
                    // 動的CSSを再読み込み
                    reloadDynamicCSS();
                } else {
                    showStatus('エラー: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showStatus('適用エラー: ' + error, 'error');
            });
        }
        
        function resetStyles() {
            if (confirm('スタイルをデフォルトにリセットしますか？')) {
                fetch(api('/api/styles/reset'), {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateInputs(data.styles);
                        showStatus('デフォルトスタイルにリセットしました', 'success');
                        reloadDynamicCSS();
                    } else {
                        showStatus('リセットエラー: ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    showStatus('リセットエラー: ' + error, 'error');
                });
            }
        }
        
        function reloadDynamicCSS() {
            // 動的CSSファイルを再読み込み
            const link = document.querySelector('link[href*="dynamic_overrides.css"]');
            if (link) {
                const newLink = link.cloneNode();
                newLink.href = link.href + '?t=' + new Date().getTime();
                link.parentNode.replaceChild(newLink, link);
            }
            
            // iframe内のCSSも更新
            updateIframeStyles();
        }
        
        function updatePreviewRealtime() {
            const styles = {};
            const inputs = document.querySelectorAll('.style-control input');
            
            inputs.forEach(input => {
                styles[input.id] = input.value;
            });
            
            // プレビューボックスのスタイルを即座に更新
            updatePreviewBoxes(styles);
            
            // iframe内のスタイルも更新
            updateIframeStyles(styles);
            
            // 比較モードの場合は比較ビューも更新
            if (isComparisonMode) {
                updateComparisonView();
            }
            
            // 変更されたスタイルの数を表示
            const changedCount = Object.keys(styles).filter(key => 
                styles[key] !== originalValues[key]
            ).length;
            
            if (changedCount > 0) {
                showStatus(`${changedCount} 個の設定が変更されています`, 'info');
                highlightChangedElements();
            }
        }
        
        function updateIframeStyles(styles = null) {
            const iframe = document.getElementById('previewFrame');
            if (!iframe || !iframe.contentDocument) return;
            
            try {
                const iframeDoc = iframe.contentDocument;
                let styleElement = iframeDoc.getElementById('dynamic-preview-styles');
                
                if (!styleElement) {
                    styleElement = iframeDoc.createElement('style');
                    styleElement.id = 'dynamic-preview-styles';
                    iframeDoc.head.appendChild(styleElement);
                }
                
                if (styles) {
                    const css = generatePreviewCSS(styles);
                    styleElement.textContent = css;
                }
            } catch (error) {
                console.log('iframe style update restricted:', error);
            }
        }
        
        function generatePreviewCSS(styles) {
            return `
                table th, table td {
                    color: ${styles.table_text_color || currentStyles.table_text_color} !important;
                }
                table th {
                    background: ${styles.table_header_bg || currentStyles.table_header_bg} !important;
                    color: ${styles.table_header_color || currentStyles.table_header_color} !important;
                }
                table td {
                    background: ${styles.table_bg_color || currentStyles.table_bg_color} !important;
                }
                button {
                    color: ${styles.button_text_color || currentStyles.button_text_color} !important;
                }
                nav, .nav {
                    color: ${styles.nav_text_color || currentStyles.nav_text_color} !important;
                }
                .accent {
                    color: ${styles.accent_color || currentStyles.accent_color} !important;
                }
                .muted {
                    color: ${styles.muted_text_color || currentStyles.muted_text_color} !important;
                }
            `;
        }
        
        function showStatus(message, type) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            
            if (type === 'success') {
                statusDiv.style.background = 'rgba(25, 180, 120, 0.2)';
                statusDiv.style.color = '#6ff3c2';
            } else if (type === 'error') {
                statusDiv.style.background = 'rgba(200, 50, 60, 0.2)';
                statusDiv.style.color = '#ff9aa0';
            } else if (type === 'info') {
                statusDiv.style.background = 'rgba(255, 165, 0, 0.2)';
                statusDiv.style.color = '#ffb366';
            } else {
                statusDiv.style.background = 'rgba(0,234,255,0.1)';
                statusDiv.style.color = '#00eaff';
            }
        }
        
        // リアルタイムプレビュー機能
        document.querySelectorAll('.style-control input').forEach(input => {
            // 初期値を保存
            originalValues[input.id] = input.value;
            
            input.addEventListener('input', function() {
                updatePreviewRealtime();
                highlightChangedElements(input.id);
            });
        });
        
        function updatePreviewRealtime() {
            // プレビューエリアのスタイルを即座に更新
            const root = document.documentElement;
            const inputs = document.querySelectorAll('.style-control input');
            
            inputs.forEach(input => {
                const cssVar = '--dynamic-' + input.id.replace(/_/g, '-');
                root.style.setProperty(cssVar, input.value);
            });
        }
        
        function highlightChangedElements(changedInputId) {
            // 変更されたスタイルに関連するプレビューボックスをハイライト
            const elementMap = {
                'table_text_color': ['table-preview'],
                'table_bg_color': ['table-preview'],
                'table_header_color': ['table-preview'],
                'table_header_bg': ['table-preview'],
                'button_text_color': ['table-preview', 'text-preview'],
                'nav_text_color': ['nav-preview'],
                'accent_color': ['nav-preview'],
                'muted_text_color': ['text-preview']
            };
            
            // 全てのハイライトをクリア
            document.querySelectorAll('.preview-box').forEach(box => {
                box.classList.remove('highlight');
            });
            document.querySelectorAll('.change-indicator').forEach(indicator => {
                indicator.classList.remove('active');
            });
            
            // 変更があった要素をハイライト
            if (elementMap[changedInputId]) {
                elementMap[changedInputId].forEach(elementId => {
                    const element = document.getElementById(elementId);
                    const indicator = document.getElementById(elementId.replace('-preview', '-indicator'));
                    
                    if (element) {
                        element.classList.add('highlight');
                        // 3秒後にハイライトを削除
                        setTimeout(() => {
                            element.classList.remove('highlight');
                        }, 3000);
                    }
                    
                    if (indicator) {
                        indicator.classList.add('active');
                        // 3秒後にインジケーターを非表示
                        setTimeout(() => {
                            indicator.classList.remove('active');
                        }, 3000);
                    }
                });
            }
            
            // 変更状況をステータスに表示
            const changedCount = Object.keys(originalValues).filter(key => {
                const input = document.getElementById(key);
                return input && input.value !== originalValues[key];
            }).length;
            
            if (changedCount > 0) {
                showStatus(`${changedCount}個の設定が変更されています - 「適用」ボタンで保存`, 'info');
            } else {
                showStatus('準備完了 - 上記の色を調整して「適用」ボタンを押してください', 'default');
            }
        }
        
        // 選択要素情報パネルの管理
        function updateSelectionInfoPanel() {
            const panel = document.getElementById('selectionInfoPanel');
            const selectionList = document.getElementById('selectionList');
            
            if (!panel || !selectionList) {
                return;
            }
            
            // 選択要素がある場合はパネルを表示
            if (selectedElements.length > 0) {
                panel.style.display = 'block';
                
                // 選択リストを更新
                selectionList.innerHTML = '';
                
                selectedElements.forEach((selection, index) => {
                    const element = selection.element;
                    const rect = element.getBoundingClientRect();
                    const computedStyle = window.getComputedStyle(element);
                    
                    const selectionItem = document.createElement('div');
                    selectionItem.className = 'selection-item';
                    selectionItem.style.cssText = `
                        border: 1px solid #444;
                        border-radius: 6px;
                        padding: 12px;
                        margin-bottom: 8px;
                        background: rgba(0, 234, 255, 0.05);
                        position: relative;
                    `;
                    
                    selectionItem.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="background: #00eaff; color: #000; border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold;">${selection.id}</span>
                                <strong style="color: #00eaff;">${element.tagName.toLowerCase()}</strong>
                            </div>
                            <button class="deselect-btn" data-selection-id="${selection.id}" style="background: #ff4444; color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">削除</button>
                        </div>
                        
                        <div style="font-size: 11px; color: #ccc; line-height: 1.4;">
                            <div><strong>サイズ:</strong> ${Math.round(rect.width)}px × ${Math.round(rect.height)}px</div>
                            <div><strong>位置:</strong> (${Math.round(rect.left)}, ${Math.round(rect.top)})</div>
                            <div><strong>背景色:</strong> ${computedStyle.backgroundColor || 'transparent'}</div>
                            <div><strong>文字色:</strong> ${computedStyle.color || 'inherit'}</div>
                            <div><strong>フォント:</strong> ${computedStyle.fontSize} ${computedStyle.fontFamily.split(',')[0]}</div>
                            ${element.className ? `<div><strong>クラス:</strong> ${element.className}</div>` : ''}
                            ${element.id ? `<div><strong>ID:</strong> ${element.id}</div>` : ''}
                            ${element.textContent.trim() ? `<div><strong>テキスト:</strong> "${element.textContent.trim().substring(0, 30)}${element.textContent.trim().length > 30 ? '...' : ''}"</div>` : ''}
                        </div>
                    `;
                    
                    selectionList.appendChild(selectionItem);
                });
            } else {
                panel.style.display = 'none';
            }
        }
        
        // 選択要素の詳細情報を取得
        function getElementDetails(element) {
            const rect = element.getBoundingClientRect();
            const computedStyle = window.getComputedStyle(element);
            
            return {
                tagName: element.tagName.toLowerCase(),
                id: element.id || '',
                className: element.className || '',
                textContent: element.textContent.trim(),
                dimensions: {
                    width: Math.round(rect.width),
                    height: Math.round(rect.height),
                    x: Math.round(rect.left),
                    y: Math.round(rect.top)
                },
                styles: {
                    backgroundColor: computedStyle.backgroundColor,
                    color: computedStyle.color,
                    fontSize: computedStyle.fontSize,
                    fontFamily: computedStyle.fontFamily.split(',')[0].replace(/['"]/g, ''),
                    border: computedStyle.border,
                    margin: computedStyle.margin,
                    padding: computedStyle.padding
                }
            };
        }
        
        // 選択情報のエクスポート
        function exportSelections() {
            const exportData = selectedElements.map(selection => ({
                id: selection.id,
                timestamp: selection.timestamp,
                details: getElementDetails(selection.element)
            }));
            
            const dataStr = JSON.stringify(exportData, null, 2);
            const dataBlob = new Blob([dataStr], {type: 'application/json'});
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `element-selections-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
            link.click();
            
            URL.revokeObjectURL(url);
            showStatus('選択情報をエクスポートしました', 'success');
        }
        
        // イベントリスナーの設定
        document.addEventListener('DOMContentLoaded', function() {
            // パネル閉じるボタン
            const closeBtn = document.getElementById('closeSelectionPanel');
            if (closeBtn) {
                closeBtn.addEventListener('click', function() {
                    document.getElementById('selectionInfoPanel').style.display = 'none';
                });
            }
            
            // 全選択解除ボタン
            const clearAllBtn = document.getElementById('clearAllSelectionsBtn');
            if (clearAllBtn) {
                clearAllBtn.addEventListener('click', function() {
                    clearAllSelections();
                    updateSelectionInfoPanel();
                    showStatus('全ての選択を解除しました', 'info');
                });
            }
            
            // エクスポートボタン
            const exportBtn = document.getElementById('exportSelectionsBtn');
            if (exportBtn) {
                exportBtn.addEventListener('click', exportSelections);
            }
            
            // 個別削除ボタンのイベント委譲
            document.addEventListener('click', function(e) {
                if (e.target.classList.contains('deselect-btn')) {
                    const selectionId = parseInt(e.target.getAttribute('data-selection-id'));
                    deselectElement(selectionId);
                    updateSelectionInfoPanel();
                    showStatus(`選択 #${selectionId} を解除しました`, 'info');
                }
            });
        });
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    # テスト用
    app = Flask(__name__)
    style_manager = create_style_api(app)
    app.run(debug=True, port=5003)
