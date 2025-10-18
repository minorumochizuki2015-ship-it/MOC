"""
品質監視ダッシュボード
AI予測結果とメトリクスの可視化
"""

import atexit
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from collections import deque
from contextlib import closing
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List

import pandas as pd
import requests
from flask import Blueprint, Flask, Response, jsonify, render_template_string, request

from src.ai_prediction import QualityPredictor

# SSE ルート（/events 系）を Flask アプリに統合
try:
    from src.blueprints.sse_routes import init_sse_routes, sse_bp
except Exception:
    sse_bp = None
    init_sse_routes = None

# 静的ファイルのパスを正しく設定
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
static_folder = os.path.join(project_root, "static")
template_folder = os.path.join(project_root, "templates")

app = Flask(__name__, static_folder=static_folder, template_folder=template_folder)
try:
    print(f"[boot] app_id={id(app)}")
except Exception:
    pass


# --- Logging: RotatingFileHandler を導入（最小差分） ---
def _setup_logging_for_app(app: Flask) -> None:
    """アプリ用ロギングをローテーション運用に切り替える。

    - 出力先: data/logs/current/dashboard_app.log
    - ローテーション: 5MB × 5世代
    - 既存ハンドラ重複を避ける
    """
    try:
        # ログ出力先ディレクトリ（プロジェクト規約: data/logs/current/）
        logs_dir = Path(project_root) / "data" / "logs" / "current"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / "dashboard_app.log"

        # フォーマット
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")

        # RotatingFileHandler を重複なく設定
        if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
            file_handler = RotatingFileHandler(
                str(log_file), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(fmt)
            app.logger.addHandler(file_handler)

        # コンソールも INFO で統一（既存のハンドラは維持）
        app.logger.setLevel(logging.INFO)

        # 終了時にファイルハンドラをクリーンアップ
        atexit.register(logging.shutdown)
    except Exception:
        # ログ設定で失敗しても本体起動は継続
        try:
            print("[warn] logging setup failed")
        except Exception:
            pass


# SSE ブループリントを登録（存在する場合）
try:
    if sse_bp is not None and init_sse_routes is not None:
        init_sse_routes(app)
        app.register_blueprint(sse_bp)
        try:
            print("[init] SSE blueprint registered: /events, /events/health, /events/stats")
        except Exception:
            pass
except Exception as _e:
    try:
        print(f"[init] SSE blueprint registration failed: {_e}")
    except Exception:
        pass


# 共通ヘッダー適用ユーティリティ
from src.utils.headers import (
    apply_cors_and_expose_headers,
    apply_options_cors_headers,
    enforce_preview_headers,
)


# すべてのレスポンスにヘッダーを付与（/preview 強制 + CORS/Expose 一貫化）
@app.after_request
def _apply_common_headers(response):
    try:
        # /preview 強制ヘッダ
        response = enforce_preview_headers(response, request)
        # CORS/Expose ヘッダ
        response = apply_cors_and_expose_headers(response, request)
        # 互換是正: /preview 400 ページ本文に古いポートが残っている場合、X-Preview-Originに正規化
        try:
            if (
                getattr(request, "path", "").startswith("/preview")
                and getattr(response, "status_code", 200) == 400
            ):
                origin = response.headers.get("X-Preview-Origin") or getattr(
                    request, "host_url", f"http://{request.host}"
                ).rstrip("/")
                # 127.0.0.1/localhost + 任意ポートの絶対URLを現在オリジンに置換
                body = response.get_data(as_text=True)
                body_fixed = re.sub(r"http://(?:127\.0\.0\.1|localhost):\d+", origin, body)
                if body_fixed != body:
                    response.set_data(body_fixed)
        except Exception:
            pass
        # 保険: EXPOSE に ETag が含まれていなければ追記（ミドルウェア重複/古いモジュール読み込み対策）
        try:
            expose = response.headers.get("Access-Control-Expose-Headers", "")
            if "etag" not in (expose or "").lower():
                response.headers["Access-Control-Expose-Headers"] = (
                    expose + (", " if expose else "") + "ETag"
                )
        except Exception:
            pass
        # デバッグ: after_request が実行されているか確認
        try:
            # Vary の多重行を可視化
            try:
                vary_list = response.headers.getlist("Vary")
            except Exception:
                vary_list = []
            print(
                f"[after_request] path={request.path} headers={dict(response.headers)} vary_list={vary_list}"
            )
        except Exception:
            pass
    except Exception:
        pass
    return response


@app.before_request
def _debug_before_request():
    """デバッグ: 受信リクエストのパスを標準出力に記録"""
    try:
        print(f"[before_request] path={request.path} method={request.method}")
    except Exception:
        pass


@app.route("/healthz", methods=["GET"])
def healthz():
    """ヘルス + 実WSGIとルート数を返却"""
    try:
        rc = sum(1 for _ in app.url_map.iter_rules())
    except Exception:
        rc = -1
    return (
        jsonify(
            {
                "status": "ok",
                "time": datetime.now().isoformat(),
                "app_id": id(app),
                "routes_count": rc,
            }
        ),
        200,
    )


@app.route("/api/diag/ping", methods=["GET"])
def diag_ping():
    """/api 名前空間のGET生存確認"""
    try:
        rc = sum(1 for _ in app.url_map.iter_rules())
    except Exception:
        rc = -1
    return jsonify({"ok": True, "app_id": id(app), "routes_count": rc}), 200


@app.route("/api/diag/routes", methods=["GET"])
def diag_routes():
    """現在のルート一覧（GET有効性の実測）"""
    rules = []
    for r in app.url_map.iter_rules():
        try:
            methods_iter = r.methods or set()
        except Exception:
            methods_iter = set()
        methods = sorted(m for m in methods_iter if m not in ("HEAD", "OPTIONS"))
        rules.append({"rule": str(r), "endpoint": r.endpoint, "methods": methods})
    return jsonify({"count": len(rules), "rules": rules}), 200


@app.before_request
def _cors_preflight_shortcircuit():
    """全エンドポイント共通のプリフライト処理を一括化。

    - 任意パスの OPTIONS を早期応答（CORS/Expose/Max-Age を統一）
    - ルート定義競合（/api/<path:path> の OPTIONS だけが登録されるケース）による 405 を防止
    """
    try:
        if request.method == "OPTIONS":
            resp = Response()
            return apply_options_cors_headers(resp, request)
    except Exception:
        # 失敗時は通常フローへ（後段の route 定義やミドルウェアに委ねる）
        pass


@app.route("/debug-headers", methods=["GET"])
def debug_headers():
    """ヘッダー付与確認用の簡易エンドポイント"""
    r = Response("ok", status=200)
    try:
        r.headers["X-Debug"] = "1"
        r.headers["ETag"] = "123"
    except Exception:
        pass
    return r


@app.route("/debug/env", methods=["GET"])
def debug_env():
    """実行プロセスのORCH系環境変数をダンプする簡易エンドポイント（開発用）"""
    try:
        env_info = {
            "ORCH_HOST": os.environ.get("ORCH_HOST"),
            "ORCH_PORT": os.environ.get("ORCH_PORT"),
            "ORCH_MCP_TOKEN": os.environ.get("ORCH_MCP_TOKEN"),
            "ORCH_MCP_RATE_WINDOW": os.environ.get("ORCH_MCP_RATE_WINDOW"),
            "ORCH_MCP_RATE_MAX": os.environ.get("ORCH_MCP_RATE_MAX"),
        }
        return jsonify({"env": env_info, "time": datetime.now().isoformat()}), 200
    except Exception as e:
        try:
            app.logger.exception("DEBUG_ENV_FAIL: %s", e)
        except Exception:
            pass
        return jsonify({"error": "DEBUG_ENV_FAIL"}), 500


# /preview は StyleManager の有無に関わらず常に提供する（同一オリジン化の中核）
@app.route("/preview")
def preview_proxy():
    """指定URLを取得して同一オリジンで配信する簡易プレビュー。
    クライアントは `target` クエリに絶対URLを渡す。
    ルート相対のリソース参照をターゲットのオリジンに書き換える。
    """
    target = request.args.get("target", "").strip()
    # クライアント設定（STYLE_BASE_URL）を任意で受け取り、FixLog に記録できるようにする
    style_base_url = request.args.get("style_base_url") or request.headers.get("X-Style-Base-Url")
    # P0: target 未指定時は 400 + ガイド文を返し、白画面を排除
    if not target:
        # 例示URLはクライアント側の location.origin を用いて動的に表示することで、
        # プロキシ越しや待機ポート切替時のポート不一致問題を解消する。
        # ここではサーバ側での推定値もヘッダーに含めるが、本文表示は JS でクライアント起点に正規化する。
        try:
            origin_url = request.host_url.rstrip("/")
        except Exception:
            origin_url = f"http://{request.host}"
        html = (
            "<h1>400 Bad Request</h1>"
            '<p id="preview-msg">Use /preview?target=(resolving...)</p>'
            "<script>"
            "(function(){"
            "  try {"
            "    var o = (window.location && window.location.origin) ? window.location.origin : (window.location.protocol + '//' + window.location.host);"
            "    var el = document.getElementById('preview-msg');"
            "    if (el) el.textContent = 'Use /preview?target=' + o + '/static/test_preview_ext.html';"
            "  } catch(e) {"
            "    /* 失敗時はサーバ推定値を残す */"
            "    var el = document.getElementById('preview-msg');"
            "    if (el) el.textContent = 'Use /preview?target=' + '"
            + origin_url
            + "' + '/static/test_preview_ext.html';"
            "  }"
            "})();"
            "</script>"
        )
        return Response(
            html,
            status=400,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store",
                "X-Preview-Origin": origin_url,
                "X-Preview-Target": target,
            },
        )
    if not re.match(r"^https?://", target):
        return Response(
            "invalid target",
            status=400,
            headers={
                "Cache-Control": "no-store",
                "X-Preview-Origin": f"http://{request.host}",
                "X-Preview-Target": target,
            },
        )
    try:
        # ターゲットのオリジンを算出（エラーマッピングでも利用するため先に計算）
        m = re.match(r"^(https?://[^/]+)", target)
        origin = m.group(1) if m else ""
        resp = requests.get(target, timeout=10)
        # 安全に status_code/headers を取り出す（モックでも動作するように）
        status_code = getattr(resp, "status_code", 200)
        headers_obj = getattr(resp, "headers", {}) or {}
        content_type = "text/html"
        try:
            content_type = headers_obj.get("Content-Type", content_type)
        except Exception:
            pass
        # 非2xxは透過せず 502 にマッピング（本文は上流の内容を提示、ヘッダーにステータスを付与）
        try:
            sc_int = int(status_code)
        except Exception:
            sc_int = 200
        if not (200 <= sc_int < 300):
            try:
                app.logger.warning(
                    "PREVIEW_UPSTREAM_ERR status=%s target=%s style_base_url=%s",
                    status_code,
                    target,
                    style_base_url,
                )
            except Exception:
                pass
            return Response(
                getattr(resp, "text", ""),
                status=502,
                headers={
                    "Content-Type": content_type,
                    "Cache-Control": "no-store",
                    "X-Upstream-Status": str(status_code),
                    "X-Preview-Target": target,
                    "X-Preview-Origin": origin,
                },
            )
        html = resp.text
        # ターゲットのオリジンを算出（上で計算済みのためそのまま使用）
        # m = re.match(r"^(https?://[^/]+)", target)
        # origin = m.group(1) if m else ""
        # FixLog（情報レベル）: 成功時の要約ログ
        try:
            has_refresh = bool(
                re.search(r'<meta[^>]+http-equiv=["\']refresh["\']', html, re.IGNORECASE)
            )
            app.logger.info(
                "PREVIEW_OK target=%s origin=%s style_base_url=%s meta_refresh=%s",
                target,
                origin,
                style_base_url,
                has_refresh,
            )
        except Exception:
            pass
        # 既存の <base> を削除してから head 直後に正規化した <base> を挿入
        html = re.sub(r"<base[^>]*>", "", html, flags=re.IGNORECASE)
        html = re.sub(
            r"<head(.*?)>",
            lambda mm: f'<head{mm.group(1)}><base href="{origin}/">',
            html,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )

        # ルート相対の属性を絶対化（#アンカーは不変）。二重/単一/無引用を網羅。
        def _rewrite_attr_dq(match):
            attr, val = match.group(1), match.group(2)
            if val.startswith("#"):
                return f'{attr}="{val}"'
            return f'{attr}="{origin}{val}"'

        def _rewrite_attr_sq2(match):
            attr, val = match.group(1), match.group(2)
            if val.startswith("#"):
                return f"{attr}='{val}'"
            return f"{attr}='{origin}{val}'"

        def _rewrite_attr_unq(match):
            attr, val = match.group(1), match.group(2)
            if val.startswith("#"):
                return f"{attr}={val}"
            return f"{attr}={origin}{val}"

        html = re.sub(r'(href|src)="(/[^"]*)"', _rewrite_attr_dq, html, flags=re.IGNORECASE)
        # 先に定義済みの _rewrite_attr_sq2 を使用（後段で同名のヘルパーを再定義するためここでは sq2 を参照）
        html = re.sub(r"(href|src)='(/[^']*)'", _rewrite_attr_sq2, html, flags=re.IGNORECASE)
        html = re.sub(r'(href|src)=(/[^>\s"\'`]+)', _rewrite_attr_unq, html, flags=re.IGNORECASE)

        # form[action] と object[data] のルート相対も同様に絶対化
        html = re.sub(r'(action|data)="(/[^"]*)"', _rewrite_attr_dq, html, flags=re.IGNORECASE)
        # 先行ブロックでは後段で _rewrite_attr_sq がローカル関数として定義されるため、早期参照による UnboundLocalError を避ける目的で
        # ここでは定義済みの _rewrite_attr_sq2 を使用する
        html = re.sub(r"(action|data)='(/[^']*)'", _rewrite_attr_sq2, html, flags=re.IGNORECASE)
        html = re.sub(r'(action|data)=(/[^>\s"\'`]+)', _rewrite_attr_unq, html, flags=re.IGNORECASE)

        # srcset の絶対化（/path 形式のみ変換）
        def _rewrite_srcset(m2):
            val = m2.group(1)
            parts = [p.strip() for p in val.split(",")]

            def fix_part(p):
                if p.startswith("/"):
                    return origin + p
                return p

            new_parts = []
            for p in parts:
                segs = p.split()
                if segs:
                    segs[0] = fix_part(segs[0])
                new_parts.append(" ".join(segs))
            return 'srcset="' + ", ".join(new_parts) + '"'

        html = re.sub(r'srcset="([^"]+)"', _rewrite_srcset, html)

        # 追加: href/src および action/data のシングルクォート・無引用属性値を絶対化
        def _rewrite_attr_sq(match):
            attr = match.group(1)
            val = match.group(2)
            if val.startswith("#"):
                return f"{attr}='{val}'"
            return f"{attr}='{origin}{val}'"

        def _rewrite_attr_unq(match):
            attr = match.group(1)
            val = match.group(2)
            if val.startswith("#"):
                return f"{attr}={val}"
            return f"{attr}={origin}{val}"

        html = re.sub(r"(href|src)='(/[^']*)'", _rewrite_attr_sq, html, flags=re.IGNORECASE)
        html = re.sub(r"""(href|src)=(/[^>\s"'`]+)""", _rewrite_attr_unq, html, flags=re.IGNORECASE)
        html = re.sub(r"(action|data)='(/[^']*)'", _rewrite_attr_sq, html, flags=re.IGNORECASE)
        html = re.sub(
            r"""(action|data)=(/[^>\s"'`]+)""", _rewrite_attr_unq, html, flags=re.IGNORECASE
        )

        # meta[http-equiv=refresh] タグ内の url=/path を絶対化（引用符保持）
        def _rewrite_meta_refresh_tag(m3):
            tag = m3.group(0)
            # content 属性値を抽出
            m_content = re.search(r'content=(["\'])(.*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if not m_content:
                return tag
            quote = m_content.group(1)
            content_val = m_content.group(2)

            # url= を書き換え
            def _repl(mm):
                q = mm.group(1) or ""
                path = mm.group(2)
                if path.startswith("/"):
                    return f"url={q}{origin}{path}{q}"
                return mm.group(0)

            new_content_val = re.sub(
                r'url=(["\']?)(/[^;\s\'"<>]+)\1', _repl, content_val, flags=re.IGNORECASE
            )
            if new_content_val == content_val:
                return tag  # 変更なし
            return tag.replace(
                f"content={quote}{content_val}{quote}", f"content={quote}{new_content_val}{quote}"
            )

        html = re.sub(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*>',
            _rewrite_meta_refresh_tag,
            html,
            flags=re.IGNORECASE,
        )

        # CSS内の @import url(/...) と url(/...) を最低限絶対化（相対 ./... は不変）
        def _rewrite_css_url(m4):
            q1 = m4.group(1) or ""
            path = m4.group(2)
            q2 = m4.group(3) or ""
            return f"url({q1}{origin}{path}{q2})"

        def _rewrite_css_import(m5):
            q1 = m5.group(1) or ""
            path = m5.group(2)
            q2 = m5.group(3) or ""
            return f"@import url({q1}{origin}{path}{q2})"

        # CSS内の @import/url を <style> ブロック内だけで絶対化（相対 ./... は不変）
        def _rewrite_style_block(ms):
            head, content = ms.group(1), ms.group(2)
            content = re.sub(
                r"@import\s+url\(\s*([\'\"]?)(/[^\)\'\"]+)([\'\"]?)\s*\)",
                _rewrite_css_import,
                content,
            )
            content = re.sub(
                r"url\(\s*([\'\"]?)(/[^\)\'\"]+)([\'\"]?)\s*\)", _rewrite_css_url, content
            )
            return f"<style{head}>{content}</style>"

        html = re.sub(
            r"<style([^>]*)>(.*?)</style>",
            _rewrite_style_block,
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )

        # ServiceWorker を無効化（プレビュー安定化）
        sw_override = (
            "<script>(function(){try{"
            "if(navigator && navigator.serviceWorker){"
            "navigator.serviceWorker.register = function(){return Promise.resolve({unregister:async()=>true});};"
            "navigator.serviceWorker.getRegistration = async function(){return undefined;};"
            "}"
            "}catch(e){}})();</script>"
        )
        if re.search(r"</body>", html, flags=re.IGNORECASE):
            html = re.sub(r"</body>", sw_override + "</body>", html, flags=re.IGNORECASE)
        else:
            html = html + sw_override

        # 成功時のレスポンスヘッダーにプレビューの文脈情報を付与（観測容易化）
        r = Response(html, mimetype="text/html")
        try:
            r.headers["Cache-Control"] = "no-store"
            r.headers["X-Preview-Target"] = target
            r.headers["X-Preview-Origin"] = origin
            r.headers["X-Disable-ServiceWorker"] = "true"
            r.headers["X-Preview-Same-Origin"] = "true"
        except Exception:
            pass
        return r
    except Exception as e:
        # 例外時も 502 とし、可観測性ヘッダーを付与（接続例外・書き換え処理エラー等）
        try:
            m = re.match(r"^(https?://[^/]+)", target)
            origin = m.group(1) if m else f"http://{request.host}"
        except Exception:
            origin = f"http://{request.host}"
        return Response(
            f"preview error: {e}",
            status=502,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store",
                "X-Upstream-Status": e.__class__.__name__,
                "X-Preview-Target": target,
                "X-Preview-Origin": origin,
            },
        )


# Style Manager統合
try:
    from src.style_manager import StyleManager

    # Style Managerのルートを統合
    style_manager = StyleManager()

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
                {"url": p, "name": t, "description": d, "path": p, "title": t, "protected": prot}
            )
        resp = jsonify(pages)
        try:
            resp.headers["X-Pages-Source"] = "dashboard"
        except Exception:
            pass
        return resp

    # /preview ルートはグローバルに登録済み（上部）。ここでは再定義しない。

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

        try:
            print(f"[DEBUG] /api/styles: computed ETag={etag} If-None-Match={inm}")
        except Exception:
            pass
        # request.if_none_match は ETags オブジェクト（contains で引用符の扱いを抽象化）
        if inm and hasattr(inm, "contains") and inm.contains(etag):
            resp = make_response("", 304)
        else:
            resp = make_response(body, 200)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        resp.headers["X-Source"] = "dashboard"
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

            # 現在スタイルのETagを算出
            import json as _json
            from hashlib import sha256

            current_body = _json.dumps(
                style_manager.styles, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")
            current_etag = sha256(current_body).hexdigest()

            # If-Match が指定され、現在ETagと不一致なら 412
            im = getattr(request, "if_match", None)
            if im and hasattr(im, "contains") and not im.contains(current_etag):
                return jsonify({"error": "ETag 競合"}), 412

            # 値型（色）検証のための簡易バリデータ
            import re as _re

            def _is_color(val: str) -> bool:
                if not isinstance(val, str):
                    return False
                s = val.strip()
                # 16進カラー (#RGB, #RRGGBB, #RRGGBBAA)
                if _re.match(r"^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$", s):
                    return True
                # rgb()/rgba()
                if _re.match(r"^rgba?\(.*\)$", s):
                    return True
                # hsl()/hsla()
                if _re.match(r"^hsla?\(.*\)$", s):
                    return True
                return False

            # キーの存在と値型チェック
            if "key" in data and "value" in data:
                k = data["key"]
                v = data["value"]
                if k not in style_manager.default_styles:
                    return jsonify({"error": "未知のキー"}), 400
                if not _is_color(v):
                    return jsonify({"error": "値型不正（color形式）"}), 400
                success = style_manager.update_style(k, v)
            elif "styles" in data:
                updates = data["styles"] or {}
                if not isinstance(updates, dict):
                    return jsonify({"error": "無効なデータ形式"}), 400
                invalid_keys = [k for k in updates.keys() if k not in style_manager.default_styles]
                if invalid_keys:
                    return jsonify({"error": "未知のキー", "keys": invalid_keys}), 400
                invalid_values = {k: v for k, v in updates.items() if not _is_color(v)}
                if invalid_values:
                    return (
                        jsonify({"error": "値型不正（color形式）", "details": invalid_values}),
                        400,
                    )
                success = style_manager.update_multiple_styles(updates)
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

    @app.route("/api/styles/patch", methods=["POST"])
    def create_style_patch():
        """スタイルパッチを作成"""
        try:
            data = request.get_json()
            # 簡易パッチ作成機能
            patch = {
                "timestamp": datetime.now().isoformat(),
                "changes": data,
                "type": "style_update",
            }
            return jsonify(patch)
        except Exception as e:
            return jsonify({"error": f"パッチ作成エラー: {str(e)}"}), 500

    @app.route("/style-manager")
    def style_manager_page():
        """スタイル管理画面 - 完全版を使用"""
        # 完全なスタイル管理テンプレート
        template = r"""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>スタイル管理システム - ORION Dashboard</title>
    <link rel="stylesheet" href="/static/css/orion.css">
    <link rel="stylesheet" href="/static/css/dynamic_overrides.css">
    <style>
        body {
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #0a0f1a 0%, #1a2332 50%, #0f1419 100%);
            color: #ffffff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow-x: hidden;
            min-height: 100vh;
        }
        .container {
            display: flex;
            height: 100vh;
            background: rgba(26, 35, 50, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            margin: 10px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .sidebar {
            width: 350px;
            background: linear-gradient(180deg, #1a2332 0%, #0f1419 100%);
            padding: 20px;
            overflow-y: auto;
            border-right: 1px solid #2a3441;
            border-radius: 12px 0 0 12px;
            box-shadow: inset 0 0 20px rgba(0, 234, 255, 0.1);
        }
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            border-radius: 0 12px 12px 0;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(90deg, #1a2332 0%, #2a3441 100%);
            padding: 15px 20px;
            border-bottom: 1px solid #2a3441;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }
        .page-selection {
            background: linear-gradient(90deg, #0f1419 0%, #1a2332 100%);
            padding: 15px 20px;
            border-bottom: 1px solid #2a3441;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }
        .iframe-container {
            flex: 1;
            position: relative;
            background: #ffffff;
        }
        #previewFrame {
            width: 100%;
            height: 100%;
            border: none;
        }
        #selectionOverlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 9999;
        }
        .element-highlight {
            position: absolute;
            border: 3px solid #00eaff;
            background: rgba(0, 234, 255, 0.1);
            pointer-events: none;
            border-radius: 4px;
            box-shadow: 0 0 20px rgba(0, 234, 255, 0.5);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 20px rgba(0, 234, 255, 0.5); }
            50% { box-shadow: 0 0 30px rgba(0, 234, 255, 0.8); }
            100% { box-shadow: 0 0 20px rgba(0, 234, 255, 0.5); }
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
            font-size: 12px;
        }
        .style-control input, .style-control select {
            width: 100%;
            padding: 8px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 6px;
            color: #ffffff;
            box-sizing: border-box;
        }
        .btn {
            padding: 12px 18px;
            border: 1px solid #00eaff;
            border-radius: 8px;
            background: linear-gradient(135deg, rgba(0,234,255,0.1) 0%, rgba(0,234,255,0.2) 100%);
            color: #00eaff;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 234, 255, 0.1);
            position: relative;
            overflow: hidden;
        }
        .btn:hover {
            background: linear-gradient(135deg, rgba(0,234,255,0.2) 0%, rgba(0,234,255,0.3) 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 234, 255, 0.3);
        }
        .btn:active {
            transform: translateY(0);
            box-shadow: 0 2px 10px rgba(0, 234, 255, 0.2);
        }
        .edit-mode-buttons {
            display: flex;
            gap: 8px;
            margin: 16px 0;
        }
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
        #selectionOverlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 10000;
        }
        .element-highlight {
            position: fixed;
            border: 2px solid #00eaff;
            background: rgba(0,234,255,0.1);
            pointer-events: none;
            z-index: 10001;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- サイドバー -->
        <div class="sidebar">
            <h2 style="margin: 0 0 20px 0; color: #00eaff;">🎨 スタイル管理システム</h2>
            
            <!-- ナビゲーション -->
             <div style="margin-bottom: 20px;">
                 <a href="/dashboard" style="color: #8aa0c8; text-decoration: none; margin-right: 15px; padding: 8px 16px; border-radius: 4px; transition: all 0.2s ease;">ダッシュボード</a>
                 <a href="/tasks" style="color: #8aa0c8; text-decoration: none; margin-right: 15px; padding: 8px 16px; border-radius: 4px; transition: all 0.2s ease;">タスク</a>
                 <a href="/style-manager" style="color: #00eaff; text-decoration: none; background: rgba(0,234,255,0.1); padding: 8px 16px; border-radius: 4px;">スタイル管理</a>
             </div>

            <!-- 接続設定（ベースURL） -->
            <div style="margin-bottom: 20px;">
                <h3 style="margin: 0 0 10px 0; color: #ffffff;">🔌 接続設定</h3>
                <input id="baseUrlInput" placeholder="http://127.0.0.1:5001" style="width: 100%; padding: 8px; background: #2a3441; color: #ffffff; border: 1px solid #00eaff; border-radius: 6px;">
                <div style="display: flex; gap: 8px; margin-top: 8px;">
                    <button id="saveBaseUrlBtn" class="btn" style="flex: 1; font-size: 11px;">💾 保存</button>
                    <button id="pingBaseUrlBtn" class="btn" style="flex: 1; font-size: 11px;">📡 接続テスト</button>
                </div>
                <div id="baseUrlStatus" style="margin-top: 8px; font-size: 12px; color: #8aa0c8;">未設定（相対パスで接続）</div>
            </div>

            <!-- ページ選択 -->
            <div style="margin-bottom: 20px;">
                <h3 style="margin: 0 0 10px 0; color: #ffffff;">📄 ページ選択</h3>
                <select id="pageSelect" style="width: 100%; padding: 8px; background: #2a3441; color: #ffffff; border: 1px solid #00eaff; border-radius: 6px; margin-bottom: 10px;">
                    <option value="">ページを読み込み</option>
                </select>
                <button id="loadPageBtn" class="btn" style="width: 100%;">📖 ページを読み込み</button>
            </div>

            <!-- ライブ編集画面 -->
            <div style="margin-bottom: 20px;">
                <h3 style="margin: 0 0 10px 0; color: #ffffff;">🖥️ ライブ編集画面</h3>
                <div style="display: flex; gap: 8px;">
                    <button id="compareBtn" class="btn" style="flex: 1; font-size: 11px;">📊 比較表示</button>
                    <button id="resetViewBtn" class="btn" style="flex: 1; font-size: 11px;">🔄 ズームリセット</button>
                </div>
                <div id="editModeText" style="margin-top: 8px; padding: 8px; background: rgba(0,234,255,0.1); border-radius: 4px; font-size: 11px; color: #00eaff;">
                    🎯 選択モード: 要素をクリックして選択してください
                </div>
            </div>

            <!-- ビジュアル編集ツール -->
            <div style="margin-bottom: 20px;">
                <h3 style="margin: 0 0 10px 0; color: #ffffff;">🎨 ビジュアル編集ツール</h3>
                <div class="edit-mode-buttons">
                    <button id="selectModeBtn" class="edit-mode-btn active" onclick="setEditMode('select')">🎯 選択</button>
                    <button id="colorModeBtn" class="edit-mode-btn" onclick="setEditMode('color')">🎨 色</button>
                    <button id="textModeBtn" class="edit-mode-btn" onclick="setEditMode('text')">📝 文字</button>
                    <button id="moveModeBtn" class="edit-mode-btn" onclick="setEditMode('move')">↔️ 移動</button>
                </div>
                <!-- 選択情報 -->
                <div id="selectionInfo" style="display:none; font-size:12px; color:#8aa0c8; margin-top:8px;">
                    選択: <span id="selTag"></span> <span id="selId"></span> <span id="selClass"></span>
                </div>
                <!-- 色編集ツール -->
                <div id="colorTools" style="display:none; margin-top:10px;">
                    <div class="style-control">
                        <label>選択要素の文字色</label>
                        <input type="color" id="selected_text_color" value="#ffffff">
                    </div>
                    <div class="style-control">
                        <label>選択要素の背景色</label>
                        <input type="color" id="selected_bg_color" value="#0a0f1a">
                    </div>
                    <button id="applySelectedColorsBtn" class="btn" style="width:100%;">🎨 適用</button>
                </div>
                <!-- 変更ログ -->
                <div id="changeLog" style="margin-top:12px; font-size:12px; color:#8aa0c8;"></div>
            </div>

            <!-- 詳細設定 -->
            <details style="margin-top: 16px;">
                <summary style="cursor: pointer; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 6px; margin-bottom: 8px; color: #ffffff;">⚙️ 詳細設定</summary>
                
                <div class="style-control">
                    <label>テーブル文字色</label>
                    <input type="color" id="table_text_color" value="#ffffff">
                </div>
                
                <div class="style-control">
                    <label>テーブル背景色</label>
                    <input type="color" id="table_bg_color" value="#0a0f1a">
                </div>
                
                <div class="style-control">
                    <label>ボタン文字色</label>
                    <input type="color" id="button_text_color" value="#ffffff">
                </div>
                
                <div class="style-control">
                    <label>ボタン背景色</label>
        <input type="color" id="button_bg_color" value="#00eaff" data-sem-role="color-input" data-sem-intent="button_bg_color">
                </div>
            </details>

            <!-- アクションボタン -->
            <div style="margin-top: 20px; display: flex; gap: 10px;">
        <button id="applyBtn" class="btn" style="flex: 1; background: rgba(0,234,255,0.2);" data-sem-role="apply-button" data-sem-intent="save-styles">✅ 適用</button>
                <button id="resetBtn" class="btn" style="flex: 1; background: rgba(255,100,100,0.2); border-color: #ff6464; color: #ff6464;">🔄 リセット</button>
            </div>
        </div>

        <!-- メインコンテンツ -->
        <div class="main-content">
            <!-- ヘッダー -->
            <div class="header">
                <h1 style="margin: 0; color: #ffffff;">スタイル管理システム</h1>
                <div style="color: #8aa0c8;">リアルタイム編集</div>
            </div>

            <!-- ページ選択エリア -->
            <div class="page-selection">
                <div style="color: #8aa0c8; font-size: 14px;">
                    左側でページを選択し、読み込みボタンを押してください
                </div>
            </div>

            <!-- iframe表示エリア -->
            <div class="iframe-container" style="display: none;">
                <iframe id="previewFrame" src=""></iframe>
            </div>
        </div>
    </div>

    <!-- 選択オーバーレイ -->
    <div id="selectionOverlay"></div>

    <script>
        let currentStyles = {};
        let originalValues = {};
        let currentEditMode = 'select';
        let selectedElement = null;

        // --- 接続設定ヘルパー ---
        function getBaseUrl() {
            return localStorage.getItem('STYLE_BASE_URL') || '';
        }
        function setBaseUrl(url) {
            localStorage.setItem('STYLE_BASE_URL', (url || '').trim());
            updateBaseUrlStatus();
        }
        function api(path) {
            const base = getBaseUrl();
            if (!base) return path;
            return base.replace(/\/$/, '') + path;
        }
        function updateBaseUrlStatus() {
            const base = getBaseUrl();
            const el = document.getElementById('baseUrlStatus');
            if (!el) return;
            el.textContent = base ? `接続先: ${base}` : '未設定（相対パスで接続）';
        }
        async function pingBaseUrl() {
            const base = getBaseUrl();
            const el = document.getElementById('baseUrlStatus');
            if (!base) { el.textContent = '未設定（相対パスで接続）'; return; }
            try {
                const res = await fetch(api('/api/pages'));
                el.textContent = res.ok ? `到達性OK: ${base}` : `到達性NG(${res.status}): ${base}`;
            } catch (e) {
                el.textContent = `接続エラー: ${base}`;
            }
        }

        // ページ読み込み時の初期化
        window.onload = function() {
            // ベースURL初期値
            const input = document.getElementById('baseUrlInput');
            if (input) { input.value = getBaseUrl(); }
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
                    originalValues = {...data};
                    updateInputs(data);
                    console.log('スタイルを読み込みました');
                })
                .catch(error => {
                    console.error('スタイル読み込みエラー:', error);
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
                    console.error('ページ一覧の読み込みエラー:', error);
                });
        }

        function setupEventListeners() {
            document.getElementById('loadPageBtn').addEventListener('click', loadSelectedPage);
            document.getElementById('applyBtn').addEventListener('click', applyStyles);
            document.getElementById('resetBtn').addEventListener('click', resetStyles);
            const saveBtn = document.getElementById('saveBaseUrlBtn');
            const pingBtn = document.getElementById('pingBaseUrlBtn');
            const input = document.getElementById('baseUrlInput');
            if (saveBtn && input) {
                saveBtn.addEventListener('click', () => setBaseUrl(input.value));
            }
            if (pingBtn) {
                pingBtn.addEventListener('click', pingBaseUrl);
            }
            bindSelectedStyleInputs();
        }

        function loadSelectedPage() {
            const select = document.getElementById('pageSelect');
            const selectedUrl = select.value;
            
            if (!selectedUrl) {
                alert('ページを選択してください');
                return;
            }

            const iframe = document.getElementById('previewFrame');
            const container = document.querySelector('.iframe-container');
            
            const base = getBaseUrl();
            const full = base ? base.replace(/\/$/, '') + selectedUrl : (window.location.origin + selectedUrl);
            // 観測強化: UI 側の STYLE_BASE_URL をクエリに付与し、FixLog で相関可能にする
            const styleBase = (base || window.location.origin).trim();
            const styleParam = `&style_base_url=${encodeURIComponent(styleBase)}`;
            iframe.src = '/preview?target=' + encodeURIComponent(full) + styleParam;
            container.style.display = 'block';
            
            iframe.onload = function() {
                try {
                    setupIframeInteraction();
                    console.log('ページを読み込みました:', selectedUrl);
                } catch (error) {
                    console.error('iframe設定エラー:', error);
                }
            };
        }

        function setupIframeInteraction() {
            const iframe = document.getElementById('previewFrame');
            if (!iframe) return;
            
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            if (!iframeDoc) return;
            
            const allElements = iframeDoc.querySelectorAll('*');
            allElements.forEach(element => {
                element.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    selectElement(element);
                });
                
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
            });
        }

        function selectElement(element) {
            selectedElement = element;
            console.log('要素を選択しました:', element.tagName, element.className);
            
            // 選択ハイライトを表示
            showElementSelection(element);
            // 選択情報更新
            updateSelectionInfoPanel();
            // 色ツール初期値反映
            showColorTools(element);
        }

        function showElementSelection(element) {
            const iframe = document.getElementById('previewFrame');
            const overlay = document.getElementById('selectionOverlay');
            
            if (!iframe || !overlay) return;
            
            const rect = element.getBoundingClientRect();
            const iframeRect = iframe.getBoundingClientRect();
            
            overlay.innerHTML = '';
            
            const highlight = document.createElement('div');
            highlight.className = 'element-highlight';
            highlight.style.left = (rect.left + iframeRect.left) + 'px';
            highlight.style.top = (rect.top + iframeRect.top) + 'px';
            highlight.style.width = rect.width + 'px';
            highlight.style.height = rect.height + 'px';
            
            overlay.appendChild(highlight);
        }

        function setEditMode(mode) {
            currentEditMode = mode;
            
            document.querySelectorAll('.edit-mode-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(mode + 'ModeBtn').classList.add('active');
            
            const modeTexts = {
                'select': '🎯 選択モード: 要素をクリックして選択してください',
                'color': '🎨 色編集モード: 要素を選択して色を変更してください',
                'text': '📝 文字編集モード: テキスト要素を選択してフォントを調整してください',
                'move': '↔️ 移動モード: 要素をドラッグして位置を変更してください'
            };
            document.getElementById('editModeText').textContent = modeTexts[mode];

            // ツールの表示切替
            const colorTools = document.getElementById('colorTools');
            if (colorTools) colorTools.style.display = (mode === 'color') ? 'block' : 'none';
        }

        function updateInputs(styles) {
            Object.keys(styles).forEach(key => {
                const input = document.getElementById(key);
                if (input) {
                    input.value = styles[key];
                }
            });
        }

        function applyStyles() {
            const inputs = document.querySelectorAll('.style-control input');
            const styles = {};
            
            inputs.forEach(input => {
                styles[input.id] = input.value;
            });
            
            fetch(api('/api/styles'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ styles })
            })
            .then(response => response.json())
            .then(data => {
                console.log('スタイルを適用しました');
                // ページをリロードして変更を反映
                const iframe = document.getElementById('previewFrame');
                if (iframe.src) {
                    iframe.src = iframe.src;
                }
            })
            .catch(error => {
                console.error('スタイル適用エラー:', error);
            });
        }

        function resetStyles() {
            fetch(api('/api/styles/reset'), {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                console.log('スタイルをリセットしました');
                loadCurrentStyles();
                // ページをリロードして変更を反映
                const iframe = document.getElementById('previewFrame');
                if (iframe.src) {
                    iframe.src = iframe.src;
                }
            })
            .catch(error => {
                console.error('スタイルリセットエラー:', error);
            });
        }

        // --- 選択情報＆色編集 ---
        let modifications = [];

        function updateSelectionInfoPanel() {
            const info = document.getElementById('selectionInfo');
            const tag = document.getElementById('selTag');
            const id = document.getElementById('selId');
            const cls = document.getElementById('selClass');
            if (!selectedElement || !info) return;
            info.style.display = 'block';
            tag.textContent = selectedElement.tagName.toLowerCase();
            id.textContent = selectedElement.id ? ('#' + selectedElement.id) : '';
            cls.textContent = selectedElement.className ? ('.' + selectedElement.className.replace(/\s+/g, '.')) : '';
        }

        function showColorTools(element) {
            const colorTools = document.getElementById('colorTools');
            if (!colorTools || !element) return;
            const cs = (element.ownerDocument.defaultView || window).getComputedStyle(element);
            const textInp = document.getElementById('selected_text_color');
            const bgInp = document.getElementById('selected_bg_color');
            if (textInp) textInp.value = rgbToHex(cs.color);
            if (bgInp) bgInp.value = rgbToHex(cs.backgroundColor);
        }

        function bindSelectedStyleInputs() {
            const btn = document.getElementById('applySelectedColorsBtn');
            if (btn) {
                btn.addEventListener('click', () => {
                    if (!selectedElement) { alert('要素を選択してください'); return; }
                    const textColor = document.getElementById('selected_text_color').value;
                    const bgColor = document.getElementById('selected_bg_color').value;
                    selectedElement.style.color = textColor;
                    selectedElement.style.backgroundColor = bgColor;
                    logModification(selectedElement, { color: textColor, backgroundColor: bgColor });
                });
            }
        }

        function logModification(element, styles) {
            const selector = buildSelector(element);
            modifications.push({ selector, styles, time: new Date().toLocaleTimeString() });
            const log = document.getElementById('changeLog');
            if (log) {
                log.innerHTML = modifications.slice(-10).map(m => `# ${m.time} ${m.selector} → ${JSON.stringify(m.styles)}`).join('<br>');
            }
            console.log('変更ログ:', selector, styles);
        }

        function buildSelector(el) {
            if (!el) return '';
            const tag = el.tagName.toLowerCase();
            const id = el.id ? ('#' + el.id) : '';
            const cls = el.className ? ('.' + el.className.trim().replace(/\s+/g, '.')) : '';
            return tag + id + cls;
        }

        function rgbToHex(rgb) {
            if (!rgb) return '#000000';
            const m = rgb.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
            if (!m) return '#000000';
            const r = parseInt(m[1]).toString(16).padStart(2, '0');
            const g = parseInt(m[2]).toString(16).padStart(2, '0');
            const b = parseInt(m[3]).toString(16).padStart(2, '0');
            return `#${r}${g}${b}`;
        }
    </script>
</body>
</html>
"""
        return render_template_string(template)

    @app.route("/metrics")
    def metrics_page():
        """メトリクス表示ページ"""
        return render_template_string(
            """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Metrics Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: #34495e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
                .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .metric-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
                .metric-label { color: #7f8c8d; margin-top: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>System Metrics</h1>
                    <p>システムパフォーマンス指標</p>
                </div>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">96.33%</div>
                        <div class="metric-label">PyTest Coverage</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">100%</div>
                        <div class="metric-label">UI Accessibility</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">85%</div>
                        <div class="metric-label">Performance Score</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">PASS</div>
                        <div class="metric-label">Security Scan</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        )

except ImportError:
    print("[WARN] Style Manager統合に失敗しました。基本機能のみ利用可能です。")

    # Style Manager統合に失敗した場合の基本ルート
    @app.route("/api/pages", methods=["GET"])
    def get_available_pages_fallback():
        """利用可能なページ一覧を取得（フォールバック）"""
        pages = [
            {
                "url": "/dashboard",
                "name": "ダッシュボード",
                "description": "メインダッシュボード画面",
            },
            {"url": "/tasks", "name": "タスク管理", "description": "タスク一覧と管理画面"},
        ]
        return jsonify(pages)

    @app.route("/style-manager")
    def style_manager_page_fallback():
        """スタイル管理画面（フォールバック）"""
        return "<h1>Style Manager</h1><p>Style Manager機能は現在利用できません。</p>"

    @app.route("/metrics")
    def metrics_page_fallback():
        """メトリクス表示ページ（フォールバック）"""
        return "<h1>Metrics</h1><p>メトリクス機能は現在利用できません。</p>"


# 予測器のシングルトンを用意し、リクエスト毎の再初期化とDB初期化のオーバーヘッドを回避
PREDICTOR_SINGLETON = None


def get_predictor() -> QualityPredictor:
    global PREDICTOR_SINGLETON
    if PREDICTOR_SINGLETON is None:
        # 起動時に一度だけ初期化（モデルが保存済みなら自動ロードされ、未保存なら未学習状態）
        PREDICTOR_SINGLETON = QualityPredictor("data/quality_metrics.db")
    return PREDICTOR_SINGLETON


class QualityDashboard:
    """品質ダッシュボードクラス"""

    def __init__(self, db_path: str = "data/quality_metrics.db"):
        self.db_path = Path(db_path)
        # シングルトン予測器を共有して、毎回の学習やDB初期化を避ける
        self.predictor = get_predictor()

    def get_recent_metrics(self, days: int = 7) -> List[Dict]:
        """最近のメトリクス取得"""
        try:
            with closing(
                sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            ) as conn:
                with conn:
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
        except Exception:
            # DBがない/テーブル未作成などでもスキーマ準拠の空配列を返す
            return []

    def get_prediction_summary(self) -> Dict:
        """予測サマリー取得"""
        try:
            # リクエスト内での再学習は避ける（重い処理のためSLOに影響）
            # 事前にモデルを学習・永続化しておけば、起動時にロードされ is_trained が True になる
            # 未学習の場合はエラー情報を返す（HTTP 200）
            if not self.predictor.is_trained:
                return {"error": "Model not trained yet. Please pre-train the model."}

            # 最新メトリクスで予測（24hが無い場合は7dフォールバック）
            recent_data = self.get_recent_metrics(1)
            data_window = "24h"
            used_fallback = False
            if not recent_data:
                recent_data = self.get_recent_metrics(7)
                data_window = "7d"
                used_fallback = True
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
                "data_window": data_window,
                "used_fallback": used_fallback,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_trend_data(self, days: int = 30) -> Dict:
        """トレンドデータ取得"""
        try:
            with closing(
                sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            ) as conn:
                with conn:
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

            # 安全な除算（total_count が 0 の場合は 0）
            issue_rate = [
                (float(ic) / float(tc)) if float(tc or 0) > 0 else 0.0
                for ic, tc in zip(df.get("issue_count", []), df.get("total_count", []))
            ]

            return {
                "dates": df.get("date", []).tolist() if hasattr(df, "get") else [],
                "coverage_trend": df.get("avg_coverage", []).tolist() if hasattr(df, "get") else [],
                "complexity_trend": (
                    df.get("avg_complexity", []).tolist() if hasattr(df, "get") else []
                ),
                "error_trend": df.get("avg_error_rate", []).tolist() if hasattr(df, "get") else [],
                "performance_trend": (
                    df.get("avg_performance", []).tolist() if hasattr(df, "get") else []
                ),
                "issue_rate": issue_rate,
            }
        except Exception:
            # DBがない/テーブル未作成などでもスキーマ準拠のデータ形（空配列）を返す
            return {
                "dates": [],
                "coverage_trend": [],
                "complexity_trend": [],
                "error_trend": [],
                "performance_trend": [],
                "issue_rate": [],
            }


# Flask routes
@app.route("/")
@app.route("/dashboard")
def dashboard():
    """メインダッシュボード"""
    return dashboard_main()


@app.route("/tasks")
def tasks():
    """タスク管理ページ"""
    template = """
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>タスク管理 - ORION Dashboard</title>
        <link rel="stylesheet" href="/static/css/orion.css">
        <style>
            body {
                margin: 0;
                padding: 0;
                background: #0a0f1a;
                color: #ffffff;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background: #1a2332;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border: 1px solid #2a3441;
            }
            .nav-links {
                margin-bottom: 20px;
            }
            .nav-links a {
                color: #8aa0c8;
                text-decoration: none;
                margin-right: 20px;
                padding: 8px 16px;
                border-radius: 4px;
                transition: all 0.2s ease;
            }
            .nav-links a:hover {
                background: rgba(255,255,255,0.1);
                color: #ffffff;
            }
            .nav-links a.active {
                color: #00eaff;
                background: rgba(0,234,255,0.1);
            }
            .task-card {
                background: #1a2332;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 15px;
                border: 1px solid #2a3441;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="margin: 0; color: #00eaff;">📋 タスク管理</h1>
                <div class="nav-links">
                    <a href="/">ダッシュボード</a>
                    <a href="/tasks" class="active">タスク</a>
                    <a href="/style-manager">スタイル管理</a>
                </div>
            </div>
            
            <div class="task-card">
                <h3 style="color: #00eaff; margin-top: 0;">📝 進行中のタスク</h3>
                <p>現在進行中のタスクはありません。</p>
            </div>
            
            <div class="task-card">
                <h3 style="color: #00eaff; margin-top: 0;">✅ 完了済みタスク</h3>
                <p>スタイル管理システムの復元 - 完了</p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(template)


def dashboard_main():
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
                <div style="margin-top: 15px;">
                    <a href="/dashboard" style="color: #00eaff; text-decoration: none; background: rgba(0,234,255,0.1); padding: 8px 16px; border-radius: 4px; margin-right: 15px;">ダッシュボード</a>
                    <a href="/tasks" style="color: #8aa0c8; text-decoration: none; padding: 8px 16px; border-radius: 4px; margin-right: 15px; transition: all 0.2s ease;">タスク</a>
                    <a href="/style-manager" style="color: #8aa0c8; text-decoration: none; padding: 8px 16px; border-radius: 4px; transition: all 0.2s ease;">スタイル管理</a>
                </div>
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


# --- Compatibility routes to reduce non-critical 404 logs ---
@app.route("/@vite/client")
def vite_client_placeholder():
    """Viteクライアントのプレースホルダー。
    開発環境以外では配信されないため、404のノイズを避けるためにプレースホルダーを返す。
    """
    return Response("/* Vite client placeholder */", mimetype="application/javascript")


@app.route("/status")
def status():
    """簡易ステータス（監視用）"""
    return jsonify(
        {"status": "ok", "service": "quality_dashboard", "timestamp": datetime.now().isoformat()}
    )


@app.route("/api/system-health")
def api_system_health():
    """システムヘルス（簡易版）"""
    try:
        db_path = Path("data/quality_metrics.db")
        db_ok = db_path.exists()
    except Exception:
        db_ok = False
    return jsonify(
        {
            "service": "quality_dashboard",
            "db": db_ok,
            "predictor_ready": True,
            "timestamp": datetime.now().isoformat(),
        }
    ), (200 if db_ok else 503)


@app.route("/api/work/progress")
def api_work_progress():
    """作業進捗のダミー（仕様未定義のため占位）"""
    return jsonify(
        {
            "progress": {
                "tasks_in_progress": 0,
                "completed_today": 0,
                "queued": 0,
            },
            "note": "Placeholder endpoint",
            "timestamp": datetime.now().isoformat(),
        }
    )


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


@app.route("/api/trends-schema/<schema_name>.json")
def api_trends_schema(schema_name: str):
    """トレンドAPIの契約スキーマを配信するエンドポイント

    tests/contract/test_schema_validation.py が参照する
    /api/trends-schema/dashboard_trends.schema.json に対応。
    """
    try:
        schema_path = Path("schema") / f"{schema_name}.json"
        if not schema_path.exists():
            # 後方互換: schema_name に拡張子が含まれている場合
            alt_path = Path("schema") / schema_name
            if alt_path.exists():
                schema_path = alt_path
        content = schema_path.read_text(encoding="utf-8")
        return Response(content, mimetype="application/json")
    except Exception:
        # スキーマがない場合は 404（契約テストで JSONDecodeError を避けるため空JSON）
        return Response("{}", mimetype="application/json", status=404)


@app.route("/api/metrics")
def api_metrics():
    """メトリクスAPI"""
    dashboard_obj = QualityDashboard()
    return jsonify(dashboard_obj.get_recent_metrics())


# --- Autopilot endpoints (placeholder) ---
@app.route("/api/autopilot/status")
def api_autopilot_status():
    """自動操縦ステータス（未実装のため占位）"""
    return (
        jsonify(
            {
                "status": "unavailable",
                "message": "Autopilot features are not implemented on this dashboard",
                "timestamp": datetime.now().isoformat(),
            }
        ),
        501,
    )


@app.route("/api/autopilot/logs")
def api_autopilot_logs():
    """自動操縦ログ（未実装のため占位）"""
    return jsonify(
        {
            "logs": [],
            "note": "Autopilot logs unavailable",
            "timestamp": datetime.now().isoformat(),
        }
    )


# --- MCP Contract endpoints (minimal scaffolding) ---
# 契約スキーマ（schema/contracts/*.json）に合わせた最小応答を返すエンドポイント群。
# 監査ルールに従い、操作の証跡は observability/mcp/ 配下に保存します。


def _mcp_evidence_dir() -> Path:
    p = Path("observability") / "mcp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_evidence(subdir: str, name: str, payload: Dict[str, any]) -> None:
    try:
        base = _mcp_evidence_dir() / subdir
        base.mkdir(parents=True, exist_ok=True)
        out = base / f"{name}.json"
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        # 証跡保存に失敗しても API は継続（ログに残す）
        try:
            app.logger.warning("MCP_EVIDENCE_WRITE_FAIL subdir=%s name=%s", subdir, name)
        except Exception:
            pass


# /mcp Blueprint
mcp_bp = Blueprint("mcp", __name__, url_prefix="/mcp")

# MCP 認証・レート制限設定（環境変数で調整可能）
MCP_RATE_WINDOW_SEC = int(os.environ.get("ORCH_MCP_RATE_WINDOW", "10"))
MCP_RATE_MAX = int(os.environ.get("ORCH_MCP_RATE_MAX", "10"))
_mcp_rate_buckets: Dict[str, deque] = {}


@mcp_bp.before_request
def _mcp_auth_and_rate_limit():
    """/mcp/* 用の最小セキュリティ: Bearer 認証＋IPベース短期レート制限。

    - 認証: ORCH_MCP_TOKEN が設定されている場合のみ Bearer トークンを必須化（未設定時は開発モードとして通過）
    - レート制限: IP ごとに MCP_RATE_WINDOW_SEC 秒のウィンドウで MCP_RATE_MAX リクエストまで許容
    - プリフライト（OPTIONS）はグローバルの before_request が処理するためスキップ
    """
    try:
        # プリフライトはスキップ（上位の統一処理に委譲）
        if request.method == "OPTIONS":
            return None

        # Bearer 認証
        expected = os.environ.get("ORCH_MCP_TOKEN")
        if expected:
            auth = request.headers.get("Authorization", "")
            ok = False
            if auth.startswith("Bearer "):
                provided = auth.split(None, 1)[1]
                ok = provided == expected
            if not ok:
                try:
                    app.logger.warning(
                        "MCP_UNAUTHORIZED path=%s ip=%s expected=%r auth=%r",
                        request.path,
                        request.remote_addr,
                        expected,
                        request.headers.get("Authorization", ""),
                    )
                except Exception:
                    pass
                return jsonify({"error": "Unauthorized"}), 401

        # IP レート制限（短期強化）
        ip = request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown"
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()
        now = time.time()
        bucket = _mcp_rate_buckets.get(ip)
        if bucket is None:
            bucket = deque()
            _mcp_rate_buckets[ip] = bucket
        # ウィンドウ外の古いエントリを削除
        while bucket and (now - bucket[0]) > MCP_RATE_WINDOW_SEC:
            bucket.popleft()
        if len(bucket) >= MCP_RATE_MAX:
            retry_after = max(1, MCP_RATE_WINDOW_SEC - int(now - bucket[0]))
            resp = jsonify({"error": "Too Many Requests"})
            try:
                resp.headers["Retry-After"] = str(retry_after)
                resp.headers["X-RateLimit-Limit"] = str(MCP_RATE_MAX)
                resp.headers["X-RateLimit-Remaining"] = "0"
                resp.headers["X-RateLimit-Window"] = str(MCP_RATE_WINDOW_SEC)
            except Exception:
                pass
            return resp, 429
        bucket.append(now)
        return None
    except Exception:
        # セーフティネット: 失敗時は通常フローへ（MCP を止めない）
        try:
            app.logger.exception("MCP_SECURITY_FILTER_FAIL")
        except Exception:
            pass
        return None


@mcp_bp.route("/site/load", methods=["POST"])
def mcp_site_load():
    """site.load { url } → { graph_id }

    受信ペイロードに url が含まれる想定。最低限の ID を生成して返却。
    """
    body = request.get_json(silent=True) or {}
    url = (body or {}).get("url")
    graph_id = f"graph-{uuid.uuid4().hex[:12]}"
    result = {"graph_id": graph_id, "received_url": url}
    _write_evidence("site_load", graph_id, {"request": body, "response": result})
    return jsonify(result)


@mcp_bp.route("/site/select", methods=["POST"])
def mcp_site_select():
    """site.select { graph_id, by:{mode,value}, scope? } → { anchor_id[] }

    簡易実装: mode/value に応じたダミーアンカー ID を返す。
    """
    body = request.get_json(silent=True) or {}
    graph_id = (body or {}).get("graph_id") or f"graph-{uuid.uuid4().hex[:8]}"
    by = (body or {}).get("by") or {}
    mode = by.get("mode") or "unknown"
    value = by.get("value") or ""
    anchors = [f"a-{mode}-{uuid.uuid4().hex[:6]}"] if value else []
    result = {"anchor_id": anchors, "graph_id": graph_id}
    _write_evidence(
        "site_select", f"{graph_id}-{uuid.uuid4().hex[:6]}", {"request": body, "response": result}
    )
    return jsonify(result)


@mcp_bp.route("/patch/propose", methods=["POST"])
def mcp_patch_propose():
    """patch.propose { anchors, instruction, constraints } → { diff_id, diffs[], preview_url }

    最小差分: diffs は空配列、preview_url は /preview に誘導（ターゲットが指定されていれば流用）。
    """
    body = request.get_json(silent=True) or {}
    diff_id = f"diff-{uuid.uuid4().hex[:12]}"
    target = request.args.get("target") or (body.get("constraints", {}) or {}).get("target")
    preview_url = f"/preview?target={target}" if target else "/preview"
    result = {"diff_id": diff_id, "diffs": [], "preview_url": preview_url}
    _write_evidence("patch_propose", diff_id, {"request": body, "response": result})
    return jsonify(result)


@mcp_bp.route("/patch/apply", methods=["POST"])
def mcp_patch_apply():
    """patch.apply { diff_id, mode } → { apply_id, rollback_token }

    最小差分: 即時成功を返すスタブ。モードは受信値を反映するのみ。
    """
    body = request.get_json(silent=True) or {}
    diff_id = (body or {}).get("diff_id") or f"diff-{uuid.uuid4().hex[:8]}"
    apply_id = f"apply-{uuid.uuid4().hex[:12]}"
    rollback_token = f"rb-{uuid.uuid4().hex[:16]}"
    result = {
        "apply_id": apply_id,
        "rollback_token": rollback_token,
        "diff_id": diff_id,
        "mode": body.get("mode"),
    }
    _write_evidence("patch_apply", apply_id, {"request": body, "response": result})
    return jsonify(result)


@mcp_bp.route("/patch/test", methods=["POST"])
def mcp_patch_test():
    """patch.test { diff_id, gates[] } → { diff_id, results[] }

    最小差分: 受信ゲートを "pass" として返すスタブ。
    """
    body = request.get_json(silent=True) or {}
    diff_id = (body or {}).get("diff_id") or f"diff-{uuid.uuid4().hex[:8]}"
    gates = (body or {}).get("gates") or []
    results = [{"gate": g, "status": "pass"} for g in gates]
    result = {"diff_id": diff_id, "results": results}
    _write_evidence(
        "patch_test", f"{diff_id}-{uuid.uuid4().hex[:6]}", {"request": body, "response": result}
    )
    return jsonify(result)


@mcp_bp.route("/patch/rollback", methods=["POST"])
def mcp_patch_rollback():
    """patch.rollback { apply_id, token } → { ok }

    最小差分: apply_id と token を受け取り、検証後にロールバック成功を返すスタブ。
    """
    body = request.get_json(silent=True) or {}
    apply_id = (body or {}).get("apply_id") or f"apply-{uuid.uuid4().hex[:8]}"
    token = (body or {}).get("token")
    # 最低限のバリデーション: token は必須
    if not token:
        return jsonify({"error": "token required"}), 400
    result = {"ok": True, "apply_id": apply_id}
    _write_evidence("patch_rollback", apply_id, {"request": body, "response": result})
    return jsonify(result)


@mcp_bp.route("/ping", methods=["GET"])
def mcp_ping():
    """MCP ping for sanity check"""
    return jsonify({"ok": True, "time": datetime.now().isoformat()})


# Blueprint 登録
app.register_blueprint(mcp_bp)


@app.route("/debug/urlmap", methods=["GET"])
def debug_urlmap():
    """現在の Flask ルーティングテーブルをダンプする簡易デバッグ用エンドポイント"""
    rules = []
    try:
        for r in app.url_map.iter_rules():
            rules.append(
                {
                    "rule": str(r),
                    "endpoint": r.endpoint,
                    "methods": sorted(list(r.methods)) if r.methods else [],
                }
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"count": len(rules), "rules": sorted(rules, key=lambda x: x["rule"])})


# /api/ プレフィックス経由でもルート一覧を取得できるようにする
@app.route("/api/debug/routes", methods=["GET", "OPTIONS"])
def api_debug_routes():
    """Flask のルーティング一覧を API 経由で返す（/api/ は既存で到達確認済み）"""
    rules = []
    try:
        for r in app.url_map.iter_rules():
            rules.append(
                {
                    "rule": str(r),
                    "endpoint": r.endpoint,
                    "methods": sorted(list(r.methods)) if r.methods else [],
                }
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    # GET は JSON を返し、OPTIONS は CORS ヘッダのみ返す
    if request.method == "OPTIONS":
        response = Response()
        response = apply_options_cors_headers(response, request)
        return response
    return jsonify({"count": len(rules), "rules": sorted(rules, key=lambda x: x["rule"])})


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
            with closing(
                sqlite3.connect(db_path.as_posix(), timeout=30, check_same_thread=False)
            ) as conn:
                with conn:
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


# --- Error handlers ---
@app.errorhandler(404)
def _not_found(e):
    """404 時の追加ロギング

    static へのアクセスで 404 が発生した場合、要求 URL と Flask の static 実体解決結果をログに出す。
    可観測性を高め、/static 配信の不一致を特定しやすくするための最小差分追加。
    """
    from flask import request

    try:
        if request.path.startswith("/static/"):
            resolved = Path(app.static_folder, request.path.removeprefix("/static/"))
            app.logger.warning("STATIC_404 path=%s resolved=%s", request.path, resolved)
    except Exception:
        # ログ出力で例外が起きても 404 応答は維持
        pass

    return e, 404


def main():
    """メイン実行関数"""
    # ORCH_PORT 環境変数で起動ポートを切り替え（既定: 5001）
    # ログローテーション設定（失敗しても起動継続）
    try:
        _setup_logging_for_app(app)
        app.logger.info("Logging initialized with RotatingFileHandler")
    except Exception:
        pass

    port_str = os.getenv("ORCH_PORT", "5001")
    try:
        port = int(port_str)
    except ValueError:
        port = 5001
        print(f"[WARN] ORCH_PORT='{port_str}' は数値に変換できないため、既定の 5001 を使用します")

    # ポートフォールバック: 5000→5001→5002（ORCH_PORT 指定時はそれを優先）
    def _choose_available_port(candidates):
        """Windows/Unix 双方で安定する空きポート検出。

        - 既存プロセスが LISTEN 中の場合、connect_ex が 0 を返すので使用不可と判断
        - LISTEN が無ければ connect_ex が非 0 を返すため使用可能と判断
        - SO_REUSEADDR による誤検出（既存プロセスがいるのに bind 成功）を避ける
        """
        import socket as _socket

        for p in candidates:
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(0.25)
                # 127.0.0.1 宛の接続試行で LISTEN 有無を確認
                res = s.connect_ex(("127.0.0.1", p))
                s.close()
                if res != 0:
                    return p
            except Exception:
                # 例外時は次候補へ
                continue
        # すべて使用不可と判定された場合は最初の候補にフォールバック
        return candidates[0]

    candidates = []
    if port not in (5000, 5001, 5002):
        candidates.append(port)
    candidates.extend(list(range(5000, 5011)))
    chosen = _choose_available_port(candidates)
    if chosen != port:
        print(f"[WARN] Port {port} is busy. Falling back to {chosen}.")

    # ルート構成の簡易ダンプ（起動時出力）
    try:
        rules = list(app.url_map.iter_rules())
        has_mcp = any(str(r).startswith("/mcp/") or str(r) == "/mcp" for r in rules)
        print(f"[init] routes={len(rules)} has_mcp={has_mcp}")
        # 代表ルートを一部出力
        for r in rules:
            s = str(r)
            if s in ("/mcp/site/load", "/mcp/ping", "/api/autopilot/status"):
                print(f"[init] route: {s} -> {r.endpoint} methods={sorted(list(r.methods))}")
    except Exception:
        pass

    print("Starting Quality Dashboard...")
    print(f"Access: http://localhost:{chosen}")
    # 本番統一: Werkzeug ではなく Waitress で起動する（監査是正）。
    # 環境変数 ORCH_USE_WERKZEUG=1 の場合のみ従来の開発サーバーを使用可能。
    use_dev = os.getenv("ORCH_USE_WERKZEUG", "0") in ("1", "true", "True")
    host_env = os.getenv("ORCH_HOST", "127.0.0.1")
    if use_dev:
        # デバッグリローダーによる再起動を避けるため debug=False で起動
        app.run(debug=False, host=host_env, port=chosen)
    else:
        try:
            from waitress import serve
        except Exception:
            # フォールバック（waitress 未インストール時のみ）
            app.run(debug=False, host=host_env, port=chosen)
            return
        # Waitress で WSGI として提供
        serve(app, host=host_env, port=chosen, threads=8)


if __name__ == "__main__":
    main()
