"""
共通ヘッダユーティリティ

ダッシュボード系アプリで重複しているヘッダ付与ロジック（/preview の強制ヘッダ、
CORS 補正、Access-Control-Expose-Headers など）を一元化します。

使用例（Flask）:

    from src.utils.headers import enforce_preview_headers, apply_cors_and_expose_headers

    @app.after_request
    def _after(response):
        # /preview 系の強制ヘッダを最初に適用
        response = enforce_preview_headers(response, request)
        # グローバル CORS/Expose を適用
        response = apply_cors_and_expose_headers(response, request)
        return response

プリフライト（OPTIONS）用の補助関数も用意しています:

    from src.utils.headers import apply_options_cors_headers

    @app.route('/api/<path:path>', methods=['OPTIONS'])
    def handle_options(path):
        resp = Response()
        apply_options_cors_headers(resp, request)
        return resp
"""

from typing import Optional, Iterable
import re

# 一貫性を保つために、Expose 対象ヘッダを定数化
# 備考: ETag は通常は JS から参照不可ですが、Access-Control-Expose-Headers に列挙することで
#       Fetch レスポンスの headers.get('etag') から参照可能になります。
EXPOSE_HEADERS = (
    "X-Preview-Origin, X-Preview-Target, X-Upstream-Status, X-Disable-ServiceWorker, X-Preview-Same-Origin, ETag"
)

# ヘッダ名の一貫性を担保するための定数（表記ゆれ防止）
DISABLE_SW_HEADER = "X-Disable-ServiceWorker"


def _compute_preview_origin(target: Optional[str], request_host: str) -> str:
    """target からオリジンを推定。失敗時は受信ホストを返す。

    Args:
        target: /preview?target= の値
        request_host: Flask request.host（例: "localhost:5000"）
    Returns:
        例: "http://localhost:5000" のようなオリジン文字列
    """
    if not target:
        return f"http://{request_host}"
    try:
        m = re.match(r"^(https?://[^/]+)", target)
        if m:
            return m.group(1)
    except Exception:
        pass
    return f"http://{request_host}"


def enforce_preview_headers(response, request):
    """/preview 応答で必須ヘッダを強制付与します。

    - Cache-Control: no-store
    - X-Preview-Target（未指定時は空文字）
    - X-Preview-Origin（target から推定、失敗時は受信ホスト）
    - X-Disable-ServiceWorker: true（ServiceWorker干渉の抑止）
    - X-Preview-Same-Origin: true（同一オリジン配信フラグ）

    本関数は例外を握りつぶし、可能な限り既存のヘッダへ上書き/補完します。
    """
    try:
        if getattr(request, "path", "").startswith("/preview"):
            # 監査要件: /preview 応答は常に no-store
            response.headers["Cache-Control"] = "no-store"

            # X-Preview-Target 補完
            if not response.headers.get("X-Preview-Target"):
                response.headers["X-Preview-Target"] = request.args.get("target", "") or ""

            # X-Preview-Origin 補完
            if not response.headers.get("X-Preview-Origin"):
                origin = _compute_preview_origin(request.args.get("target", ""), request.host)
                response.headers["X-Preview-Origin"] = origin

            # ServiceWorker 抑止（ダッシュボード側の要件と整合）
            if not response.headers.get(DISABLE_SW_HEADER):
                response.headers[DISABLE_SW_HEADER] = "true"

            # 同一オリジン配信フラグ（ダッシュボード配信で常に同一オリジン化される前提）
            if not response.headers.get("X-Preview-Same-Origin"):
                response.headers["X-Preview-Same-Origin"] = "true"
    except Exception:
        # ヘッダ付与失敗時もレスポンスはそのまま返す
        pass
    return response


def _compute_vary_value(response, additions: Iterable[str]) -> str:
    """Vary ヘッダを重複なく統合した最終値を返す。

    - response.headers.getlist('Vary') を用いて複数行の Vary を収集
    - それぞれをカンマ区切りで分割し、大小文字を無視して集合化
    - additions を加えて重複を除去
    - カンマ+スペース区切りで再結合
    """
    items = []
    seen = set()
    try:
        existing = []
        # getlist があれば複数行を取得、なければ単一値を扱う
        getlist = getattr(response.headers, "getlist", None)
        if callable(getlist):
            existing = response.headers.getlist("Vary") or []
        else:
            existing = [response.headers.get("Vary", "")] if response.headers.get("Vary") else []
        for val in existing:
            for part in (val or "").split(","):
                p = part.strip()
                if p and p.lower() not in seen:
                    items.append(p)
                    seen.add(p.lower())
        for add in additions:
            a = add.strip()
            if a and a.lower() not in seen:
                items.append(a)
                seen.add(a.lower())
    except Exception:
        # フォールバック: 既存値が取得できない場合は additions のみ
        for add in additions:
            a = add.strip()
            if a and a.lower() not in seen:
                items.append(a)
                seen.add(a.lower())
    return ", ".join(items)


def apply_cors_and_expose_headers(response, request):
    """全応答に CORS 補正と Access-Control-Expose-Headers を付与します。

    - Origin がある場合: Allow-Origin=Origin, Vary+=Origin, Allow-Credentials=true
    - Origin がない場合: Allow-Origin=*
    - Allow-Methods/Allow-Headers を包括的に付与
    - Access-Control-Expose-Headers を統一定数で付与
    """
    try:
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            # 既存の Vary を集合化して一意化し、最後に一行に再設定
            final_vary = _compute_vary_value(response, ["Origin"])
            try:
                # 重複行を消すために一旦削除してから単一行で再設定
                del response.headers["Vary"]
            except Exception:
                pass
            try:
                # set() を使って単一行に正規化
                response.headers.set("Vary", final_vary)
            except Exception:
                # フォールバック: 通常代入
                response.headers["Vary"] = final_vary
            response.headers["Access-Control-Allow-Credentials"] = "true"
        else:
            response.headers["Access-Control-Allow-Origin"] = "*"

        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Style-Base-Url"
        response.headers["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
    except Exception:
        pass
    return response


def apply_options_cors_headers(response, request):
    """プリフライト（OPTIONS）応答用のヘッダ付与。EXPOSE と CORS を一貫化。"""
    try:
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        else:
            response.headers["Access-Control-Allow-Origin"] = "*"

        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Style-Base-Url"
        # 監査是正: プリフライト最適化のため Max-Age を設定（秒）。
        # 資格情報付き CORS と動的 Origin/Vary は既存の要件を維持。
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
    except Exception:
        pass
    return response
