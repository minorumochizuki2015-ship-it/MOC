"""
学習インテーク・アプリ用UIルーター
Webインターフェース提供
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .classifier import classify_domain
from .schema import IntakeItemCreate, PrivacyLevel, SourceType, TaskType

router = APIRouter(prefix="/ui", tags=["UI"])

# テンプレート設定
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# パス設定（自己HTTPを避けるため直接ファイルアクセス）
ROOT = Path(__file__).resolve().parents[2]  # repo ルート
INTAKE = ROOT / "data" / "intake"
INBOX = INTAKE / "inbox"
ACCEPT = INTAKE / "accepted"
REJECT = INTAKE / "rejected"
BUCKETS = INTAKE / "buckets"
SFT = ROOT / "data" / "sft"
DATA = ROOT / "data"

def mtime_ms(p: Path) -> int:
    """ファイルの更新時刻をミリ秒で取得"""
    try:
        return int(p.stat().st_mtime * 1000)
    except Exception:
        return 0

def _count(p: Path) -> int:
    """ファイル数をカウント"""
    return sum(1 for _ in p.rglob("*.jsonl")) if p.exists() else 0

def snapshot():
    """システム状態を直接取得（HTTP不要・例外飲み）"""
    try:
        return {
            "inbox": _count(INBOX),
            "accepted": _count(ACCEPT),
            "rejected": _count(REJECT),
            "buckets": len(list(BUCKETS.glob("*.jsonl"))) if BUCKETS.exists() else 0,
            "sft": len(list(SFT.glob("*.jsonl"))) if SFT.exists() else 0,
        }
    except Exception:
        return {"inbox": 0, "accepted": 0, "rejected": 0, "buckets": 0, "sft": 0}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """メインUIページ"""
    return templates.TemplateResponse("index.html", {"request": request, "state": snapshot()})


@router.post("/submit")
async def submit_data(
    source: str = Form(...),
    title: str = Form(...),
    domain: str = Form(...),
    task_type: str = Form(...),
    success: bool = Form(False),
    prompt: str = Form(...),
    output: str = Form(...),
    rationale_success: str = Form(""),
    rationale_failure: str = Form(""),
    math_or_rules: str = Form(""),
    refs: str = Form(""),
    privacy: str = Form("no_pii"),
    tags: str = Form("")
):
    """データ投入フォーム処理"""
    try:
        # フォームデータをIntakeItemCreateに変換
        refs_list = [r.strip() for r in refs.split(",") if r.strip()] if refs else []
        tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        
        item_data = IntakeItemCreate(
            source=SourceType(source),
            title=title,
            domain=domain if domain != "auto" else None,
            task_type=TaskType(task_type),
            success=success,
            prompt=prompt,
            output=output,
            rationale_success=rationale_success if rationale_success else None,
            rationale_failure=rationale_failure if rationale_failure else None,
            math_or_rules=math_or_rules if math_or_rules else None,
            refs=refs_list,
            privacy=PrivacyLevel(privacy),
            tags=tags_list
        )
        
        # APIエンドポイントに送信
        import requests
        response = requests.post(
            "http://127.0.0.1:8787/intake/post",
            json=item_data.dict(),
            timeout=10
        )
        
        if response.status_code == 200:
            return {"success": True, "message": "データが正常に投入されました"}
        else:
            return {"success": False, "message": f"エラー: {response.text}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.get("/items")
def ui_items():
    """アイテム一覧取得（epoch ms統一）"""
    base = DATA / "intake"
    rows = []
    for box in ["inbox", "queue", "accepted", "rejected"]:
        for p in (base/box).glob("*.json"):
            rec = {"box": box, "fname": p.name, "ts_ms": mtime_ms(p)}
            try:
                j = json.loads(p.read_text(encoding="utf-8"))
                rec["title"]  = j.get("title") or j.get("id") or p.stem
                rec["domain"] = j.get("domain") or "unknown"
            except Exception as e:
                rec["error"] = str(e)
            rows.append(rec)
    rows.sort(key=lambda r: r.get("ts_ms", 0), reverse=True)
    return JSONResponse({"success": True, "items": rows})


@router.post("/approve/{item_id}")
async def approve_item(item_id: str):
    """アイテム承認"""
    try:
        import requests
        response = requests.post(f"http://127.0.0.1:8787/intake/approve?item_id={item_id}", timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "message": "アイテムが承認されました"}
        else:
            return {"success": False, "message": f"エラー: {response.text}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.post("/reject/{item_id}")
async def reject_item(item_id: str):
    """アイテム拒否"""
    try:
        import requests
        response = requests.post(f"http://127.0.0.1:8787/intake/reject?item_id={item_id}", timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "message": "アイテムが拒否されました"}
        else:
            return {"success": False, "message": f"エラー: {response.text}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.post("/filter")
async def run_filter():
    """フィルタ実行"""
    try:
        result = subprocess.run([
            sys.executable, "-X", "utf8", "-u", 
            "tools/intake_filter.py", "--data-dir", "data/intake"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return {"success": True, "message": "フィルタが正常に実行されました", "output": result.stdout}
        else:
            return {"success": False, "message": f"フィルタエラー: {result.stderr}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.post("/export-sft")
async def export_sft(domain: str = "all"):
    """SFT生成"""
    try:
        cmd = [
            sys.executable, "-X", "utf8", "-u",
            "tools/export_sft_dataset.py",
            "--buckets", "data/intake/buckets",
            "--out", "data/sft_ui",
            "--min_chars", "8"
        ]
        
        if domain != "all":
            cmd.extend(["--domain", domain])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            return {"success": True, "message": "SFTが正常に生成されました", "output": result.stdout}
        else:
            return {"success": False, "message": f"SFT生成エラー: {result.stderr}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.post("/train")
async def train_model(domain: str = "code", auto_eval: bool = True):
    """学習実行"""
    try:
        cmd = [
            sys.executable, "-X", "utf8", "-u",
            "tools/train_local.py",
            "--domain", domain,
            "--plan-only"
        ]
        
        if auto_eval:
            cmd.append("--auto-eval")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return {"success": True, "message": "学習計画が生成されました", "output": result.stdout}
        else:
            return {"success": False, "message": f"学習エラー: {result.stderr}"}
    
    except Exception as e:
        return {"success": False, "message": f"エラー: {str(e)}"}


@router.get("/status")
def ui_status():
    """システム状態取得（epoch ms統一）"""
    intake = DATA / "intake"
    sftdir = DATA / "sft"
    return {
        "success": True,
        "status": {
            "inbox":    len(list((intake/"inbox").glob("*.json"))),
            "accepted": len(list((intake/"accepted").glob("*.json"))),
            "rejected": len(list((intake/"rejected").glob("*.json"))),
            "buckets":  len([p for p in (intake/"buckets").glob("*") if p.is_dir()]),
            "sft":      len(list(sftdir.glob("*.jsonl"))),
            "timestamp_ms": int(time.time()*1000),
        }
    }


@router.get("/health")
async def health_check():
    """ヘルスチェック"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ダッシュボード用関数
def _jget(p: Path, default=None):
    """JSONファイル読み込み"""
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def _tail_jsonl(p: Path, n: int = 20):
    """JSONLファイルの末尾n行読み込み"""
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        return [json.loads(x) for x in lines[-n:] if x.strip()]
    except Exception:
        return []

def _snapshot():
    """システム状態スナップショット取得"""
    qd = _jget(DATA/"outputs"/"quick_diagnose.json", {})
    stats = _jget(DATA/"sft"/"stats.json", {})
    hist = _tail_jsonl(DATA/"logs"/"current"/"mini_eval_history.jsonl", 20)
    
    def _count(dir_name):
        p = DATA/"intake"/dir_name
        try:
            return sum(1 for _ in p.glob("*.json"))
        except Exception:
            return 0
    
    snap = {
        "ts": int(time.time()),
        "qd": qd,
        "stats": stats,
        "history": hist,
        "counts": {
            "inbox": _count("inbox"),
            "queue": _count("queue"),
            "accepted": _count("accepted"),
        },
        "last": hist[-1] if hist else None,
    }
    return snap

@router.get("/snapshot.json")
async def ui_snapshot():
    """ダッシュボード用スナップショットAPI"""
    return JSONResponse(_snapshot())

@router.get("/dashboard", response_class=HTMLResponse)
async def ui_dashboard(request: Request):
    """ダッシュボードページ"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/ui/dashboard", include_in_schema=False)
async def _dash_redirect():
    """ダッシュボードエイリアス（リダイレクト）"""
    return RedirectResponse(url="/ui/", status_code=307)
