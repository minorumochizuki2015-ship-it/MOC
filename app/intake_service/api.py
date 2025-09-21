"""
学習インテーク・アプリ用FastAPIローカルAPI
127.0.0.1:8787でローカル専用APIサーバー
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import ui
from .classifier import classify_domain
from .schema import (
    IntakeItem,
    IntakeItemCreate,
    IntakeItemMeta,
    IntakeItemUpdate,
    IntakeListResponse,
    IntakeResponse,
    create_intake_item,
)

# イベントログ設定
EVLOG = Path("data/logs/current/intake_events.jsonl")
EVLOG.parent.mkdir(parents=True, exist_ok=True)

def emit(ev: dict):
    """イベントログ出力"""
    ev.setdefault("ts_ms", int(time.time()*1000))
    with EVLOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False)+"\n")

# FastAPIアプリケーション初期化
app = FastAPI(
    title="GoverningCore Intake Service",
    description="ローカル統治核AI用学習インテーク・アプリ",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS無効（ローカル専用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=[],
    allow_headers=[],
)

# データディレクトリ
DATA_DIR = Path("data/intake")
INBOX_DIR = DATA_DIR / "inbox"
QUEUE_DIR = DATA_DIR / "queue"
ACCEPTED_DIR = DATA_DIR / "accepted"
REJECTED_DIR = DATA_DIR / "rejected"
BUCKETS_DIR = DATA_DIR / "buckets"
INDEX_FILE = DATA_DIR / "index.jsonl"

# ディレクトリ作成
for dir_path in [INBOX_DIR, QUEUE_DIR, ACCEPTED_DIR, REJECTED_DIR, BUCKETS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


def _save_item(item: IntakeItem, directory: Path) -> str:
    """アイテムをファイルに保存"""
    timestamp = item.ts.strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{item.id}.json"
    filepath = directory / filename
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(item.dict(), f, ensure_ascii=False, indent=2, default=str)
    
    return str(filepath)


def _load_item(item_id: str, directory: Path) -> IntakeItem:
    """アイテムをファイルから読み込み"""
    for filepath in directory.glob(f"*_{item_id}.json"):
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return IntakeItem(**data)
    
    raise HTTPException(status_code=404, detail="アイテムが見つかりません")


def _list_items(directories: List[Path]) -> List[IntakeItemMeta]:
    """アイテム一覧を取得"""
    items = []
    
    for directory in directories:
        for filepath in directory.glob("*.json"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    item = IntakeItem(**data)
                    items.append(IntakeItemMeta(
                        id=item.id,
                        ts=item.ts,
                        source=item.source,
                        title=item.title,
                        domain=item.domain,
                        task_type=item.task_type,
                        success=item.success,
                        privacy=item.privacy,
                        tags=item.tags
                    ))
            except Exception as e:
                print(f"Warning: Failed to load {filepath}: {e}")
                continue
    
    # タイムスタンプでソート（新しい順）
    items.sort(key=lambda x: x.ts, reverse=True)
    return items


def _move_item(item_id: str, from_dir: Path, to_dir: Path) -> str:
    """アイテムを移動"""
    # ファイルを検索
    source_file = None
    for filepath in from_dir.glob(f"*_{item_id}.json"):
        source_file = filepath
        break
    
    if not source_file:
        raise HTTPException(status_code=404, detail="アイテムが見つかりません")
    
    # 移動先ファイル名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_file = to_dir / f"{timestamp}_{item_id}.json"
    
    # ファイル移動
    source_file.rename(dest_file)
    
    return str(dest_file)


def _update_bucket(item: IntakeItem) -> None:
    """バケットファイルに追記"""
    bucket_dir = BUCKETS_DIR / item.domain.value
    bucket_dir.mkdir(exist_ok=True)
    
    # 日付別ファイル
    date_str = item.ts.strftime("%Y%m%d")
    bucket_file = bucket_dir / f"{date_str}.jsonl"
    
    # SFT形式で追記
    sft_item = {
        "instruction": item.prompt,
        "input": "",
        "output": item.output,
        "meta": {
            "id": item.id,
            "ts": item.ts.isoformat(),
            "source": item.source,
            "title": item.title,
            "domain": item.domain,
            "task_type": item.task_type,
            "success": item.success,
            "rationale_success": item.rationale_success,
            "rationale_failure": item.rationale_failure,
            "math_or_rules": item.math_or_rules,
            "refs": item.refs,
            "privacy": item.privacy,
            "tags": item.tags
        }
    }
    
    with open(bucket_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(sft_item, ensure_ascii=False) + "\n")


def _update_index(item: IntakeItem, status: str) -> None:
    """インデックスファイルに追記"""
    index_entry = {
        "id": item.id,
        "ts": item.ts.isoformat(),
        "status": status,
        "domain": item.domain,
        "title": item.title,
        "source": item.source
    }
    
    with open(INDEX_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(index_entry, ensure_ascii=False) + "\n")


@app.get("/", response_model=IntakeResponse)
async def root():
    """ルートエンドポイント"""
    return IntakeResponse(
        success=True,
        message="GoverningCore Intake Service is running",
        data={"version": "1.0.0", "host": "127.0.0.1:8787"}
    )


@app.post("/intake/post", response_model=IntakeResponse)
async def post_intake(item_data: IntakeItemCreate, bg: BackgroundTasks, auto: bool = False):
    """JSON投入エンドポイント（自動パイプライン対応）"""
    try:
        # ドメインが未指定の場合は自動推定
        if item_data.domain is None:
            item_data.domain = classify_domain(
                item_data.title,
                item_data.prompt,
                item_data.output,
                item_data.refs
            )
        
        # IntakeItem作成
        item = create_intake_item(item_data)
        
        # ファイル保存
        filepath = _save_item(item, INBOX_DIR)
        
        # インデックス更新
        _update_index(item, "inbox")
        
        # イベントログ出力
        emit({"type":"post_saved","id":item.id,"title":item_data.title,"source":item_data.source})
        
        # 自動パイプライン実行
        if auto or os.getenv("AUTO_PROCESS") == "1":
            bg.add_task(_run_pipeline, item.id)
        
        return IntakeResponse(
            success=True,
            message="アイテムが正常に投入されました",
            data={"id": item.id, "filepath": filepath, "auto_processing": auto or os.getenv("AUTO_PROCESS") == "1"}
        )
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"アイテム投入エラー: {str(e)}")


@app.post("/intake/post_text", response_model=IntakeResponse)
async def post_intake_text(
    title: str,
    prompt: str,
    output: str,
    source: str = "manual",
    task_type: str = "edit",
    success: bool = True
):
    """テキスト投入エンドポイント"""
    try:
        # 最小スキーマで自動梱包
        item_data = IntakeItemCreate(
            source=source,
            title=title,
            prompt=prompt,
            output=output,
            task_type=task_type,
            success=success
        )
        
        return await post_intake(item_data)
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"テキスト投入エラー: {str(e)}")


@app.get("/intake/items", response_model=IntakeListResponse)
async def get_items():
    """アイテム一覧取得エンドポイント"""
    try:
        items = _list_items([INBOX_DIR, QUEUE_DIR, ACCEPTED_DIR])
        
        return IntakeListResponse(
            success=True,
            message=f"{len(items)}件のアイテムを取得しました",
            items=items,
            total=len(items)
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"アイテム一覧取得エラー: {str(e)}")


@app.post("/intake/approve", response_model=IntakeResponse)
async def approve_item(item_id: str):
    """アイテム承認エンドポイント"""
    try:
        # アイテム読み込み
        item = _load_item(item_id, QUEUE_DIR)
        
        # 移動
        filepath = _move_item(item_id, QUEUE_DIR, ACCEPTED_DIR)
        
        # バケット更新
        _update_bucket(item)
        
        # インデックス更新
        _update_index(item, "accepted")
        
        return IntakeResponse(
            success=True,
            message="アイテムが承認されました",
            data={"id": item_id, "filepath": filepath}
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"アイテム承認エラー: {str(e)}")


@app.post("/intake/reject", response_model=IntakeResponse)
async def reject_item(item_id: str):
    """アイテム拒否エンドポイント"""
    try:
        # アイテム読み込み
        item = _load_item(item_id, QUEUE_DIR)
        
        # 移動
        filepath = _move_item(item_id, QUEUE_DIR, REJECTED_DIR)
        
        # インデックス更新
        _update_index(item, "rejected")
        
        return IntakeResponse(
            success=True,
            message="アイテムが拒否されました",
            data={"id": item_id, "filepath": filepath}
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"アイテム拒否エラー: {str(e)}")


@app.post("/intake/edit", response_model=IntakeResponse)
async def edit_item(item_id: str, update_data: IntakeItemUpdate):
    """アイテム編集エンドポイント"""
    try:
        # アイテム読み込み
        item = _load_item(item_id, QUEUE_DIR)
        
        # 更新データを適用
        update_dict = update_data.dict(exclude_unset=True)
        for key, value in update_dict.items():
            setattr(item, key, value)
        
        # ファイル保存
        filepath = _save_item(item, QUEUE_DIR)
        
        return IntakeResponse(
            success=True,
            message="アイテムが更新されました",
            data={"id": item_id, "filepath": filepath}
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"アイテム編集エラー: {str(e)}")


@app.get("/health", response_model=IntakeResponse)
async def health_check():
    """ヘルスチェックエンドポイント"""
    return IntakeResponse(
        success=True,
        message="Service is healthy",
        data={"status": "ok", "timestamp": datetime.now().isoformat()}
    )


@app.get("/healthz")
def healthz():
    """監視＆起動判定用（軽量）"""
    return {"ok": True}


@app.get("/ui/events")
def ui_events(since_ms: int = Query(0)):
    """イベント取得API（ポーリング用）"""
    out = []
    if EVLOG.exists():
        for line in EVLOG.read_text(encoding="utf-8").splitlines():
            try:
                j = json.loads(line)
                if int(j.get("ts_ms",0)) > since_ms:
                    out.append(j)
            except Exception:
                continue
    return JSONResponse({"success": True, "events": out, "now_ms": int(time.time()*1000)})


# 自動パイプライン関数
def _run_pipeline(item_id: str = None):
    """自動パイプライン実行（フィルタ→SFT生成）"""
    try:
        # フィルタ実行
        emit({"type":"filter_start","id":item_id})
        result = subprocess.run([
            sys.executable, "-X", "utf8", "-u", 
            "tools/intake_filter.py", "--data-dir", "data/intake"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            raise Exception(f"intake_filter failed: {result.stderr}")
        
        emit({"type":"filter_ok","id":item_id})
        
        # SFT生成
        result = subprocess.run([
            sys.executable, "-X", "utf8", "-u",
            "tools/export_sft_dataset.py",
            "--buckets", "data/intake/buckets",
            "--out", "data/sft"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            raise Exception(f"export_sft_dataset failed: {result.stderr}")
        
        # SFT更新時刻を取得
        train_file = Path("data/sft/train.jsonl")
        train_mtime_ms = int(train_file.stat().st_mtime * 1000) if train_file.exists() else 0
        emit({"type":"sft_ok","id":item_id,"train_mtime_ms":train_mtime_ms})
            
    except Exception as e:
        # イベントログ出力
        emit({"type":"filter_err","id":item_id,"msg":str(e)})
        
        # ログ出力
        log_dir = Path("data/logs/current")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "intake_auto.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] ERROR: {str(e)}\n")

# UIルーターを組み込み
app.include_router(ui.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8787)
