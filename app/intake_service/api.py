"""
Intake Service API
FastAPIベースのHTTPエンドポイントを提供し、パイプライン実行とステータス管理を行う
"""

import subprocess
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

# 共通エラーハンドリングをインポート
from app.shared.error_handling import (
    ErrorHandler,
    global_exception_handler,
    mask_sensitive_data,
    retry_on_exception,
)

# 標準化ログ設定をインポート
from app.shared.logging_config import (
    LoggerFactory,
    LogLevel,
    MetricsCollector,
    log_operation,
    log_performance,
)
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# ログ設定
logger = LoggerFactory.get_logger("intake_service", log_level=LogLevel.INFO)
metrics = LoggerFactory.get_metrics_collector("intake_service")

# FastAPIアプリケーション初期化
app = FastAPI(
    title="Intake Service API",
    description="パイプライン実行とステータス管理のためのAPI",
    version="1.0.0",
)

# CORS設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 本番環境では適切に制限する
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# グローバル例外ハンドラを追加
app.add_exception_handler(Exception, global_exception_handler)


# データモデル定義
class TriggerType(str, Enum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class PipelineStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    RUNNING = "running"


class PipelineRequest(BaseModel):
    trigger: TriggerType = Field(..., description="パイプライン実行トリガー")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="実行パラメータ")

    @field_validator("params")
    @classmethod
    def validate_params(cls, v):
        """パラメータのバリデーション"""
        if v is None:
            return {}

        # 機密データをマスク
        masked_params = mask_sensitive_data(v)
        logger.info(f"Pipeline params validated: {masked_params}")
        return v


class PipelineResponse(BaseModel):
    status: PipelineStatus = Field(..., description="実行ステータス")
    message: str = Field(..., description="実行結果メッセージ")
    pipeline_id: str = Field(..., description="パイプライン実行ID")
    timestamp: str = Field(..., description="実行時刻")


class PipelineStatusResponse(BaseModel):
    pipeline_id: str = Field(..., description="パイプライン実行ID")
    status: PipelineStatus = Field(..., description="実行ステータス")
    trigger: TriggerType = Field(..., description="実行トリガー")
    params: Dict[str, Any] = Field(..., description="実行パラメータ")
    start_time: str = Field(..., description="開始時刻")
    end_time: Optional[str] = Field(None, description="終了時刻")
    output: Optional[str] = Field(None, description="実行結果出力")
    error: Optional[str] = Field(None, description="エラー情報")


# パイプライン実行状況管理
pipeline_status: Dict[str, Dict[str, Any]] = {}


# リクエストIDミドルウェア
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """リクエストIDを追加するミドルウェア"""
    request_id = str(uuid.uuid4())[:8]
    request.state.request_id = request_id

    # リクエストログ
    logger.info(
        f"Request received: {request.method} {request.url}",
        extra={
            "request_id": request_id,
            "operation": "http_request",
            "method": request.method,
            "url": str(request.url),
            "user_agent": request.headers.get("user-agent", "unknown"),
        },
    )

    # メトリクス記録
    metrics.increment_counter(
        "http_requests_total", tags={"method": request.method, "endpoint": request.url.path}
    )

    response = await call_next(request)

    # レスポンスヘッダーにリクエストIDを追加
    response.headers["X-Request-ID"] = request_id

    # レスポンスログ
    logger.info(
        f"Request completed: {request.method} {request.url}",
        extra={
            "request_id": request_id,
            "operation": "http_response",
            "status_code": response.status_code,
        },
    )

    # レスポンスメトリクス記録
    metrics.increment_counter(
        "http_responses_total",
        tags={
            "method": request.method,
            "endpoint": request.url.path,
            "status_code": str(response.status_code),
        },
    )

    return response


def get_request_id(request: Request) -> str:
    """リクエストIDを取得"""
    return getattr(request.state, "request_id", "unknown")


@retry_on_exception(max_retries=2, delay=1.0, exceptions=(subprocess.TimeoutExpired,))
@log_performance(operation_name="pipeline_execution", logger=logger)
def _run_pipeline(pipeline_id: str, trigger: TriggerType, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    パイプライン実行の内部関数（リトライ機構付き）

    Args:
        pipeline_id: パイプライン実行ID
        trigger: 実行トリガー
        params: 実行パラメータ

    Returns:
        実行結果辞書
    """
    with log_operation(
        "pipeline_execution", logger, pipeline_id=pipeline_id, trigger=trigger.value
    ):

        try:
            # パイプライン実行状況を記録
            pipeline_status[pipeline_id] = {
                "status": PipelineStatus.RUNNING,
                "trigger": trigger,
                "params": mask_sensitive_data(params),  # 機密データをマスク
                "start_time": datetime.now().isoformat(),
                "end_time": None,
            }

            # メトリクス記録
            metrics.increment_counter(
                "pipeline_executions_started", tags={"trigger": trigger.value}
            )

            # パラメータに基づいてコマンドを決定
            command = params.get("command", ["python", "--version"])
            timeout = params.get("timeout", 30)

            # 実際のパイプライン処理
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            if result.returncode == 0:
                pipeline_status[pipeline_id].update(
                    {
                        "status": PipelineStatus.SUCCESS,
                        "end_time": datetime.now().isoformat(),
                        "output": result.stdout.strip(),
                    }
                )

                # 成功メトリクス記録
                metrics.increment_counter(
                    "pipeline_executions_success", tags={"trigger": trigger.value}
                )

                logger.info(f"Pipeline {pipeline_id} completed successfully")
                return {
                    "status": PipelineStatus.SUCCESS,
                    "message": f"Pipeline executed successfully. Output: {result.stdout.strip()}",
                    "pipeline_id": pipeline_id,
                }
            else:
                pipeline_status[pipeline_id].update(
                    {
                        "status": PipelineStatus.ERROR,
                        "end_time": datetime.now().isoformat(),
                        "error": result.stderr,
                    }
                )

                # エラーメトリクス記録
                metrics.increment_counter(
                    "pipeline_executions_error",
                    tags={"trigger": trigger.value, "error_type": "subprocess_error"},
                )

                logger.error(f"Pipeline {pipeline_id} failed: {result.stderr}")
                return {
                    "status": PipelineStatus.ERROR,
                    "message": f"Pipeline execution failed: {result.stderr}",
                    "pipeline_id": pipeline_id,
                }

        except subprocess.TimeoutExpired:
            pipeline_status[pipeline_id].update(
                {
                    "status": PipelineStatus.ERROR,
                    "end_time": datetime.now().isoformat(),
                    "error": f"Pipeline execution timeout ({timeout}s)",
                }
            )

            # タイムアウトメトリクス記録
            metrics.increment_counter(
                "pipeline_executions_timeout",
                tags={"trigger": trigger.value, "timeout_seconds": str(timeout)},
            )

            logger.error(f"Pipeline {pipeline_id} timed out after {timeout}s")
            raise  # リトライ機構に委ねる

        except Exception as e:
            pipeline_status[pipeline_id].update(
                {
                    "status": PipelineStatus.ERROR,
                    "end_time": datetime.now().isoformat(),
                    "error": str(e),
                }
            )

            # 例外メトリクス記録
            metrics.increment_counter(
                "pipeline_executions_error",
                tags={"trigger": trigger.value, "error_type": "exception"},
            )

            logger.error(f"Pipeline {pipeline_id} failed with exception: {e}")
            return {
                "status": PipelineStatus.ERROR,
                "message": f"Pipeline execution failed: {str(e)}",
                "pipeline_id": pipeline_id,
            }


# APIエンドポイント定義


@app.get("/", response_model=Dict[str, str])
async def root():
    """ルートエンドポイント - サービス情報を返す"""
    return {
        "service": "Intake Service API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/intake/pipeline", response_model=PipelineResponse)
async def execute_pipeline(request: PipelineRequest, http_request: Request = None):
    """
    パイプライン実行エンドポイント

    Args:
        request: パイプライン実行リクエスト
        http_request: HTTPリクエストオブジェクト

    Returns:
        パイプライン実行結果

    Raises:
        CustomHTTPException: 実行エラー時
    """
    request_id = get_request_id(http_request) if http_request else None

    try:
        # 一意のパイプラインIDを生成
        pipeline_id = str(uuid.uuid4())[:8]

        # パラメータバリデーション
        if request.params and len(str(request.params)) > 1000:
            ErrorHandler.validation_error(
                "Parameters too large", "Parameters must be less than 1000 characters", request_id
            )

        # パイプライン実行
        result = _run_pipeline(pipeline_id, request.trigger, request.params)

        return PipelineResponse(
            status=result["status"],
            message=result["message"],
            pipeline_id=result["pipeline_id"],
            timestamp=datetime.now().isoformat(),
        )

    except subprocess.TimeoutExpired:
        ErrorHandler.timeout_error(
            "Pipeline execution", request.params.get("timeout", 30), request_id
        )
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        ErrorHandler.internal_error("Pipeline execution failed", str(e), request_id)


@app.get("/api/intake/pipeline/{pipeline_id}", response_model=PipelineStatusResponse)
async def get_pipeline_status(pipeline_id: str, http_request: Request = None):
    """
    パイプライン実行状況取得エンドポイント

    Args:
        pipeline_id: パイプライン実行ID
        http_request: HTTPリクエストオブジェクト

    Returns:
        パイプライン実行状況

    Raises:
        CustomHTTPException: パイプラインIDが見つからない場合
    """
    request_id = get_request_id(http_request) if http_request else None

    if pipeline_id not in pipeline_status:
        ErrorHandler.not_found("Pipeline", pipeline_id, request_id)

    status_data = pipeline_status[pipeline_id]

    return PipelineStatusResponse(pipeline_id=pipeline_id, **status_data)


@app.get("/api/intake/pipelines", response_model=Dict[str, Any])
async def list_pipelines(
    limit: int = 10, offset: int = 0, status_filter: Optional[PipelineStatus] = None
):
    """
    パイプライン一覧取得エンドポイント

    Args:
        limit: 取得件数制限
        offset: 取得開始位置
        status_filter: ステータスフィルタ

    Returns:
        パイプライン一覧
    """
    # バリデーション
    if limit > 100:
        ErrorHandler.validation_error("Limit too large", "Limit must be 100 or less")
    if offset < 0:
        ErrorHandler.validation_error("Invalid offset", "Offset must be non-negative")

    # フィルタリング
    pipelines = list(pipeline_status.items())
    if status_filter:
        pipelines = [
            (pid, status) for pid, status in pipelines if status.get("status") == status_filter
        ]

    total = len(pipelines)

    # ページネーション適用
    paginated_pipelines = pipelines[offset : offset + limit]

    return {
        "pipelines": [{"pipeline_id": pid, **status} for pid, status in paginated_pipelines],
        "total": total,
        "limit": limit,
        "offset": offset,
        "status_filter": status_filter,
    }


@app.delete("/api/intake/pipeline/{pipeline_id}")
async def delete_pipeline(pipeline_id: str, http_request: Request = None):
    """
    パイプライン実行履歴削除エンドポイント

    Args:
        pipeline_id: パイプライン実行ID
        http_request: HTTPリクエストオブジェクト

    Returns:
        削除結果
    """
    request_id = get_request_id(http_request) if http_request else None

    if pipeline_id not in pipeline_status:
        ErrorHandler.not_found("Pipeline", pipeline_id, request_id)

    # 実行中のパイプラインは削除不可
    if pipeline_status[pipeline_id].get("status") == PipelineStatus.RUNNING:
        ErrorHandler.validation_error(
            "Cannot delete running pipeline", "Stop the pipeline before deletion", request_id
        )

    del pipeline_status[pipeline_id]
    logger.info(f"Pipeline {pipeline_id} deleted")

    return {"message": f"Pipeline {pipeline_id} deleted successfully"}


@app.get("/health")
async def health_check():
    """ヘルスチェックエンドポイント"""
    active_pipelines = len(
        [p for p in pipeline_status.values() if p.get("status") == PipelineStatus.RUNNING]
    )

    # ヘルスメトリクス記録
    metrics.record_gauge("active_pipelines", active_pipelines)

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_pipelines": active_pipelines,
    }


@app.get("/metrics")
async def get_metrics():
    """メトリクスエンドポイント"""
    total_pipelines = len(pipeline_status)
    status_counts = {}

    for status_data in pipeline_status.values():
        status = status_data.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    # 内部メトリクス要約取得
    internal_metrics = metrics.get_metrics_summary()

    return {
        "total_pipelines": total_pipelines,
        "status_distribution": status_counts,
        "internal_metrics": internal_metrics,
        "timestamp": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
