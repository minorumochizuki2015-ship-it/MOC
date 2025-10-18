"""
共通エラーハンドリングモジュール
プロジェクト全体で統一されたエラーハンドリングとレスポンス形式を提供
"""

import logging
import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ErrorCode(str, Enum):
    """エラーコード定義"""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class ErrorSeverity(str, Enum):
    """エラー重要度"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StandardErrorResponse(BaseModel):
    """標準エラーレスポンス形式"""

    error_code: ErrorCode = Field(..., description="エラーコード")
    message: str = Field(..., description="ユーザー向けエラーメッセージ")
    details: Optional[str] = Field(None, description="詳細情報（開発者向け）")
    timestamp: str = Field(..., description="エラー発生時刻")
    request_id: Optional[str] = Field(None, description="リクエストID")
    severity: ErrorSeverity = Field(ErrorSeverity.MEDIUM, description="エラー重要度")


class CustomHTTPException(HTTPException):
    """カスタムHTTP例外クラス"""

    def __init__(
        self,
        status_code: int,
        error_code: ErrorCode,
        message: str,
        details: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        request_id: Optional[str] = None,
    ):
        self.error_code = error_code
        self.message = message
        self.details = details
        self.severity = severity
        self.request_id = request_id

        error_response = StandardErrorResponse(
            error_code=error_code,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            request_id=request_id,
            severity=severity,
        )

        super().__init__(status_code=status_code, detail=error_response.dict())


def create_error_response(
    status_code: int,
    error_code: ErrorCode,
    message: str,
    details: Optional[str] = None,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    request_id: Optional[str] = None,
) -> JSONResponse:
    """標準エラーレスポンス作成"""
    error_response = StandardErrorResponse(
        error_code=error_code,
        message=message,
        details=details,
        timestamp=datetime.now().isoformat(),
        request_id=request_id,
        severity=severity,
    )

    # ログ出力
    log_level = {
        ErrorSeverity.LOW: logging.INFO,
        ErrorSeverity.MEDIUM: logging.WARNING,
        ErrorSeverity.HIGH: logging.ERROR,
        ErrorSeverity.CRITICAL: logging.CRITICAL,
    }.get(severity, logging.WARNING)

    logger.log(
        log_level,
        f"Error {error_code}: {message} (Status: {status_code}, Request ID: {request_id})",
    )

    return JSONResponse(status_code=status_code, content=error_response.dict())


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """グローバル例外ハンドラ"""
    request_id = getattr(request.state, "request_id", None)

    # CustomHTTPExceptionの場合
    if isinstance(exc, CustomHTTPException):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    # HTTPExceptionの場合
    if isinstance(exc, HTTPException):
        return create_error_response(
            status_code=exc.status_code,
            error_code=ErrorCode.INTERNAL_ERROR,
            message=str(exc.detail),
            request_id=request_id,
        )

    # その他の例外
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return create_error_response(
        status_code=500,
        error_code=ErrorCode.INTERNAL_ERROR,
        message="Internal server error",
        details=str(exc) if logger.isEnabledFor(logging.DEBUG) else None,
        severity=ErrorSeverity.HIGH,
        request_id=request_id,
    )


def mask_sensitive_data(data: Dict[str, Any], sensitive_keys: set = None) -> Dict[str, Any]:
    """機密データのマスク処理"""
    if sensitive_keys is None:
        sensitive_keys = {
            "password",
            "token",
            "secret",
            "key",
            "auth",
            "credential",
            "api_key",
            "access_token",
            "refresh_token",
            "private_key",
        }

    masked_data = {}
    for key, value in data.items():
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
            masked_data[key] = "***MASKED***"
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
        elif isinstance(value, list):
            masked_data[key] = [
                mask_sensitive_data(item, sensitive_keys) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            masked_data[key] = value

    return masked_data


class ErrorHandler:
    """エラーハンドリングユーティリティクラス"""

    @staticmethod
    def validation_error(
        message: str, details: Optional[str] = None, request_id: Optional[str] = None
    ):
        """バリデーションエラー"""
        raise CustomHTTPException(
            status_code=400,
            error_code=ErrorCode.VALIDATION_ERROR,
            message=message,
            details=details,
            severity=ErrorSeverity.LOW,
            request_id=request_id,
        )

    @staticmethod
    def not_found(resource: str, identifier: str, request_id: Optional[str] = None):
        """リソース未発見エラー"""
        raise CustomHTTPException(
            status_code=404,
            error_code=ErrorCode.NOT_FOUND,
            message=f"{resource} not found",
            details=f"{resource} with identifier '{identifier}' does not exist",
            severity=ErrorSeverity.LOW,
            request_id=request_id,
        )

    @staticmethod
    def internal_error(
        message: str, details: Optional[str] = None, request_id: Optional[str] = None
    ):
        """内部エラー"""
        raise CustomHTTPException(
            status_code=500,
            error_code=ErrorCode.INTERNAL_ERROR,
            message=message,
            details=details,
            severity=ErrorSeverity.HIGH,
            request_id=request_id,
        )

    @staticmethod
    def timeout_error(operation: str, timeout_seconds: int, request_id: Optional[str] = None):
        """タイムアウトエラー"""
        raise CustomHTTPException(
            status_code=408,
            error_code=ErrorCode.TIMEOUT_ERROR,
            message=f"Operation timed out",
            details=f"{operation} exceeded timeout of {timeout_seconds} seconds",
            severity=ErrorSeverity.MEDIUM,
            request_id=request_id,
        )

    @staticmethod
    def service_unavailable(service: str, request_id: Optional[str] = None):
        """サービス利用不可エラー"""
        raise CustomHTTPException(
            status_code=503,
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            message=f"Service temporarily unavailable",
            details=f"{service} is currently unavailable",
            severity=ErrorSeverity.HIGH,
            request_id=request_id,
        )


# リトライ機構
import asyncio
from functools import wraps
from typing import Callable, Tuple, Type


def retry_on_exception(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
):
    """例外発生時のリトライデコレータ"""

    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries:
                        logger.error(
                            f"Function {func.__name__} failed after {max_retries} retries: {e}"
                        )
                        raise

                    wait_time = delay * (backoff_factor**attempt)
                    logger.warning(
                        f"Function {func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {wait_time}s: {e}"
                    )
                    await asyncio.sleep(wait_time)

            raise last_exception

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries:
                        logger.error(
                            f"Function {func.__name__} failed after {max_retries} retries: {e}"
                        )
                        raise

                    wait_time = delay * (backoff_factor**attempt)
                    logger.warning(
                        f"Function {func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {wait_time}s: {e}"
                    )
                    import time

                    time.sleep(wait_time)

            raise last_exception

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator
