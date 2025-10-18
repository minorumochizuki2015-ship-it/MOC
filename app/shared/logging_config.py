from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = [
    "LogLevel",
    "StructuredFormatter",
    "LoggingConfig",
    "MetricsCollector",
    "log_performance",
    "log_operation",
    "get_logger",
    "create_request_logger",
    "LoggerFactory",
    "is_pytest_running",
    "_in_pytest",
]

_LOG_DIR = Path("data/logs")


def is_pytest_running() -> bool:
    """Detect if the current process is running under pytest without importing pytest."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    if os.environ.get("PYTEST_RUNNING"):
        return True
    if os.environ.get("ORCH_IN_PYTEST") == "1":
        return True
    return False


# Backward-compatible alias expected by existing imports/tests
_in_pytest = is_pytest_running


def _resolve_level(default_level: int) -> int:
    """Resolve log level from environment variables with a default.

    Recognizes LOG_LEVEL / ORCH_LOG_LEVEL.
    Accepts names like DEBUG/INFO/WARNING/ERROR/CRITICAL or numeric levels.
    """
    raw = os.environ.get("LOG_LEVEL") or os.environ.get("ORCH_LOG_LEVEL")
    if not raw:
        return default_level
    try:
        return int(raw)
    except ValueError:
        name = raw.strip().upper()
        mapping = {
            "NOTSET": logging.NOTSET,
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        return mapping.get(name, default_level)


class LogLevel:
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        # Optional extras
        for key in (
            "request_id",
            "user_id",
            "operation",
            "duration_ms",
            "status_code",
            "error_code",
        ):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


class LoggingConfig:
    """Unified logging configuration builder."""

    def __init__(
        self,
        service_name: str,
        log_level: int = LogLevel.INFO,
        log_dir: Optional[str] = None,
        enable_console: bool = True,
        enable_file: bool = True,
        enable_structured: bool = True,
        in_pytest_override: Optional[bool] = None,
    ) -> None:
        self.service_name = service_name
        self.log_level = log_level
        self.log_dir = Path(log_dir) if log_dir else _LOG_DIR
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.enable_structured = enable_structured
        self.in_pytest_override = in_pytest_override

    def setup_logger(self) -> logging.Logger:
        in_pytest = (
            self.in_pytest_override if self.in_pytest_override is not None else is_pytest_running()
        )
        level = _resolve_level(self.log_level if not in_pytest else LogLevel.WARNING)
        logger = logging.getLogger(self.service_name)
        if logger.handlers:
            logger.setLevel(level)
            logger.propagate = False
            return logger

        logger.setLevel(level)
        formatter: logging.Formatter
        if self.enable_structured:
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

        # Stream handler to stderr
        if self.enable_console:
            sh = logging.StreamHandler(sys.stderr)
            sh.setLevel(level)
            sh.setFormatter(formatter)
            logger.addHandler(sh)

        # File handler (suppressed during pytest)
        if self.enable_file and not in_pytest:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(
                    self.log_dir / f"{self.service_name}.log", encoding="utf-8"
                )
                fh.setLevel(level)
                fh.setFormatter(formatter)
                logger.addHandler(fh)
            except Exception:
                # Fail soft if file handler cannot be created
                pass

        logger.propagate = False
        return logger


class MetricsCollector:
    """Lightweight metrics collector that logs metrics events."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.metrics: Dict[str, Any] = {}

    def increment_counter(
        self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None
    ) -> None:
        key = f"counter.{name}"
        self.metrics[key] = int(self.metrics.get(key, 0)) + value
        self.logger.info(
            f"Metric counter incremented: {name}",
            extra={
                "operation": "metric_counter",
                "metric_name": name,
                "metric_value": value,
                "metric_tags": tags or {},
            },
        )

    def record_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        key = f"gauge.{name}"
        self.metrics[key] = float(value)
        self.logger.info(
            f"Metric gauge recorded: {name}",
            extra={
                "operation": "metric_gauge",
                "metric_name": name,
                "metric_value": value,
                "metric_tags": tags or {},
            },
        )

    def record_histogram(
        self, name: str, value: float, tags: Optional[Dict[str, str]] = None
    ) -> None:
        key = f"histogram.{name}"
        bucket = list(self.metrics.get(key, []))
        bucket.append(float(value))
        self.metrics[key] = bucket
        self.logger.info(
            f"Metric histogram recorded: {name}",
            extra={
                "operation": "metric_histogram",
                "metric_name": name,
                "metric_value": value,
                "metric_tags": tags or {},
            },
        )

    def get_metrics_summary(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for key, value in self.metrics.items():
            metric_type, name = key.split(".", 1)
            if metric_type == "histogram" and isinstance(value, list) and value:
                summary[name] = {
                    "count": len(value),
                    "min": min(value),
                    "max": max(value),
                    "avg": sum(value) / len(value),
                }
            else:
                summary[name] = value
        return summary


def log_performance(operation_name: Optional[str] = None, logger: Optional[logging.Logger] = None):
    """Decorator to measure performance and log start/complete/error events."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            request_id = str(uuid.uuid4())[:8]
            op_name = operation_name or f"{func.__module__}.{func.__name__}"

            if logger:
                logger.info(
                    f"Operation started: {op_name}",
                    extra={
                        "request_id": request_id,
                        "operation": op_name,
                        "operation_status": "started",
                    },
                )
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                if logger:
                    logger.info(
                        f"Operation completed: {op_name}",
                        extra={
                            "request_id": request_id,
                            "operation": op_name,
                            "operation_status": "completed",
                            "duration_ms": round(duration_ms, 2),
                        },
                    )
                return result
            except Exception:
                duration_ms = (time.time() - start_time) * 1000
                if logger:
                    logger.error(
                        f"Operation failed: {op_name}",
                        exc_info=True,
                        extra={
                            "request_id": request_id,
                            "operation": op_name,
                            "operation_status": "error",
                            "duration_ms": round(duration_ms, 2),
                        },
                    )
                raise

        return wrapper

    return decorator


@contextmanager
def log_operation(operation_name: str, logger: Optional[logging.Logger] = None):
    """Context manager to log start/completion of an operation."""
    request_id = str(uuid.uuid4())[:8]
    if logger:
        logger.info(
            f"Operation started: {operation_name}",
            extra={
                "request_id": request_id,
                "operation": operation_name,
                "operation_status": "started",
            },
        )
    start = time.time()
    try:
        yield
        duration_ms = (time.time() - start) * 1000
        if logger:
            logger.info(
                f"Operation completed: {operation_name}",
                extra={
                    "request_id": request_id,
                    "operation": operation_name,
                    "operation_status": "completed",
                    "duration_ms": round(duration_ms, 2),
                },
            )
    except Exception:
        duration_ms = (time.time() - start) * 1000
        if logger:
            logger.error(
                f"Operation failed: {operation_name}",
                exc_info=True,
                extra={
                    "request_id": request_id,
                    "operation": operation_name,
                    "operation_status": "error",
                    "duration_ms": round(duration_ms, 2),
                },
            )
        raise


def get_logger(
    service_name: str,
    *,
    log_level: int = LogLevel.INFO,
    structured: bool = True,
    in_pytest: Optional[bool] = None,  # backward-compatible keyword, optional override
) -> logging.Logger:
    """Get a standard logger configured for the service.

    - Suppresses FileHandler when running under pytest (auto-detected).
    - Accepts optional in_pytest override for backward compatibility.
    """
    config = LoggingConfig(
        service_name=service_name,
        log_level=log_level,
        enable_structured=structured,
        in_pytest_override=in_pytest,
    )
    return config.setup_logger()


def create_request_logger(base_logger: logging.Logger, request_id: str) -> logging.LoggerAdapter:
    return logging.LoggerAdapter(base_logger, {"request_id": request_id})


class LoggerFactory:
    _loggers: Dict[str, logging.Logger] = {}

    @classmethod
    def get_logger(cls, service_name: str, **kwargs: Any) -> logging.Logger:
        if service_name not in cls._loggers:
            cls._loggers[service_name] = get_logger(service_name, **kwargs)
        return cls._loggers[service_name]

    @classmethod
    def get_metrics_collector(cls, service_name: str) -> MetricsCollector:
        logger = cls.get_logger(service_name)
        return MetricsCollector(logger)
