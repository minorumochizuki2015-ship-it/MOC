"""
本番環境向け最適化ログ設定モジュール
パフォーマンスを重視したログ設定を提供
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

def setup_production_logging(
    log_name: str = "main",
    log_level: Optional[int] = None,
    log_dir: Optional[Path] = None,
    console_output: bool = False,
    file_output: bool = True,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    本番環境向けの最適化されたログ設定を行う
    
    Args:
        log_name: ログファイル名（拡張子なし）
        log_level: ログレベル（Noneの場合は環境変数から取得）
        log_dir: ログディレクトリ（Noneの場合はdata/logs/current）
        console_output: コンソール出力の有無（本番環境では通常False）
        file_output: ファイル出力の有無
        max_file_size: ログファイルの最大サイズ（バイト）
        backup_count: バックアップファイル数
    
    Returns:
        設定されたロガー
    """
    # 環境変数からログレベルを取得（デフォルトはINFO）
    if log_level is None:
        env_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        log_level = getattr(logging, env_level, logging.INFO)
    
    if log_dir is None:
        log_dir = Path("data/logs/current")
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # ハンドラーリスト
    handlers = []
    
    # ローテーションファイルハンドラー（本番環境推奨）
    if file_output:
        log_file = log_dir / f"{log_name}.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        )
        handlers.append(file_handler)
    
    # コンソールハンドラー（本番環境では通常無効）
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(console_handler)
    
    # ログ設定
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        handlers=handlers,
        force=True
    )
    
    return logging.getLogger(__name__)

def get_performance_logger(name: str, enable_debug: bool = None) -> logging.Logger:
    """
    パフォーマンスを考慮したロガーを取得
    
    Args:
        name: ロガー名
        enable_debug: DEBUGログの有効化（Noneの場合は環境変数から判定）
    
    Returns:
        ロガーインスタンス
    """
    logger = logging.getLogger(name)
    
    # 環境変数でDEBUGログの有効/無効を制御
    if enable_debug is None:
        enable_debug = os.getenv('ENABLE_DEBUG_LOGS', 'false').lower() == 'true'
    
    if not enable_debug and logger.level <= logging.DEBUG:
        logger.setLevel(logging.INFO)
    
    return logger

class ConditionalLogger:
    """
    条件付きログ出力クラス
    高頻度ログの最適化に使用
    """
    
    def __init__(self, logger: logging.Logger, sample_rate: int = 100):
        """
        Args:
            logger: ベースロガー
            sample_rate: サンプリング率（N回に1回ログ出力）
        """
        self.logger = logger
        self.sample_rate = sample_rate
        self.call_count = 0
    
    def debug_sampled(self, message: str, *args, **kwargs):
        """サンプリングされたDEBUGログ"""
        self.call_count += 1
        if self.call_count % self.sample_rate == 0:
            self.logger.debug(message, *args, **kwargs)
    
    def info_sampled(self, message: str, *args, **kwargs):
        """サンプリングされたINFOログ"""
        self.call_count += 1
        if self.call_count % self.sample_rate == 0:
            self.logger.info(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """通常のINFOログ（サンプリングなし）"""
        self.logger.info(message, *args, **kwargs)
    
    def debug(self, message: str, *args, **kwargs):
        """通常のDEBUGログ（サンプリングなし）"""
        self.logger.debug(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """通常のWARNINGログ（サンプリングなし）"""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """通常のERRORログ（サンプリングなし）"""
        self.logger.error(message, *args, **kwargs)

# 本番環境用デフォルト設定
PRODUCTION_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
PRODUCTION_LOG_LEVEL = logging.INFO
PRODUCTION_LOG_DIR = Path("data/logs/current")

# 環境別ログレベル設定
ENVIRONMENT_LOG_LEVELS = {
    'development': logging.DEBUG,
    'testing': logging.INFO,
    'staging': logging.INFO,
    'production': logging.WARNING
}

def get_environment_log_level() -> int:
    """環境に応じたログレベルを取得"""
    env = os.getenv('ENVIRONMENT', 'development').lower()
    return ENVIRONMENT_LOG_LEVELS.get(env, logging.INFO)