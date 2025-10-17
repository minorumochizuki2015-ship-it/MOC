"""
共通ログ設定モジュール
全てのモジュールで統一されたログ設定を提供
"""
import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logging(
    log_name: str = "main",
    log_level: int = logging.INFO,
    log_dir: Optional[Path] = None,
    console_output: bool = True,
    file_output: bool = True
) -> logging.Logger:
    """
    統一されたログ設定を行う
    
    Args:
        log_name: ログファイル名（拡張子なし）
        log_level: ログレベル
        log_dir: ログディレクトリ（Noneの場合はdata/logs/current）
        console_output: コンソール出力の有無
        file_output: ファイル出力の有無
    
    Returns:
        設定されたロガー
    """
    if log_dir is None:
        log_dir = Path("data/logs/current")
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # ハンドラーリスト
    handlers = []
    
    # ファイルハンドラー
    if file_output:
        log_file = log_dir / f"{log_name}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    
    # コンソールハンドラー
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(console_handler)
    
    # ログ設定
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers,
        force=True  # 既存の設定を上書き
    )
    
    return logging.getLogger(__name__)

def get_logger(name: str) -> logging.Logger:
    """
    指定された名前のロガーを取得
    
    Args:
        name: ロガー名
    
    Returns:
        ロガーインスタンス
    """
    return logging.getLogger(name)

# デフォルトログ設定
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_DIR = Path("data/logs/current")

# ログレベル定数
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}