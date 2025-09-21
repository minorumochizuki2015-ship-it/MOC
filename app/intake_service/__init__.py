"""
学習インテーク・アプリ用パッケージ
ローカル統治核AI用学習データ収集・管理システム
"""

from .api import app
from .classifier import classifier, classify_domain
from .schema import (
    DomainType,
    IntakeItem,
    IntakeItemCreate,
    IntakeItemMeta,
    IntakeItemUpdate,
    IntakeListResponse,
    IntakeResponse,
    PrivacyLevel,
    SourceType,
    TaskType,
    create_intake_item,
    create_sft_item,
)

__version__ = "1.0.0"
__all__ = [
    "app",
    "classify_domain",
    "classifier",
    "DomainType",
    "IntakeItem",
    "IntakeItemCreate",
    "IntakeItemMeta",
    "IntakeItemUpdate",
    "IntakeListResponse",
    "IntakeResponse",
    "PrivacyLevel",
    "SourceType",
    "TaskType",
    "create_intake_item",
    "create_sft_item",
]

