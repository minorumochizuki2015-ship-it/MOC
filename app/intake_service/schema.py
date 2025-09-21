"""
学習インテーク・アプリ用スキーマ定義
Pydanticベースのバリデーション・シリアライゼーション
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class SourceType(str, Enum):
    """データソース種別"""
    TRAE = "trae"
    CURSOR = "cursor"
    MANUAL = "manual"


class DomainType(str, Enum):
    """ドメイン種別"""
    CODE = "code"
    WRITE = "write"
    PATENT = "patent"
    UNKNOWN = "unknown"


class TaskType(str, Enum):
    """タスク種別"""
    EDIT = "edit"
    SEARCH = "search"
    FIX = "fix"
    DRAFT = "draft"
    REFACTOR = "refactor"
    SPEC = "spec"


class PrivacyLevel(str, Enum):
    """プライバシーレベル"""
    NO_PII = "no_pii"
    PII_REDACTED = "pii_redacted"


class IntakeItem(BaseModel):
    """学習インテークアイテムの基本スキーマ"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="一意識別子")
    ts: datetime = Field(default_factory=datetime.now, description="タイムスタンプ")
    source: SourceType = Field(..., description="データソース")
    title: str = Field(..., min_length=1, max_length=200, description="短い要約")
    domain: DomainType = Field(default=DomainType.UNKNOWN, description="ドメイン")
    task_type: TaskType = Field(..., description="タスク種別")
    success: bool = Field(..., description="成功フラグ")
    prompt: str = Field(..., min_length=1, description="プロンプト")
    output: str = Field(..., min_length=1, description="出力")
    rationale_success: Optional[str] = Field(None, description="成功理由")
    rationale_failure: Optional[str] = Field(None, description="失敗理由")
    math_or_rules: Optional[str] = Field(None, description="使用した式/根拠/規約")
    refs: List[str] = Field(default_factory=list, description="参照パス/URL")
    privacy: PrivacyLevel = Field(default=PrivacyLevel.NO_PII, description="プライバシーレベル")
    tags: List[str] = Field(default_factory=list, description="タグ")

    @validator('prompt', 'output')
    def validate_content_length(cls, v: str) -> str:
        """コンテンツ長の検証"""
        if len(v) > 10000:  # 10KB制限
            raise ValueError("コンテンツが長すぎます（10KB制限）")
        return v

    @validator('refs')
    def validate_refs(cls, v: List[str]) -> List[str]:
        """参照の検証"""
        if len(v) > 20:  # 参照数制限
            raise ValueError("参照が多すぎます（20個制限）")
        return v

    class Config:
        """Pydantic設定"""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class IntakeItemCreate(BaseModel):
    """インテークアイテム作成用スキーマ"""
    
    source: SourceType = Field(..., description="データソース")
    title: str = Field(..., min_length=1, max_length=200, description="短い要約")
    domain: Optional[DomainType] = Field(None, description="ドメイン（未指定時は自動推定）")
    task_type: TaskType = Field(..., description="タスク種別")
    success: bool = Field(..., description="成功フラグ")
    prompt: str = Field(..., min_length=1, description="プロンプト")
    output: str = Field(..., min_length=1, description="出力")
    rationale_success: Optional[str] = Field(None, description="成功理由")
    rationale_failure: Optional[str] = Field(None, description="失敗理由")
    math_or_rules: Optional[str] = Field(None, description="使用した式/根拠/規約")
    refs: List[str] = Field(default_factory=list, description="参照パス/URL")
    privacy: PrivacyLevel = Field(default=PrivacyLevel.NO_PII, description="プライバシーレベル")
    tags: List[str] = Field(default_factory=list, description="タグ")


class IntakeItemUpdate(BaseModel):
    """インテークアイテム更新用スキーマ"""
    
    title: Optional[str] = Field(None, min_length=1, max_length=200, description="短い要約")
    domain: Optional[DomainType] = Field(None, description="ドメイン")
    task_type: Optional[TaskType] = Field(None, description="タスク種別")
    success: Optional[bool] = Field(None, description="成功フラグ")
    prompt: Optional[str] = Field(None, min_length=1, description="プロンプト")
    output: Optional[str] = Field(None, min_length=1, description="出力")
    rationale_success: Optional[str] = Field(None, description="成功理由")
    rationale_failure: Optional[str] = Field(None, description="失敗理由")
    math_or_rules: Optional[str] = Field(None, description="使用した式/根拠/規約")
    refs: Optional[List[str]] = Field(None, description="参照パス/URL")
    privacy: Optional[PrivacyLevel] = Field(None, description="プライバシーレベル")
    tags: Optional[List[str]] = Field(None, description="タグ")


class IntakeItemMeta(BaseModel):
    """インテークアイテムの軽量メタデータ"""
    
    id: str = Field(..., description="一意識別子")
    ts: datetime = Field(..., description="タイムスタンプ")
    source: SourceType = Field(..., description="データソース")
    title: str = Field(..., description="短い要約")
    domain: DomainType = Field(..., description="ドメイン")
    task_type: TaskType = Field(..., description="タスク種別")
    success: bool = Field(..., description="成功フラグ")
    privacy: PrivacyLevel = Field(..., description="プライバシーレベル")
    tags: List[str] = Field(..., description="タグ")

    class Config:
        """Pydantic設定"""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class IntakeResponse(BaseModel):
    """API応答用スキーマ"""
    
    success: bool = Field(..., description="成功フラグ")
    message: str = Field(..., description="メッセージ")
    data: Optional[Dict[str, Any]] = Field(None, description="データ")


class IntakeListResponse(BaseModel):
    """インテークアイテム一覧応答用スキーマ"""
    
    success: bool = Field(..., description="成功フラグ")
    message: str = Field(..., description="メッセージ")
    items: List[IntakeItemMeta] = Field(..., description="アイテム一覧")
    total: int = Field(..., description="総数")


def create_intake_item(data: IntakeItemCreate) -> IntakeItem:
    """IntakeItemCreateからIntakeItemを作成"""
    return IntakeItem(**data.dict())


def create_sft_item(item: IntakeItem) -> Dict[str, Any]:
    """IntakeItemからSFT用アイテムを作成"""
    return {
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

