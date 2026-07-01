"""Shared pydantic models used across the gateway."""
from __future__ import annotations
from typing import Any, Optional
from enum import Enum
from pydantic import BaseModel, Field


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY_AGENT = "readonly_agent"
    SUPPORT_BOT = "support_bot"


class Principal(BaseModel):
    """The authenticated caller (a human user or an agent/service account)."""
    subject: str
    role: Role


class ToolCallRequest(BaseModel):
    """What a client sends to invoke a tool through the gateway."""
    upstream: str = Field(..., description="Logical name of the upstream MCP server")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    category: str          # e.g. "prompt_injection", "aws_key", "email"
    detail: str
    confidence: float = 1.0
    span: Optional[tuple[int, int]] = None


class ScanVerdict(BaseModel):
    allowed: bool
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: Optional[str] = None
    reason: Optional[str] = None


class ToolCallResult(BaseModel):
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    blocked_by: Optional[str] = None   # "policy" | "injection_scanner" | "pii_scanner"
    findings: list[Finding] = Field(default_factory=list)
