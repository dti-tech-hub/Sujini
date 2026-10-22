"""Pydantic request/response schemas for the REST API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    created_at: str | None = None
    last_login_at: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class EventIn(BaseModel):
    """Flexible event envelope.

    Known fields are documented here; additional collector-specific fields are
    preserved in `raw_event` by the normalizer. A raw web-server log line can be
    supplied in `line` instead.
    """

    model_config = ConfigDict(extra="allow")

    timestamp: Any | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    method: str | None = None
    destination: str | None = None
    endpoint: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    event_type: str | None = None
    severity: str | None = None
    message: str | None = None
    request_body: str | None = None
    dataset_label: str | None = None
    line: str | None = None


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=4000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    attack_category: str = Field(default="suspicious_activity", max_length=64)
    source_ip: str | None = None
    username: str | None = None


class ApprovalRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)
    action_ids: list[str] | None = None


class RejectionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    action_ids: list[str] | None = None


class MessageResponse(BaseModel):
    message: str
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    database: str
    version: str
    llm: str
    threat_intel: str
    simulation_mode: bool
    timestamp: str
    database_latency_ms: float | None = None
    detection: dict[str, Any] | None = None
