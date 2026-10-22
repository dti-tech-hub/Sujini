"""Shared FastAPI dependencies."""
from __future__ import annotations

from fastapi import Depends, Request

from src.security.authentication import get_current_user
from src.services.soc_service import SocService


def get_service(request: Request) -> SocService:
    return request.app.state.soc_service


def get_request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def current_user(user=Depends(get_current_user)):
    return user
