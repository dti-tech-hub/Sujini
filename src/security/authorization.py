"""Role hierarchy and authorization helpers."""
from __future__ import annotations

from fastapi import HTTPException, status

ROLE_LEVEL = {"viewer": 1, "analyst": 2, "admin": 3}


def has_at_least(role: str, minimum: str) -> bool:
    return ROLE_LEVEL.get(role.lower(), 0) >= ROLE_LEVEL.get(minimum.lower(), 99)


def assert_minimum_role(role: str, minimum: str) -> None:
    if not has_at_least(role, minimum):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized; '{minimum}' or higher required",
        )
