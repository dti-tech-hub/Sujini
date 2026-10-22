"""Authentication routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.schemas import LoginRequest, TokenResponse, UserResponse
from src.database import repository
from src.security.authentication import authenticate_user, create_access_token, get_current_user
from src.security.audit import AuditService
from src.utils.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    limiter = request.app.state.login_limiter
    client = request.client.host if request.client else "unknown"
    allowed, retry_after = limiter.allow(f"login:{client}")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Retry after {retry_after:.0f}s.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
    session: Session = request.app.state.session_factory()
    try:
        user = authenticate_user(session, payload.username, payload.password)
        if not user:
            AuditService(session).record(
                actor=payload.username[:64], actor_role="anonymous", action="LOGIN_FAILED",
                entity_type="user", entity_id=None, outcome="DENIED",
                details={"client_ip": client},
            )
            session.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        repository.touch_last_login(session, user)
        token, expires_in = create_access_token(user)
        AuditService(session).record(
            actor=user.username, actor_role=user.role, action="LOGIN_SUCCESS",
            entity_type="user", entity_id=user.id, outcome="SUCCESS",
            details={"client_ip": client},
        )
        session.commit()
        return TokenResponse(
            access_token=token,
            expires_in=expires_in,
            user=UserResponse(**user.to_dict()),
        )
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        logger.exception("Login failed unexpectedly")
        raise HTTPException(status_code=500, detail="Authentication service error")
    finally:
        session.close()


@router.get("/me", response_model=UserResponse)
def me(user=Depends(get_current_user)) -> UserResponse:
    return UserResponse(**user.to_dict())
