"""Authentication primitives: JWT access tokens and FastAPI dependencies."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.database import repository
from src.database.models import User
from src.security.passwords import verify_password
from src.utils.config import get_config, get_secret_key

_bearer = HTTPBearer(auto_error=False)


class AuthError(Exception):
    pass


def create_access_token(user: User, expires_minutes: int | None = None) -> tuple[str, int]:
    cfg = get_config().get("auth", {})
    minutes = expires_minutes or int(cfg.get("access_token_minutes", 120))
    issued = datetime.now(tz=timezone.utc)
    expires = issued + timedelta(minutes=minutes)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        "iss": "ai-cyber-ir",
    }
    token = jwt.encode(payload, get_secret_key(), algorithm=cfg.get("algorithm", "HS256"))
    return token, minutes * 60


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            get_secret_key(),
            algorithms=[get_config().get("auth", {}).get("algorithm", "HS256")],
            issuer="ai-cyber-ir",
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token") from exc


def authenticate_user(session: Session, username: str, password: str) -> User | None:
    user = repository.get_user_by_username(session, username)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _session_for(request: Request) -> Session:
    factory = request.app.state.session_factory
    return factory()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    session = _session_for(request)
    try:
        user = session.get(User, payload.get("sub"))
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive or unknown")
        return user
    finally:
        session.close()


def require_roles(*roles: str):
    """Dependency factory enforcing role membership."""
    allowed = {role.lower() for role in roles}

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role.lower() not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(sorted(allowed))}",
            )
        return user

    return dependency
