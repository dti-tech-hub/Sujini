"""FastAPI application factory and middleware."""
from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.api import (
    routes_alerts, routes_auth, routes_demo, routes_incidents,
    routes_investigation, routes_metrics, routes_response,
)
from src.api.schemas import HealthResponse
from src.database.connection import create_database
from src.security.rate_limit import SlidingWindowRateLimiter
from src.services.soc_service import SocService
from src.utils.config import get_config
from src.utils.exceptions import AppError
from src.utils.helpers import iso, utcnow
from src.utils.logging import get_logger, setup_logging

logger = get_logger(__name__)


def create_app(database_url: str | None = None, *, rate_limit_enabled: bool = True) -> FastAPI:
    setup_logging()
    cfg = get_config()
    engine, session_factory = create_database(database_url)
    service = SocService(session_factory)

    app = FastAPI(
        title=cfg.get("api", {}).get("title", "AI Cyber Incident Response API"),
        version=cfg.get("app", {}).get("version", "1.0.0"),
        description=(
            "AI-agent-assisted web-security incident response: detection, evidence correlation, "
            "threat intelligence, MITRE ATT&CK mapping, risk scoring, human approval, and "
            "simulated safe response. All response actions are simulations."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.soc_service = service
    app.state.started_at = utcnow()
    app.state.rate_limit_enabled = rate_limit_enabled
    api_cfg = cfg.get("api", {})
    app.state.rate_limiter = SlidingWindowRateLimiter(
        int(api_cfg.get("rate_limit_requests", 120)),
        int(api_cfg.get("rate_limit_window_seconds", 60)),
    )
    app.state.login_limiter = SlidingWindowRateLimiter(
        int(api_cfg.get("login_rate_limit_requests", 10)),
        int(api_cfg.get("login_rate_limit_window_seconds", 60)),
    )

    origins = list(api_cfg.get("cors_origins", ["http://localhost:8501"]))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id
        start = time.perf_counter()
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 5 * 1024 * 1024:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request body exceeds 5 MB limit", "request_id": request_id},
                    )
            except ValueError:
                pass
        if rate_limit_enabled and request.url.path not in {
            "/health", "/docs", "/redoc", "/openapi.json", "/auth/login", "/",
        }:
            client = request.client.host if request.client else "unknown"
            allowed, retry_after = app.state.rate_limiter.allow(f"api:{client}")
            if not allowed:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded", "request_id": request_id},
                    headers={"Retry-After": str(int(retry_after) + 1)},
                )
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request error", extra={"request_id": request_id, "path": request.url.path})
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error", "request_id": request_id},
            )
        duration_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-ms"] = f"{duration_ms:.1f}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        logger.info(
            "http_request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.message,
                "code": exc.code,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = []
        for error in exc.errors()[:20]:
            errors.append({
                "loc": [str(part) for part in error.get("loc", [])],
                "msg": str(error.get("msg", "invalid value"))[:300],
                "type": str(error.get("type", "validation_error")),
            })
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Request validation failed",
                "errors": errors,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": getattr(request.state, "request_id", None)},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled application error", extra={"request_id": getattr(request.state, "request_id", None)})
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    app.include_router(routes_auth.router)
    app.include_router(routes_alerts.router)
    app.include_router(routes_incidents.router)
    app.include_router(routes_investigation.router)
    app.include_router(routes_response.router)
    app.include_router(routes_metrics.router)
    app.include_router(routes_demo.router)

    @app.get("/", tags=["system"])
    def root() -> dict[str, Any]:
        return {
            "name": cfg.get("app", {}).get("name"),
            "version": cfg.get("app", {}).get("version"),
            "docs": "/docs",
            "health": "/health",
            "simulation_only": True,
        }

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        data = service.health()
        data.pop("status", None)
        data["status"] = "ok" if data.get("database") == "ok" else "degraded"
        return HealthResponse(**data)

    return app


app = create_app()
