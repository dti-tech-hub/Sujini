"""Domain exceptions mapped to HTTP responses at the API boundary."""
from __future__ import annotations


class AppError(Exception):
    status_code = 400
    code = "app_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class PolicyError(AppError):
    status_code = 403
    code = "policy_violation"


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"


class AuthenticationFailure(AppError):
    status_code = 401
    code = "authentication_failed"
