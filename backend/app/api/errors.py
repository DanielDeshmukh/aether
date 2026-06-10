"""Standardized error handling for AETHER API."""

from typing import Any, Dict, Optional
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class AetherError(HTTPException):
    """Base exception class for AETHER-specific errors."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code or f"ERROR_{status_code}"


class ScanNotFoundError(AetherError):
    """Raised when a scan is not found."""
    
    def __init__(self, scan_id: str):
        super().__init__(
            status_code=404,
            detail=f"Scan not found: {scan_id}",
            error_code="SCAN_NOT_FOUND",
        )


class UnauthorizedError(AetherError):
    """Raised when user is not authorized to access a resource."""
    
    def __init__(self, message: str = "Unauthorized access"):
        super().__init__(
            status_code=403,
            detail=message,
            error_code="UNAUTHORIZED",
        )


class RateLimitError(AetherError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded. Please try again later."):
        super().__init__(
            status_code=429,
            detail=message,
            error_code="RATE_LIMIT_EXCEEDED",
            headers={"Retry-After": "60"},
        )


class ValidationError(AetherError):
    """Raised when input validation fails."""
    
    def __init__(self, field: str, message: str):
        super().__init__(
            status_code=422,
            detail=f"Validation error on '{field}': {message}",
            error_code="VALIDATION_ERROR",
        )


class ExternalServiceError(AetherError):
    """Raised when an external service call fails."""
    
    def __init__(self, service: str, message: str = "Service temporarily unavailable"):
        super().__init__(
            status_code=502,
            detail=f"{service}: {message}",
            error_code="EXTERNAL_SERVICE_ERROR",
        )


def create_error_response(
    status_code: int,
    message: str,
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """Create a standardized error response.
    
    Args:
        status_code: HTTP status code.
        message: Human-readable error message.
        error_code: Machine-readable error code.
        details: Additional error details.
        
    Returns:
        JSONResponse with consistent error format.
    """
    content = {
        "error": {
            "code": error_code or f"ERROR_{status_code}",
            "message": message,
        },
        "data": details,
    }
    return JSONResponse(status_code=status_code, content=content)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for unhandled exceptions.
    
    Args:
        request: The incoming request.
        exc: The unhandled exception.
        
    Returns:
        JSONResponse with 500 status and generic error message.
    """
    return create_error_response(
        status_code=500,
        message="Internal server error. Please try again later.",
        error_code="INTERNAL_SERVER_ERROR",
    )


async def aether_error_handler(request: Request, exc: AetherError) -> JSONResponse:
    """Handler for AETHER-specific exceptions.
    
    Args:
        request: The incoming request.
        exc: The AETHER exception.
        
    Returns:
        JSONResponse with appropriate status code and error details.
    """
    return create_error_response(
        status_code=exc.status_code,
        message=exc.detail,
        error_code=exc.error_code,
    )
