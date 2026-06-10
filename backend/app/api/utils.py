"""Shared utilities for AETHER API."""

from typing import Any, Optional


def standard_response(
    data: Any = None,
    message: Optional[str] = None,
) -> dict:
    """Create a standardized API response.
    
    Args:
        data: The response data payload.
        message: Optional human-readable message.
        
    Returns:
        Dictionary with consistent format.
    """
    response = {}
    if data is not None:
        response["data"] = data
    if message is not None:
        response["message"] = message
    return response
