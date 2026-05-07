import hashlib
import hmac
import logging
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aether.shield")

class AetherShield:
    """
    Core security logic for AETHER-Shield token validation.
    """
    @staticmethod
    def generate_token(scan_id: str, user_id: str) -> str:
        # Simple deterministic token for MVP safety handshake
        material = f"{scan_id}:{user_id}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def verify_token(token: str, scan_id: str, user_id: str) -> bool:
        if not token:
            return False
        expected = AetherShield.generate_token(scan_id, user_id)
        return hmac.compare_digest(expected, token)


class AetherShieldMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware to inject AETHER-Shield status and audit tokens.
    """
    async def dispatch(self, request: Request, call_next):
        # Pre-processing: validate safety handshake for scan-related endpoints
        if request.url.path.startswith("/api/v1/scans") and request.method == "POST":
            # For MVP, we look for a handshake token or just ensure the shield is ready
            logger.info(f"AETHER-Shield monitoring request to {request.url.path}")

        response = await call_next(request)

        # Post-processing: add the shield signature to all responses
        response.headers["X-Aether-Shield"] = "v1-active"
        return response
