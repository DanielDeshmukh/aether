import hashlib
import hmac
import logging
import os
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aether.shield")

class AetherShield:
    """
    Core security logic for AETHER-Shield token validation.
    """
    @staticmethod
    def get_secret() -> bytes:
        secret = os.getenv("AETHER_SHIELD_SECRET", "").strip()
        if not secret:
            # Fallback to a warning and a stable but suboptimal key if unset in dev
            # In production, this should fail fast or be strictly required
            logger.warning("AETHER_SHIELD_SECRET is not configured. Security is degraded.")
            return b"dev-fallback-secret-do-not-use-in-prod"
        return secret.encode("utf-8")

    @staticmethod
    def generate_token(scan_id: str, user_id: str) -> str:
        material = f"{scan_id}:{user_id}".encode("utf-8")
        return hmac.new(AetherShield.get_secret(), material, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_token(token: str, scan_id: str, user_id: str) -> bool:
        if not token:
            return False
        expected = AetherShield.generate_token(scan_id, user_id)
        return hmac.compare_digest(expected, token)

    @staticmethod
    def verify_request_handshake(request: Request) -> bool:
        """
        Verify the safety handshake for an incoming request.
        """
        # For MVP, we expect X-Aether-Scan-ID and X-Aether-User-ID and X-Aether-Safety-Token
        # If the scan initiation path, we might only check for presence of a system signature
        scan_id = request.headers.get("X-Aether-Scan-ID")
        user_id = request.headers.get("X-Aether-User-ID")
        token = request.headers.get("X-Aether-Safety-Token")

        if not all([scan_id, user_id, token]):
            return False

        return AetherShield.verify_token(token, scan_id, user_id)


class AetherShieldMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware to inject AETHER-Shield status and audit tokens.
    """
    async def dispatch(self, request: Request, call_next):
        # Pre-processing: validate safety handshake for scan-related endpoints
        # Note: only enforcing for active scans, not all scan-creation calls if they lack context yet
        if request.url.path.startswith("/api/v1/scans") and request.method == "POST":
            # If they provided handshake headers, verify them
            if "X-Aether-Safety-Token" in request.headers:
                if not AetherShield.verify_request_handshake(request):
                    logger.warning("AETHER-Shield rejected invalid handshake for %s", request.url.path)
                    raise HTTPException(status_code=401, detail="Invalid AETHER-Shield handshake")

            logger.info("AETHER-Shield monitoring request to %s", request.url.path)

        response = await call_next(request)

        # Post-processing: add the shield signature to all successful responses
        response.headers["X-Aether-Shield"] = "v1-active"
        return response
