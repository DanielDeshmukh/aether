import logging
import os
import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.services.storage import ScanStorage

security = HTTPBearer()
logger = logging.getLogger("AETHER_BACKEND")
scan_storage = ScanStorage()


async def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> str:
    token = creds.credentials

    secret = os.getenv("AETHER_JWT_SECRET", "").strip()
    if not secret:
        logger.error("AUTH_FAILURE: AETHER_JWT_SECRET is not configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret not configured",
        )

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.InvalidTokenError as exc:
        logger.error("AUTH_FAILURE: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from exc


async def get_verified_user_id(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> uuid.UUID:
    token = creds.credentials if creds else None
    if not token:
        raise HTTPException(status_code=401, detail="No Auth Header")

    secret = os.getenv("AETHER_JWT_SECRET", "").strip()
    if not secret:
        logger.error("AUTH_FAILURE: AETHER_JWT_SECRET is not configured")
        raise HTTPException(status_code=500, detail="JWT secret not configured")

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
        user_id = uuid.UUID(payload["sub"])
        return user_id
    except Exception as exc:
        logger.error("AUTH_FAILURE: %s", str(exc))
        raise HTTPException(status_code=401, detail="Invalid Session") from exc


async def check_scan_quota(
    user_id: Annotated[str, Depends(get_current_user)],
) -> str:
    total_scans = scan_storage.get_total_scan_count(user_id)
    if total_scans >= 3:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AETHER MVP Limit Reached: 3/3 scans used. Contact DevLabs for access.",
        )
    return user_id
