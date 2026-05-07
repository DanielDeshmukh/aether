import logging
import os
import uuid
from typing import Annotated
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client
from app.services.storage import ScanStorage

security = HTTPBearer()
logger = logging.getLogger("AETHER_BACKEND")
scan_storage = ScanStorage()

def get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        raise RuntimeError("Supabase env vars not loaded")

    return create_client(url, key)


async def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    supabase = Depends(get_supabase)
):
    token = creds.credentials

    err = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    try:
        response = supabase.auth.get_user(token)
        user = response.user

        if not user:
            raise err

        return user.id

    except Exception as e:
        print("AUTH ERROR:", e)
        raise err


async def get_verified_user_id(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> uuid.UUID:
    token = creds.credentials if creds else None
    if not token:
        raise HTTPException(status_code=401, detail="No Auth Header")

    secret = os.getenv("SUPABASE_JWT_SECRET", "").strip()
    if not secret:
        logger.error("AUTH_FAILURE: SUPABASE_JWT_SECRET is not configured")
        raise HTTPException(status_code=500, detail="JWT secret not configured")

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
        user_id = uuid.UUID(payload["sub"])
        logger.info("--- DEV LOG: ACTIVE SESSION ---")
        logger.info("CURRENT_USER_ID: %s", user_id)
        logger.info("-------------------------------")
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
