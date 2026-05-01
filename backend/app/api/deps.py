import os
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client
from app.services.storage import ScanStorage

security = HTTPBearer()
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