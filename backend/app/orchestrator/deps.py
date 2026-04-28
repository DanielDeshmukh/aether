import os
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client

security = HTTPBearer()

supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_ANON_KEY")
)

def get_supabase():
    return supabase

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
        response = supabase.auth.get_user(token) # Use the initialized supabase client
        user = response.user

        if not user:
            raise err

        return user.id

    except Exception as e:
        print("AUTH ERROR:", e)
        raise err