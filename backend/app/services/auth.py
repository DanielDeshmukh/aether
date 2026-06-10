import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import jwt
from passlib.hash import bcrypt


_ACCESS_TOKEN_EXPIRY_MINUTES = 60
_REFRESH_TOKEN_EXPIRY_DAYS = 7
_MAGIC_LINK_EXPIRY_MINUTES = 15


def _get_jwt_secret() -> str:
    secret = os.getenv("AETHER_JWT_SECRET", "").strip()
    if not secret:
        raise RuntimeError("AETHER_JWT_SECRET is not configured")
    return secret


def create_access_token(user_id: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "aud": "authenticated",
        "iat": now,
        "exp": now + timedelta(minutes=_ACCESS_TOKEN_EXPIRY_MINUTES),
        "type": "access",
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def create_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "iat": now,
        "exp": now + timedelta(days=_REFRESH_TOKEN_EXPIRY_DAYS),
        "type": "refresh",
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def decode_token(token: str, expected_type: str = "access") -> dict:
    data = jwt.decode(
        token,
        _get_jwt_secret(),
        algorithms=["HS256"],
        audience="authenticated",
    )
    if data.get("type") != expected_type:
        raise ValueError(f"Expected token type '{expected_type}', got '{data.get('type')}'")
    return data


def generate_magic_link_token() -> str:
    return secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    return bcrypt.hash(token)


def _verify_token(raw: str, hashed: str) -> bool:
    try:
        return bcrypt.verify(raw, hashed)
    except Exception:
        return False


async def exchange_google_code(code: str) -> dict:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip()

    if not client_id or not client_secret:
        raise RuntimeError("Google OAuth credentials not configured")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=15,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        access_token = token_data["access_token"]

        userinfo_resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        return userinfo_resp.json()


def get_google_auth_url() -> str:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()

    actual_redirect = redirect_uri or f"{frontend_url}/api/v1/auth/google/callback"

    return (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&"
        f"redirect_uri={actual_redirect}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile&"
        f"access_type=offline&"
        f"prompt=consent"
    )
