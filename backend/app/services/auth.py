import os
import secrets
from datetime import datetime, timedelta, timezone

import httpx
import jwt


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
        "jti": secrets.token_urlsafe(16),
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
        "jti": secrets.token_urlsafe(16),
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
    jti = data.get("jti")
    if jti:
        from app.services.storage import ScanStorage
        storage = ScanStorage()
        if storage.database_configured() and storage.is_token_revoked(jti):
            raise ValueError("Token has been revoked")
    return data


def generate_magic_link_token() -> str:
    return secrets.token_urlsafe(32)


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
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&"
        f"redirect_uri={actual_redirect}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent"
    )


async def exchange_github_code(code: str) -> dict:
    client_id = os.getenv("GITHUB_CLIENT_ID", "").strip()
    client_secret = os.getenv("GITHUB_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        raise RuntimeError("GitHub OAuth credentials not configured")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        access_token = token_data.get("access_token")
        if not access_token:
            raise RuntimeError(f"GitHub OAuth failed: {token_data.get('error_description', 'Unknown error')}")

        userinfo_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        user_info = userinfo_resp.json()

        email = user_info.get("email")
        if not email:
            emails_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                timeout=10,
            )
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                primary = next((e for e in emails if e.get("primary")), None)
                if primary:
                    email = primary["email"]

        return {
            "email": email or "",
            "name": user_info.get("name") or user_info.get("login") or "",
        }


def get_github_auth_url() -> str:
    client_id = os.getenv("GITHUB_CLIENT_ID", "").strip()
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI", "").strip()
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()

    actual_redirect = redirect_uri or f"{frontend_url}/api/v1/auth/github/callback"

    return (
        "https://github.com/login/oauth/authorize?"
        f"client_id={client_id}&"
        f"redirect_uri={actual_redirect}&"
        "scope=user:email"
    )
