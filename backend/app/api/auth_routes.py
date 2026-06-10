import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr

from app.services.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    exchange_github_code,
    exchange_google_code,
    generate_magic_link_token,
    get_github_auth_url,
    get_google_auth_url,
)
from app.services.email import send_magic_link_email
from app.services.storage import ScanStorage
from app.api.rate_limiter import rate_limit_magic_link, rate_limit_refresh
from app.api.utils import standard_response

logger = logging.getLogger("aether.auth")
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

storage = ScanStorage()


class MagicLinkRequest(BaseModel):
    email: EmailStr


class RefreshRequest(BaseModel):
    refresh_token: str


def _get_or_create_user(
    email: str,
    name: Optional[str] = None,
    provider: str = "email",
) -> dict:
    now = datetime.now(timezone.utc)

    with storage.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email FROM public.users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()

            if row:
                user_id = row[0]
                cur.execute(
                    "UPDATE public.users SET last_login_at = %s, provider = GREATEST(provider, %s) WHERE id = %s",
                    (now, provider, user_id),
                )
                conn.commit()
                return {"id": str(user_id), "email": row[1], "name": name}

            user_id = uuid.uuid4()
            cur.execute(
                """INSERT INTO public.users (id, email, name, provider, created_at, last_login_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (user_id, email, name, provider, now, now),
            )
            conn.commit()
            return {"id": str(user_id), "email": email, "name": name}


def _store_magic_link(email: str, user_id: str, token_hash: str) -> None:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=15)

    with storage.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO public.magic_links (token, email, user_id, expires_at, used, created_at)
                   VALUES (%s, %s, %s, %s, false, %s)""",
                (token_hash, email, uuid.UUID(user_id), expires_at, now),
            )
            conn.commit()


def _verify_magic_link(token_hash: str) -> Optional[dict]:
    now = datetime.now(timezone.utc)

    with storage.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, email, user_id, expires_at, used
                   FROM public.magic_links
                   WHERE token = %s AND used = false
                   ORDER BY created_at DESC LIMIT 1""",
                (token_hash,),
            )
            row = cur.fetchone()

            if not row:
                return None

            ml_id, email, user_id, expires_at, used = row

            if used or (expires_at and expires_at < now):
                return None

            cur.execute(
                "UPDATE public.magic_links SET used = true WHERE id = %s",
                (ml_id,),
            )
            conn.commit()

            return {
                "email": email,
                "user_id": str(user_id),
            }


@router.post("/magic-link")
async def request_magic_link(payload: MagicLinkRequest, request: Request, _rate_limit: None = Depends(rate_limit_magic_link)):
    storage.ensure_schema()

    email = payload.email.lower().strip()

    recent_count = storage.count_magic_links_recent(email, hours=1)
    if recent_count >= 3:
        raise HTTPException(
            status_code=429,
            detail="Too many magic link requests. Maximum 3 per hour. Please try again later.",
        )

    user = _get_or_create_user(email)

    raw_token = generate_magic_link_token()
    _store_magic_link(email, user["id"], raw_token)

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
    magic_link_url = f"{frontend_url}/auth/callback?token={raw_token}"

    sent = await send_magic_link_email(email, magic_link_url)

    if not sent:
        raise HTTPException(
            status_code=503,
            detail="Failed to send magic link email. Please try again.",
        )

    return standard_response(message="Magic link sent to your email.")


@router.get("/verify")
async def verify_magic_link(token: str = Query(...)):
    storage.ensure_schema()

    result = _verify_magic_link(token)

    if not result:
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
        return RedirectResponse(url=f"{frontend_url}/auth/callback?error=invalid_token")

    access = create_access_token(result["user_id"], result["email"])
    refresh = create_refresh_token(result["user_id"])

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
    return RedirectResponse(
        url=f"{frontend_url}/auth/callback?access_token={access}&refresh_token={refresh}"
    )


@router.get("/google")
async def google_auth():
    return RedirectResponse(url=get_google_auth_url())


@router.get("/google/callback")
async def google_callback(code: str = Query(...)):
    storage.ensure_schema()

    try:
        userinfo = await exchange_google_code(code)
    except Exception as exc:
        logger.exception("Google OAuth exchange failed: %s", exc)
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
        return RedirectResponse(url=f"{frontend_url}/auth/callback?error=google_oauth_failed")

    email = userinfo.get("email", "").lower().strip()
    name = userinfo.get("name", "")

    if not email:
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
        return RedirectResponse(url=f"{frontend_url}/auth/callback?error=no_email")

    user = _get_or_create_user(email, name=name, provider="google")

    access = create_access_token(user["id"], email)
    refresh = create_refresh_token(user["id"])

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
    return RedirectResponse(
        url=f"{frontend_url}/auth/callback?access_token={access}&refresh_token={refresh}"
    )


@router.post("/refresh")
async def refresh_token(payload: RefreshRequest, request: Request, _rate_limit: None = Depends(rate_limit_refresh)):
    try:
        data = decode_token(payload.refresh_token, expected_type="refresh")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc

    user_id = data["sub"]

    with storage.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email FROM public.users WHERE id = %s",
                (uuid.UUID(user_id),),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    email = row[0]
    access = create_access_token(user_id, email)

    return standard_response(data={"access_token": access, "token_type": "bearer"})


@router.get("/me")
async def get_me(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth_header[7:]

    try:
        data = decode_token(token, expected_type="access")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    user_id = data["sub"]

    with storage.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, name, provider, created_at FROM public.users WHERE id = %s",
                (uuid.UUID(user_id),),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    return standard_response(data={
        "id": str(row[0]),
        "email": row[1],
        "name": row[2],
        "provider": row[3],
        "created_at": row[4].isoformat() if row[4] else None,
    })


@router.post("/logout")
async def logout(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth_header[7:]

    try:
        data = decode_token(token, expected_type="access")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    jti = data.get("jti")
    user_id = data.get("sub")
    exp = data.get("exp")

    if jti and user_id and exp:
        from datetime import datetime, timezone
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        storage.revoke_token(jti, user_id, expires_at)

    return standard_response(message="Logged out successfully")


@router.delete("/account")
async def delete_account(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth_header[7:]

    try:
        data = decode_token(token, expected_type="access")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    deleted = storage.delete_user_account(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")

    return standard_response(message="Account deleted successfully")


@router.patch("/me")
async def update_profile(request: Request, name: Optional[str] = None, email: Optional[str] = None):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth_header[7:]

    try:
        data = decode_token(token, expected_type="access")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    updated = storage.update_user_profile(user_id, name=name, email=email)
    if not updated:
        raise HTTPException(status_code=400, detail="No changes applied")

    return standard_response(message="Profile updated successfully")


@router.get("/github")
async def github_auth():
    return RedirectResponse(url=get_github_auth_url())


@router.get("/github/callback")
async def github_callback(code: str = Query(...)):
    storage.ensure_schema()

    try:
        userinfo = await exchange_github_code(code)
    except Exception as exc:
        logger.exception("GitHub OAuth exchange failed: %s", exc)
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
        return RedirectResponse(url=f"{frontend_url}/auth/callback?error=github_oauth_failed")

    email = userinfo.get("email", "").lower().strip()
    name = userinfo.get("name", "")

    if not email:
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
        return RedirectResponse(url=f"{frontend_url}/auth/callback?error=no_email")

    user = _get_or_create_user(email, name=name, provider="github")

    access = create_access_token(user["id"], email)
    refresh = create_refresh_token(user["id"])

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080").strip()
    return RedirectResponse(
        url=f"{frontend_url}/auth/callback?access_token={access}&refresh_token={refresh}"
    )
