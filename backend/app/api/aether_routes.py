import logging
import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_verified_user_id
from app.services.aether_storage import AetherStorage


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AETHER_BACKEND")

router = APIRouter(tags=["aether-storage"])


class StartScanRequest(BaseModel):
    target_url: str = Field(min_length=3)


def get_db() -> AetherStorage:
    return AetherStorage()


@router.post("/scans/start")
async def start_scan(
    payload: StartScanRequest,
    user_id: uuid.UUID = Depends(get_verified_user_id),
    db: AetherStorage = Depends(get_db),
):
    consent_id = db.insert_consent(
        user_id=user_id,
        target_url=payload.target_url,
    )
    scan_id = db.create_scan(
        user_id=user_id,
        target_url=payload.target_url,
        status="started",
    )
    session_id = db.create_session(
        user_id=user_id,
        scan_id=scan_id,
        target_url=payload.target_url,
        status="started",
    )

    return {
        "status": "started",
        "consent_id": str(consent_id),
        "scan_id": str(scan_id),
        "session_id": str(session_id),
    }
