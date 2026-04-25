import asyncio
import os
import uuid
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.orchestrator.brain import BrainOrchestrator, BrainStatus
from app.services.storage import ScanStorage

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

app = FastAPI(title="AETHER Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

active_scans: Dict[str, Dict[str, str | bool]] = {}
brain_sessions: Dict[str, BrainOrchestrator] = {}
scan_storage = ScanStorage()


def normalize_target(target_url: str) -> str:
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")

    if not parsed.netloc:
        raise ValueError("Target must include a valid hostname.")

    return parsed.geturl()


def build_reasoning_logs(target_url: str) -> List[dict]:
    hostname = urlparse(target_url).netloc.upper()

    return [
        {"type": "info", "phase": "observe", "msg": f"OBSERVE: TARGET LOCKED ON {hostname}"},
        {"type": "info", "phase": "observe", "msg": "OBSERVE: INSPECTING HEADERS, ROUTES, AND ENTRY POINTS."},
        {"type": "warn", "phase": "observe", "msg": "OBSERVE: REACT FRONTEND SIGNAL DETECTED. API RECON PRIORITIZED."},
        {"type": "info", "phase": "plan", "msg": "PLAN: BUILDING A MINIMAL HYPOTHESIS SET FROM DISCOVERED SURFACES."},
        {"type": "info", "phase": "plan", "msg": "PLAN: STAGING SAFE PROBES FOR AUTHORIZATION, INPUT, AND SESSION CONTROLS."},
        {"type": "info", "phase": "execute", "msg": "EXECUTE: LAUNCHING CONTROLLED BROWSER AND REQUEST SEQUENCE."},
        {"type": "success", "phase": "execute", "msg": "EXECUTE: TELEMETRY STREAM ACTIVE. PAYLOAD WINDOW REMAINS CONSTRAINED."},
        {"type": "info", "phase": "analyze", "msg": "ANALYZE: CORRELATING RESPONSES FOR ROOT-CAUSE SIGNALS AND FALSE-POSITIVE FILTERING."},
        {"type": "success", "phase": "analyze", "msg": "ANALYZE: INITIAL SURFACE MAP COMPLETE. READY FOR NEXT REASONING PASS."},
    ]


def create_scan_record(target_url: str, user_id: str | None = None) -> dict:
    scan_id = uuid.uuid4().hex[:8]
    active_scans[scan_id] = {
        "active": True,
        "target_url": target_url,
        "user_id": user_id,
    }
    brain_sessions[scan_id] = BrainOrchestrator(scan_id=scan_id, target_url=target_url)
    return {"scan_id": scan_id, "target_url": target_url}


@app.get("/health")
async def healthcheck():
    return {"status": "online", "engine": "O-P-E-A Flow Active"}


@app.get("/api/v1/health")
async def api_healthcheck():
    return {
        "status": "online",
        "engine": "O-P-E-A Flow Active",
        "active_scans": len(active_scans),
        "brain_sessions": len(brain_sessions),
        "supabase_configured": scan_storage.configured(),
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "database_configured": scan_storage.database_configured(),
        "scan_persistence_ready": scan_storage.configured(),
        "plan_persistence_supported": scan_storage.supports_plan_persistence() if scan_storage.configured() else False,
        "session_persistence_supported": scan_storage.supports_session_persistence() if scan_storage.configured() else False,
    }


@app.post("/api/v1/scans")
@app.post("/api/v1/scan", include_in_schema=False)
@app.post("/scan", include_in_schema=False)
async def create_scan(
    target_url: str = Query(..., min_length=3),
    user_id: str | None = Query(default=None),
):
    try:
        normalized_target = normalize_target(target_url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return create_scan_record(normalized_target, user_id=user_id)


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    scan = active_scans.get(scan_id)
    brain = brain_sessions.get(scan_id)
    if not scan or not brain:
        await websocket.send_json({"type": "error", "phase": "observe", "msg": "SCAN SESSION NOT FOUND."})
        await websocket.close(code=1008)
        return

    target_url = str(scan["target_url"])
    user_id = scan.get("user_id")

    try:
        await brain.ensure_initial_plan()
        try:
            scan_storage.ensure_schema()
            scan_storage.upsert_scan(
                scan_id=scan_id,
                target_url=target_url,
                initial_plan=brain.serialize_initial_plan(),
                brain_status=brain.state.status.value,
                user_id=str(user_id) if user_id else None,
            )
        except Exception:
            pass

        await websocket.send_json(
            {
                "type": "thought",
                "phase": "observe",
                "msg": f"ENGINE LINK ESTABLISHED FOR {target_url.upper()}",
                "brain": brain.state.snapshot(),
            }
        )

        async for log in brain.stream():
            if not active_scans.get(scan_id, {}).get("active"):
                brain.terminate()
                await websocket.send_json(
                    {
                        "type": "error",
                        "phase": "analyze",
                        "msg": "SCAN TERMINATED BY OPERATOR.",
                        "brain": brain.state.snapshot(),
                    }
                )
                break

            await websocket.send_json(log)

            if log["phase"] == "plan" and brain.state.status == BrainStatus.PAUSED:
                while brain.state.status == BrainStatus.PAUSED and active_scans.get(scan_id, {}).get("active"):
                    signal = await websocket.receive_json()
                    snapshot = brain.apply_signal(
                        signal=signal.get("action", ""),
                        reason=signal.get("reason"),
                    )
                    await websocket.send_json(
                        {
                            "type": "plan",
                            "phase": "plan",
                            "msg": f"PLAN SIGNAL RECEIVED: {signal.get('action', '').upper() or 'UNKNOWN'}",
                            "brain": snapshot,
                        }
                    )

                    try:
                        scan_storage.upsert_scan(
                            scan_id=scan_id,
                            target_url=target_url,
                            initial_plan=brain.serialize_initial_plan(),
                            brain_status=brain.state.status.value,
                            user_id=str(user_id) if user_id else None,
                        )
                    except Exception:
                        pass
    except WebSocketDisconnect:
        if brain.state.status != BrainStatus.COMPLETE:
            brain.terminate()
    finally:
        try:
            scan_storage.upsert_scan(
                scan_id=scan_id,
                target_url=target_url,
                initial_plan=brain.serialize_initial_plan(),
                brain_status=brain.state.status.value,
                user_id=str(user_id) if user_id else None,
            )
        except Exception:
            pass
        active_scans.pop(scan_id, None)
        brain_sessions.pop(scan_id, None)


@app.post("/api/v1/scan/kill/{scan_id}")
async def kill_scan(scan_id: str):
    scan = active_scans.get(scan_id)
    if not scan:
        return {"status": "scan_not_found"}

    scan["active"] = False
    brain = brain_sessions.get(scan_id)
    if brain:
        brain.terminate()
    return {"status": "termination_sequence_initiated", "scan_id": scan_id}
