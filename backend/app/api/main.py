import asyncio
import io
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.orchestrator.brain import BrainBoundaryError, BrainOrchestrator, BrainStatus
from app.services.storage import ScanStorage

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

logger = logging.getLogger("aether.api")


class ScanCreateRequest(BaseModel):
    target_url: str = Field(min_length=3)
    user_id: str | None = None
    consent_confirmed: bool = False

def get_allowed_origins() -> List[str]:
    configured = os.getenv("FRONTEND_URL", "")
    if configured.strip():
        return [origin.strip() for origin in configured.split(",") if origin.strip()]

    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


app = FastAPI(title="AETHER Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_scans: Dict[str, Dict[str, str | bool]] = {}
brain_sessions: Dict[str, BrainOrchestrator] = {}
scan_storage = ScanStorage()

logger.warning(
    "Supabase backend target: url=%s configured=%s service_role=%s",
    scan_storage.masked_supabase_url(),
    scan_storage.configured(),
    scan_storage.using_service_role_key(),
)


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


def hydrate_brain_from_record(scan_id: str, record: dict) -> BrainOrchestrator:
    brain = BrainOrchestrator(scan_id=scan_id, target_url=record.get("target_url", ""))
    brain.execution_results = record.get("results") or {"port_scan": None, "header_audit": None, "audit_engine": None}
    brain.final_report = record.get("final_report") or {}
    brain.remediations = record.get("remediations") or {}
    return brain


async def safe_send_json(websocket: WebSocket, payload: dict) -> None:
    if websocket.client_state.name != "CONNECTED":
        return
    await websocket.send_json(payload)


def persist_scan_state(scan_id: str, brain: BrainOrchestrator, target_url: str, user_id: str | None) -> bool:
    persisted = scan_storage.upsert_scan(
        scan_id=scan_id,
        target_url=target_url,
        initial_plan=brain.serialize_initial_plan(),
        brain_status=brain.state.status.value,
        results=brain.serialize_results(),
        final_report=brain.serialize_final_report(),
        remediations=brain.serialize_remediations(),
        user_id=str(user_id) if user_id else None,
    )
    audit_result = brain.serialize_results().get("audit_engine") or {}
    hunt_persisted = scan_storage.replace_hunt_findings(
        scan_id=scan_id,
        vulnerabilities=audit_result.get("findings", []),
        profiles=audit_result.get("profiles", []),
    )
    return persisted and hunt_persisted


def extract_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else None


def render_pdf_report(scan: dict, vulnerabilities: list[dict], profiles: list[dict]) -> bytes:
    try:
        from fpdf import FPDF
    except ImportError as error:
        raise HTTPException(status_code=503, detail="PDF reporting dependency is not installed.") from error

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(content_width, 12, "AETHER Security Audit", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(content_width, 8, f"Target: {scan.get('target_url', 'unknown')}", ln=True)
    pdf.cell(content_width, 8, f"Scan ID: {scan.get('id', 'unknown')}", ln=True)
    pdf.cell(content_width, 8, f"Status: {scan.get('status', 'unknown')}", ln=True)
    pdf.cell(content_width, 8, f"Threat Level: {scan.get('threat_level', 'unknown')}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(content_width, 10, "Detected Vulnerabilities", ln=True)
    pdf.set_font("Helvetica", "", 10)
    if not vulnerabilities:
        pdf.multi_cell(content_width, 6, "No persisted vulnerabilities were available for this hunt.")
    for vulnerability in vulnerabilities:
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(content_width, 7, f"{vulnerability.get('title', 'Untitled Finding')} [{vulnerability.get('severity', 'unknown').upper()}]")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(content_width, 6, vulnerability.get("detail", "No detail provided."))
        evidence = vulnerability.get("evidence") or {}
        if evidence:
            pdf.multi_cell(content_width, 6, f"Evidence: {json.dumps(evidence, ensure_ascii=True)}")
        pdf.ln(2)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(content_width, 10, "Profiles", ln=True)
    pdf.set_font("Helvetica", "", 10)
    if not profiles:
        pdf.multi_cell(content_width, 6, "No persisted resilience profiles were available for this hunt.")
    for profile in profiles:
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(content_width, 7, profile.get("label", "Untitled Profile"))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(content_width, 6, profile.get("summary", ""))
        details = profile.get("details") or {}
        if details:
            pdf.multi_cell(content_width, 6, f"Details: {json.dumps(details, ensure_ascii=True)}")
        pdf.ln(2)

    output = pdf.output(dest="S")
    if isinstance(output, bytearray):
        return bytes(output)
    if isinstance(output, str):
        return output.encode("latin-1")
    return bytes(output)


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
    }


@app.post("/api/v1/scans")
@app.post("/api/v1/scan", include_in_schema=False)
@app.post("/scan", include_in_schema=False)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
):
    try:
        normalized_target = normalize_target(payload.target_url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    if not payload.consent_confirmed:
        raise HTTPException(status_code=400, detail="CONSENT CONFIRMATION IS REQUIRED BEFORE A HUNT CAN START.")

    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before consent logging.")
        raise HTTPException(status_code=503, detail="CONSENT LOGGING IS UNAVAILABLE. COMPLETE DATABASE SETUP AND RETRY.")

    consent_logged = scan_storage.log_consent(
        user_id=payload.user_id,
        target_url=normalized_target,
        ip_address=extract_client_ip(request),
    )
    if not consent_logged:
        raise HTTPException(status_code=503, detail="CONSENT COULD NOT BE PERSISTED. HUNT ABORTED.")

    return create_scan_record(normalized_target, user_id=payload.user_id)


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
            persisted = persist_scan_state(scan_id, brain, target_url, user_id)
            logger.info("Initial scan persistence for %s: %s", scan_id, persisted)
        except Exception:
            logger.exception("Initial scan persistence failed for %s", scan_id)

        await safe_send_json(
            websocket,
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
                await safe_send_json(
                    websocket,
                    {
                        "type": "error",
                        "phase": "analyze",
                        "msg": "SCAN TERMINATED BY OPERATOR.",
                        "brain": brain.state.snapshot(),
                    }
                )
                break

            await safe_send_json(websocket, log)

            if log["phase"] == "plan" and brain.state.status == BrainStatus.PAUSED:
                while brain.state.status == BrainStatus.PAUSED and active_scans.get(scan_id, {}).get("active"):
                    signal = await websocket.receive_json()
                    snapshot = brain.apply_signal(
                        signal=signal.get("action", ""),
                        reason=signal.get("reason"),
                    )
                    await safe_send_json(
                        websocket,
                        {
                            "type": "plan",
                            "phase": "plan",
                            "msg": f"PLAN SIGNAL RECEIVED: {signal.get('action', '').upper() or 'UNKNOWN'}",
                            "brain": snapshot,
                        }
                    )

                    try:
                        persisted = persist_scan_state(scan_id, brain, target_url, user_id)
                        logger.info("Plan-stage scan persistence for %s: %s", scan_id, persisted)
                    except Exception:
                        logger.exception("Plan-stage scan persistence failed for %s", scan_id)

            if log["phase"] in {"execute", "analyze"}:
                try:
                    persisted = persist_scan_state(scan_id, brain, target_url, user_id)
                    logger.info("%s-stage scan persistence for %s: %s", log["phase"].capitalize(), scan_id, persisted)
                except Exception:
                    logger.exception("%s-stage scan persistence failed for %s", log["phase"].capitalize(), scan_id)
    except BrainBoundaryError as error:
        brain.fail(error.message, phase=error.phase)
        logger.exception("Scan %s failed with a guarded runtime error", scan_id)
        await safe_send_json(
            websocket,
            {
                "type": "error",
                "phase": error.phase,
                "msg": error.message.upper(),
                "brain": brain.state.snapshot(),
                "results": brain.serialize_results(),
                "final_report": brain.serialize_final_report(),
            },
        )
    except WebSocketDisconnect:
        if brain.state.status != BrainStatus.COMPLETE:
            brain.terminate()
    except Exception:
        brain.fail("Unexpected orchestration failure. Review the backend logs and retry the scan.")
        logger.exception("Scan %s failed with an unexpected orchestration error", scan_id)
        await safe_send_json(
            websocket,
            {
                "type": "error",
                "phase": "analyze",
                "msg": "UNEXPECTED ORCHESTRATION FAILURE. REVIEW BACKEND LOGS AND RETRY THE SCAN.",
                "brain": brain.state.snapshot(),
                "results": brain.serialize_results(),
                "final_report": brain.serialize_final_report(),
            },
        )
    finally:
        try:
            persisted = persist_scan_state(scan_id, brain, target_url, user_id)
            logger.info("Final scan persistence for %s: %s", scan_id, persisted)
        except Exception:
            logger.exception("Final scan persistence failed for %s", scan_id)
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


@app.get("/api/v1/scans/{scan_id}/report")
async def download_scan_report(scan_id: str):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before PDF generation for %s", scan_id)

    record = scan_storage.fetch_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    vulnerabilities = scan_storage.fetch_vulnerabilities(scan_id)
    profiles = scan_storage.fetch_profiles(scan_id)
    pdf_bytes = render_pdf_report(record, vulnerabilities, profiles)
    filename = f"aether-security-audit-{scan_id}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws/remediation/{scan_id}")
async def websocket_remediation(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Remediation schema sync failed for %s", scan_id)

    record = scan_storage.fetch_scan(scan_id)
    if not record:
        await websocket.send_json({"type": "error", "phase": "remediate", "msg": "SCAN RECORD NOT FOUND."})
        await websocket.close(code=1008)
        return

    brain = hydrate_brain_from_record(scan_id=scan_id, record=record)

    try:
        while True:
            payload = await websocket.receive_json()
            action = (payload.get("action") or "").strip().lower()
            if action != "generate_fix":
                await safe_send_json(websocket, {"type": "error", "phase": "remediate", "msg": "UNKNOWN REMEDIATION ACTION."})
                continue

            vuln_id = (payload.get("vuln_id") or "").strip()
            remediation = await brain.generate_fix(vuln_id)
            persisted = scan_storage.save_remediations(scan_id=scan_id, remediations=brain.serialize_remediations())
            await safe_send_json(
                websocket,
                {
                    "type": "remediate",
                    "phase": "remediate",
                    "msg": f"REMEDIATE: FIX PACKAGE GENERATED FOR {vuln_id.upper() or 'UNKNOWN FINDING'}.",
                    "remediation": remediation,
                    "remediations": brain.serialize_remediations(),
                    "persisted": persisted,
                }
            )
    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("Remediation generation failed for %s", scan_id)
        await safe_send_json(
            websocket,
            {
                "type": "error",
                "phase": "remediate",
                "msg": "REMEDIATION GENERATION FAILED. REVIEW BACKEND LOGS AND RETRY.",
            },
        )
