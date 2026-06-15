import asyncio
import io
import logging
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.orchestrator.brain import BrainBoundaryError, BrainOrchestrator, BrainStatus
from app.services.storage import ScanStorage
from app.api.deps import get_current_user
from app.tools.validators import is_safe_url

env_path = Path(__file__).resolve().parents[2] / ".env"
if not env_path.exists():
    env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(env_path)

# Windows-specific fix for Playwright and asyncio subprocess handling
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

_logo_path = Path(__file__).resolve().parents[2] / "frontend" / "public" / "images" / "logo.png"
logo_uri = _logo_path.as_uri() if _logo_path.exists() else ""

logger = logging.getLogger("aether.api")


class ScanCreateRequest(BaseModel):
    target_url: str = Field(min_length=3)
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

active_scans: Dict[str, Dict[str, Any]] = {}
brain_sessions: Dict[str, BrainOrchestrator] = {}
scan_storage = ScanStorage()

logger.warning(
    "PostgreSQL persistence target: database_configured=%s",
    scan_storage.database_configured(),
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
    scan_record: Dict[str, Any] = {
        "active": True,
        "target_url": target_url,
        "user_id": user_id,
    }
    active_scans[scan_id] = scan_record
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
    if not user_id:
        logger.warning("Attempted to persist scan state without user_id for scan_id=%s", scan_id)
        return False

    session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sess_{scan_id}"))
    return scan_storage.persist_full_pipeline(
        scan_id=scan_id,
        user_id=user_id,
        target_url=target_url,
        initial_plan=brain.serialize_initial_plan(),
        brain_status=brain.state.status.value,
        session_id=session_id,
        results=brain.serialize_results(),
        final_report=brain.serialize_final_report(),
        remediations=brain.serialize_remediations(),
    )


def extract_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else None


def _api_response(success: bool, data: dict | list | None = None, error: str | None = None) -> dict:
    """Standardized API response wrapper."""
    response: dict = {"success": success}
    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error
    return response


def generate_pdf_sync(temp_path: str) -> bytes:
    """
    Synchronous helper to generate PDF using Playwright.
    Run in a thread to avoid NotImplementedError on Windows with Python 3.13.
    """
    from playwright.sync_api import sync_playwright
    
    try:
        with sync_playwright() as p:
            # launch browser with --no-sandbox for stability
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                # Use Path.as_uri() to handle Windows absolute paths correctly
                page.goto(Path(temp_path).as_uri())
                # Ensure fonts and network resources are fully loaded
                page.wait_for_load_state("networkidle")
                
                pdf_bytes = page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"}
                )
                return pdf_bytes
            finally:
                browser.close()
    except Exception as e:
        logger.error(f"Playwright sync generation failed: {str(e)}")
        raise


async def render_pdf_report(scan: dict, vulnerabilities: list[dict], profiles: list[dict]) -> bytes:
    target_url = scan.get("target_url", "unknown")
    
    # Map vulnerabilities to HTML
    vulnerabilities_content = ""
    if not vulnerabilities:
        vulnerabilities_content = "No vulnerabilities detected."
    else:
        for v in vulnerabilities:
            title = v.get("title", "Untitled Finding")
            severity = v.get("severity", "unknown").upper()
            detail = v.get("detail", "No detail provided.")
            vulnerabilities_content += f"{title} [{severity}] - {detail}\n"

    # Map diagnosis to HTML
    final_report = scan.get("final_report") or {}
    diagnosis_content = final_report.get("synthesis") or final_report.get("report") or "No diagnosis available."

    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&family=JetBrains+Mono&display=swap');
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        html, body {{
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            background-color: #0a0a0a !important;
            color: #ffffff !important;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            padding: 60px 50px;
        }}

        .header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 50px;
            border-bottom: 1px solid #1A1A1A;
            padding-bottom: 30px;
        }}

        .logo-wrap {{ display: flex; align-items: center; gap: 15px; }}
        .logo-img {{ height: 32px; width: auto; }}
        .brand {{ 
            font-weight: 900; 
            letter-spacing: 0.4em; 
            font-size: 22px; 
            color: #ffffff; 
            text-transform: uppercase;
        }}

        .report-type {{ 
            color: #d4af37 !important; 
            font-weight: 900; 
            font-size: 14px; 
            text-transform: uppercase;
            letter-spacing: 0.2em;
            border: 1px solid #d4af37;
            padding: 8px 16px;
        }}

        .banner {{ 
            background: #111111 !important; 
            border: 1px solid #1A1A1A; 
            padding: 30px; 
            margin-bottom: 40px; 
            border-left: 5px solid #d4af37 !important;
        }}

        .target-label {{ 
            color: #d4af37 !important; 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 11px; 
            text-transform: uppercase; 
            letter-spacing: 0.15em;
            display: block;
            margin-bottom: 10px;
        }}

        .target-url {{ 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 18px; 
            font-weight: 700;
            color: #ffffff;
        }}

        .section {{ 
            margin-bottom: 40px; 
        }}

        .section-title {{ 
            color: #d4af37 !important; 
            font-weight: 900; 
            font-size: 16px; 
            margin-bottom: 25px; 
            display: flex;
            align-items: center;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}

        .section-title::before {{ 
            content: ""; 
            display: inline-block;
            width: 30px;
            height: 1px;
            background: #d4af37;
            margin-right: 15px;
        }}

        .content-card {{ 
            background: #0d0d0d !important;
            border: 1px solid #1A1A1A;
            padding: 30px;
            position: relative;
        }}

        .item-text {{ 
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px; 
            line-height: 1.8; 
            white-space: pre-wrap; 
            color: #e5e5e5;
        }}

        .footer {{
            position: fixed;
            bottom: 40px;
            left: 50px;
            right: 50px;
            border-top: 1px solid #1A1A1A;
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            color: #555555;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-wrap">
            <img src="{logo_uri}" class="logo-img" />
            <span class="brand">AETHER</span>
        </div>
        <div class="report-type">Mission Debrief</div>
    </div>

    <div class="banner">
        <span class="target-label">Primary Intelligence Target</span>
        <span class="target-url">{target_url}</span>
    </div>

    <div class="section">
        <span class="section-title">Surface Vulnerabilities</span>
        <div class="content-card">
            <p class="item-text">{vulnerabilities_content}</p>
        </div>
    </div>

    <div class="section">
        <span class="section-title">Agentic Diagnosis</span>
        <div class="content-card">
            <p class="item-text">{diagnosis_content}</p>
        </div>
    </div>

    <div class="footer">
        <span>AETHER OS v1.0 // Automated Heuristic Evaluation</span>
        <span>Secure Transmission // Confidential</span>
    </div>
</body>
</html>"""

    # Ensure cleanup requirement: write to temp file then delete
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tf:
        tf.write(html_template)
        temp_path = tf.name

    try:
        # Offload sync Playwright execution to a worker thread
        pdf_bytes = await asyncio.to_thread(generate_pdf_sync, temp_path)
        return pdf_bytes
    except Exception as e:
        logger.exception("PDF generation failed: %s", str(e))
        raise HTTPException(
            status_code=500, 
            detail="PDF generation failed. Check Playwright browser installation."
        )
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


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
        "auth_configured": bool(os.getenv("AETHER_JWT_SECRET")),
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "database_configured": scan_storage.database_configured(),
        "scan_persistence_ready": scan_storage.database_configured(),
        "plan_persistence_supported": scan_storage.supports_plan_persistence() if scan_storage.database_configured() else False,
    }


@app.post("/api/v1/scans")
@app.post("/api/v1/scan", include_in_schema=False)
@app.post("/scan", include_in_schema=False)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
):
    try:
        normalized_target = normalize_target(payload.target_url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    if not is_safe_url(normalized_target):
        raise HTTPException(
            status_code=400,
            detail="Forbidden target: Internal or private network scanning is not allowed."
        )

    if not payload.consent_confirmed:
        raise HTTPException(status_code=400, detail="CONSENT CONFIRMATION IS REQUIRED BEFORE A HUNT CAN START.")

    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before consent logging.")
        raise HTTPException(status_code=503, detail="CONSENT LOGGING IS UNAVAILABLE. COMPLETE DATABASE SETUP AND RETRY.")

    consent_logged = scan_storage.log_consent(
        user_id=user_id,
        target_url=normalized_target,
        ip_address=extract_client_ip(request),
    )
    if not consent_logged:
        raise HTTPException(status_code=503, detail="CONSENT COULD NOT BE PERSISTED. HUNT ABORTED.")

    return _api_response(success=True, data=create_scan_record(normalized_target, user_id=user_id))


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    scan = active_scans.get(scan_id)
    brain = brain_sessions.get(scan_id)

    if not scan or not brain:
        await websocket.send_json({
            "type": "error",
            "phase": "observe",
            "msg": "SCAN SESSION NOT FOUND.",
            "message": "The scan session could not be found. It may have expired or been terminated."
        })
        await websocket.close(code=1008)
        return

    target_url = str(scan["target_url"])
    user_id: str | None = scan.get("user_id")

    try:
        await brain.ensure_initial_plan()
        try:
            # Ensure schema is up-to-date before persisting, but don't crash if it fails
            try:
                scan_storage.ensure_schema()
            except Exception as e:
                logger.error("Schema sync failed during initial plan persistence for %s: %s", scan_id, str(e))
                # Continue without schema sync if it fails, persistence might still work

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
                        "type": "info", # Changed to info, as termination is an operator action, not an error
                        "status": "terminated",
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
                        # Ensure schema is up-to-date before persisting, but don't crash if it fails
                        try:
                            scan_storage.ensure_schema()
                        except Exception as e:
                            logger.error("Schema sync failed during plan-stage persistence for %s: %s", scan_id, str(e))

                        persisted = persist_scan_state(scan_id, brain, target_url, user_id)
                        logger.info("Plan-stage scan persistence for %s: %s", scan_id, persisted)
                    except Exception:
                        logger.exception("Plan-stage scan persistence failed for %s", scan_id)

            if log["phase"] in {"execute", "analyze"}:
                try:
                    persisted = persist_scan_state(scan_id, brain, target_url, user_id)
                    # Ensure schema is up-to-date before persisting, but don't crash if it fails
                    try:
                        scan_storage.ensure_schema()
                    except Exception as e:
                        logger.error("Schema sync failed during %s-stage persistence for %s: %s", log["phase"].capitalize(), scan_id, str(e))
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
                "message": "Aether encountered a guarded runtime error. Review the logs for details.",
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
                "message": "Aether is currently experiencing high traffic or the model is temporarily unavailable. Your patience is appreciated.",
                "msg": "UNEXPECTED ORCHESTRATION FAILURE. REVIEW BACKEND LOGS AND RETRY THE SCAN.",
                "brain": brain.state.snapshot(),
                "results": brain.serialize_results(),
                "final_report": brain.serialize_final_report(),
            },
        )
    finally:
        try:
            persisted = persist_scan_state(scan_id, brain, target_url, user_id)
            # Ensure schema is up-to-date before persisting, but don't crash if it fails
            try:
                scan_storage.ensure_schema()
            except Exception as e:
                logger.error("Schema sync failed during final persistence for %s: %s", scan_id, str(e))
            logger.info("Final scan persistence for %s: %s", scan_id, persisted)
        except Exception:
            logger.exception("Final scan persistence failed for %s", scan_id)
        active_scans.pop(scan_id, None)
        brain_sessions.pop(scan_id, None)


@app.post("/api/v1/scan/kill/{scan_id}")
async def kill_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan = active_scans.get(scan_id)
    if not scan:
        return _api_response(success=False, error="Scan not found.")

    if scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="ACCESS DENIED TO THIS SCAN SESSION.")

    scan["active"] = False
    brain = brain_sessions.get(scan_id)
    if brain:
        brain.terminate()
    return _api_response(success=True, data={"status": "termination_sequence_initiated", "scan_id": scan_id})


@app.get("/api/v1/scans")
async def list_scans(user_id: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before listing scans.")

    return _api_response(success=True, data=scan_storage.fetch_all_scans(user_id=user_id))


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before fetching scan %s", scan_id)

    record = scan_storage.fetch_scan(scan_id=scan_id, user_id=current_user)
    if not record:
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    return _api_response(success=True, data=record)


@app.get("/api/v1/scans/{scan_id}/report")
async def download_scan_report(scan_id: str, user_id: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before PDF generation for %s", scan_id)

    record = scan_storage.fetch_scan(scan_id, user_id=user_id)
    if not record:
        logger.warning("Download attempt failed: Scan %s not found for user %s", scan_id, user_id)
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    vulnerabilities = scan_storage.fetch_vulnerabilities(scan_id, user_id=user_id)
    profiles = scan_storage.fetch_profiles(scan_id, user_id=user_id)
    pdf_bytes = await render_pdf_report(record, vulnerabilities, profiles)
    
    target_url = record.get("target_url", "unknown")
    import re
    sanitized_url = re.sub(r'[^a-z0-9]', '-', target_url.lower())
    # Remove leading/trailing hyphens and multiple hyphens
    sanitized_url = re.sub(r'-+', '-', sanitized_url).strip('-')
    filename = f"aether-diagnosis-{sanitized_url}.pdf"

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

    user_id: str | None = websocket.query_params.get("user_id")

    record = scan_storage.fetch_scan(scan_id, user_id=user_id) if user_id else None
    if not record:
        await websocket.send_json({
            "type": "error",
            "phase": "remediate",
            "msg": "SCAN RECORD NOT FOUND OR ACCESS DENIED.",
            "message": "The scan record for remediation could not be found or access is denied."
        })
        await websocket.close(code=1008)
        return

    brain = hydrate_brain_from_record(scan_id=scan_id, record=record)

    try:
        while True:
            payload = await websocket.receive_json()
            action = (payload.get("action") or "").strip().lower()
            if action != "generate_fix":
                await safe_send_json(websocket, {
                    "type": "error",
                    "phase": "remediate",
                    "msg": "UNKNOWN REMEDIATION ACTION.",
                    "message": "The requested remediation action is not recognized."
                })
                continue

            vuln_id = (payload.get("vuln_id") or "").strip()
            remediation = await brain.generate_fix(vuln_id)
            assert user_id is not None
            persisted = scan_storage.save_remediations(scan_id=scan_id, user_id=user_id, remediations=brain.serialize_remediations())
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
                "message": "Remediation generation failed. Review backend logs and retry.",
                "msg": "REMEDIATION GENERATION FAILED. REVIEW BACKEND LOGS AND RETRY.",
            },
        )
