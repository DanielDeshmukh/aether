import asyncio
import base64
import io
import json
import logging
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Union
from urllib.parse import urlparse

from dotenv import load_dotenv

# Load env before importing internal app modules that read settings at import time.
load_dotenv()

# Third-party imports

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

# Windows-specific fix for Playwright and asyncio subprocess handling
# This must remain near the top to ensure the event loop is configured early
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Internal AETHER App Imports
# Ensure your PYTHONPATH includes the 'backend' directory so 'app' is resolvable
from app.api.aether_routes import router as aether_router
from app.orchestrator.attack_orchestrator import AttackOrchestrator, GlobalAbort
from app.orchestrator.brain import BrainBoundaryError, BrainOrchestrator, BrainStatus
from app.services.domain_verification import DomainVerificationManager
from app.services.aether_storage import AetherStorage
from app.services.storage import ScanStorage
from app.api.deps import check_scan_quota, get_current_user
from app.tools.validators import is_safe_url

# Initialize Logger

logger = logging.getLogger("aether.api")


def _rate_limit_key(request: Request) -> str:
    user_email = request.headers.get("x-user-email", "").strip().lower()
    if user_email:
        return user_email
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else "unknown-client"


limiter = Limiter(key_func=_rate_limit_key, default_limits=["60/minute"])


def _rate_limit_exception_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # Keep rate-limit errors consistent with FastAPI HTTPException response shape.
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


class ScanCreateRequest(BaseModel):
    target_url: str = Field(min_length=3)
    consent_confirmed: bool = False

# Sanity check for environment variables
print("SUPABASE URL:", os.getenv("SUPABASE_URL"))

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
app.include_router(aether_router)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exception_handler)

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
domain_verification_manager = DomainVerificationManager(scan_storage)

logger.warning(
    "Supabase backend target: url=%s configured=%s service_role=%s",
    scan_storage.masked_supabase_url(),
    scan_storage.configured(),
    scan_storage.using_service_role_key(),
)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    scan_storage.close()


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
    brain_sessions[scan_id] = BrainOrchestrator(scan_id=scan_id, target_url=target_url, user_identity=user_id)
    return {"scan_id": scan_id, "target_url": target_url}


def hydrate_brain_from_record(scan_id: str, record: dict) -> BrainOrchestrator:
    brain = BrainOrchestrator(
        scan_id=scan_id,
        target_url=record.get("target_url", ""),
        user_identity=record.get("user_id"),
    )
    brain.execution_results = record.get("results") or {"port_scan": None, "header_audit": None, "audit_engine": None}
    brain.final_report = record.get("final_report") or {}
    brain.remediations = record.get("remediations") or {}
    return brain


async def safe_send_json(websocket: WebSocket, payload: dict) -> None:
    if websocket.client_state.name != "CONNECTED":
        return
    await websocket.send_json(payload)


async def enforce_target_verification(
    websocket: WebSocket,
    brain: BrainOrchestrator,
    target_url: str,
    user_id: str | None,
) -> bool:
    verification = await domain_verification_manager.verify_target(target_url, user_id=user_id)
    if verification.allowed:
        return True

    failure_message = verification.failure_message or "DOMAIN VERIFICATION FAILED."
    brain.fail(failure_message, phase="observe")
    await safe_send_json(
        websocket,
        {
            "type": "error",
            "phase": "observe",
            "msg": failure_message,
            "brain": brain.state.snapshot(),
            "verification": verification.model_dump(),
        },
    )
    return False


def persist_scan_state(scan_id: str, brain: BrainOrchestrator, target_url: str, user_id: str | None) -> bool:
    if not user_id:
        logger.warning("Attempted to persist scan state without user_id for scan_id=%s", scan_id)
        return False

    # Requirement: session_id MUST exist. Generate a deterministic ID for telemetry + persistence.
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


def use_nvidia_orchestrator() -> bool:
    return os.getenv("AETHER_USE_NVIDIA_ORCHESTRATOR", "").strip().lower() in {"1", "true", "yes", "on"}


def build_nvidia_final_report(validation_result: dict, target_url: str) -> dict:
    findings = validation_result.get("findings", []) or []
    remediation_map = validation_result.get("remediations", {}) or {}
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest_severity = "low"
    for finding in findings:
        candidate = str(finding.get("severity", "low")).strip().lower()
        if severity_rank.get(candidate, 0) > severity_rank[highest_severity]:
            highest_severity = candidate

    if validation_result.get("status") == "terminated":
        return {
            "threat_level": "critical",
            "risk_impact": "The NVIDIA validation loop was terminated by the safety gate before full category coverage completed.",
            "remediation_steps": [
                "Review the streamed stage logs to confirm why the safety gate triggered.",
                "Re-run the scan only after validating the allowlist and operator controls.",
            ],
            "synthesis": f"NVIDIA validation for {target_url} terminated early under the active safety controls.",
        }

    remediation_steps = [
        remediation.get("summary")
        for remediation in remediation_map.values()
        if remediation.get("summary")
    ][:4]
    if not remediation_steps:
        remediation_steps = [
            finding.get("provided_solution")
            for finding in findings
            if finding.get("provided_solution")
        ][:4]
    if len(remediation_steps) < 2:
        remediation_steps.extend(
            [
                "Review every confirmed signal against the local validation trace before applying production changes.",
                "Patch the exposed control and rerun the NVIDIA-guided scan to confirm the fix holds.",
            ][: 2 - len(remediation_steps)]
        )

    return {
        "threat_level": highest_severity,
        "risk_impact": (
            f"The NVIDIA agentic validation loop completed against {target_url} and recorded "
            f"{len(findings)} confirmed signal(s), with highest severity {highest_severity.upper()}."
        ),
        "remediation_steps": remediation_steps,
        "synthesis": (
            f"Nemotron-guided reasoning completed across the allowlisted OWASP validation lanes and "
            f"captured {len(findings)} persisted finding(s)."
        ),
    }


def extract_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else None


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
    # Load logo as base64
    logo_base64 = ""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(current_dir, "..", "..", "..", "..", "frontend", "public", "images", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_base64 = base64.b64encode(f.read()).decode()
    except Exception:
        logger.exception("Failed to load logo for PDF")

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
            {"<img src='data:image/png;base64," + logo_base64 + "' class='logo-img' />" if logo_base64 else ""}
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
        "supabase_configured": scan_storage.configured(),
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "database_configured": scan_storage.database_configured(),
        "scan_persistence_ready": scan_storage.configured(),
        "plan_persistence_supported": scan_storage.supports_plan_persistence() if scan_storage.configured() else False,
    }


@app.post("/api/v1/scans")
@app.post("/api/v1/scan", include_in_schema=False)
@app.post("/scan", include_in_schema=False)
@limiter.limit("5/minute")
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    user_id: str = Depends(check_scan_quota),
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

    client_ip = extract_client_ip(request)

    consent_logged = scan_storage.log_consent(
        user_id=user_id,
        target_url=normalized_target,
        origin_ip=client_ip,
    )
    if not consent_logged:
        raise HTTPException(status_code=503, detail="CONSENT COULD NOT BE PERSISTED. HUNT ABORTED.")

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
    resolved_scan_id = scan_storage.resolve_record_identifier(scan_id)
    resolved_session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sess_{scan_id}"))
    nvidia_mode = use_nvidia_orchestrator()
    aether_storage = AetherStorage() if not nvidia_mode else None

    persistence_healthy = True

    def try_persist(stage: str, allow_retry: bool = False) -> bool:
        nonlocal persistence_healthy
        if not user_id:
            return False
        if not persistence_healthy and not allow_retry:
            return False
        try:
            persisted = persist_scan_state(scan_id, brain, target_url, user_id)
            logger.info("%s scan persistence for %s: %s", stage, scan_id, persisted)
            return persisted
        except Exception:
            persistence_healthy = False
            logger.exception("%s scan persistence failed for %s", stage, scan_id)
            return False

    async def persist_and_emit_failure(message: str, phase: str) -> None:
        brain.fail(message, phase=phase)
        await safe_send_json(
            websocket,
            {
                "type": "error",
                "phase": phase,
                "msg": message.upper(),
                "brain": brain.state.snapshot(),
                "results": brain.serialize_results(),
                "final_report": brain.serialize_final_report(),
            },
        )
        try_persist("Failure", allow_retry=True)

    try:
        await brain.ensure_initial_plan()
        try:
            scan_storage.ensure_schema()
        except Exception:
            logger.exception("Schema sync failed before initial persistence for %s", scan_id)
        try_persist("Initial")

        await safe_send_json(
            websocket,
            {
                "type": "thought",
                "phase": "observe",
                "msg": f"ENGINE LINK ESTABLISHED FOR {target_url.upper()}",
                "brain": brain.state.snapshot(),
            }
        )

        if not await enforce_target_verification(websocket, brain, target_url, str(user_id) if user_id else None):
            return

        await brain.ensure_initial_plan()
        try:
            scan_storage.ensure_schema()
            persisted = persist_scan_state(scan_id, brain, target_url, user_id)
            logger.info("Initial scan persistence for %s: %s", scan_id, persisted)
        except Exception:
            logger.exception("Initial scan persistence failed for %s", scan_id)

        if nvidia_mode:
            if not user_id:
                raise BrainBoundaryError(
                    "NVIDIA orchestration requires authenticated user context for tenant-safe persistence.",
                    phase="observe",
                )

            await safe_send_json(
                websocket,
                {
                    "type": "thought",
                    "phase": "plan",
                    "msg": "PLAN: NVIDIA ORCHESTRATOR ENABLED. STREAMING AGENTIC REASONING LOOP.",
                    "brain": brain.state.snapshot(),
                }
            )

            async def persist_with_log(stage_label: str) -> None:
                try:
                    persisted = persist_scan_state(scan_id, brain, target_url, user_id)
                    logger.info("%s persistence for %s: %s", stage_label, scan_id, persisted)
                except Exception:
                    logger.exception("%s persistence failed for %s", stage_label, scan_id)

            async def on_stage_update(payload: dict) -> None:
                if not active_scans.get(scan_id, {}).get("active"):
                    return
                brain.state.phase = payload.get("phase", brain.state.phase)
                if payload.get("msg"):
                    brain.append_thought(brain.state.phase, payload["msg"], category=payload.get("category"))
                await safe_send_json(
                    websocket,
                    {
                        **payload,
                        "brain": brain.state.snapshot(),
                        "results": brain.serialize_results(),
                    }
                )
                if brain.state.phase in {"execute", "analyze"}:
                    await persist_with_log(f"{brain.state.phase.capitalize()}-stage scan")

            async def on_finding_discovered(finding: dict) -> None:
                if not active_scans.get(scan_id, {}).get("active"):
                    return
                remediation_payload = finding.get("remediation")
                if remediation_payload and finding.get("id"):
                    brain.remediations[str(finding["id"])] = remediation_payload
                brain.state.phase = "remediate" if remediation_payload else "analyze"
                await safe_send_json(
                    websocket,
                    {
                        "type": "alert",
                        "phase": "analyze",
                        "msg": f"ACTIVE HIT: {str(finding.get('title', 'Untitled Finding')).upper()}",
                        "brain": brain.state.snapshot(),
                        "attack_vector": finding.get("attack_vector"),
                        "severity": finding.get("severity"),
                        "evidence_snippet": finding.get("evidence_snippet"),
                        "provided_solution": finding.get("provided_solution"),
                        "category": finding.get("category"),
                    }
                )
                await safe_send_json(
                    websocket,
                    {
                        "type": "remediation",
                        "phase": "remediate",
                        "msg": f"FIX THIS: {str(finding.get('title', 'Untitled Finding')).upper()}",
                        "brain": brain.state.snapshot(),
                        "provided_solution": finding.get("provided_solution"),
                        "remediation": remediation_payload,
                        "category": finding.get("category"),
                    }
                )
                await persist_with_log("Finding-stage scan")

            orchestrator = AttackOrchestrator(
                user_id=str(user_id),
                scan_id=resolved_scan_id,
                session_id=resolved_session_id,
                storage_engine=None,
                global_abort=GlobalAbort(
                    is_triggered=lambda: not active_scans.get(scan_id, {}).get("active", False),
                    reason=lambda: "SCAN_TERMINATED_BY_SAFETY_GATE",
                ),
                on_stage_update=on_stage_update,
                on_finding_discovered=on_finding_discovered,
                verification_service=domain_verification_manager,
            )
            validation_result = await orchestrator.run_validation_loop(target_url)
            brain.execution_results["tech_stack"] = validation_result.get("tech_stack")
            brain.execution_results["audit_engine"] = {
                "target_url": target_url,
                "findings": validation_result.get("findings", []),
                "profiles": validation_result.get("profiles", []),
                "trace": validation_result.get("trace", []),
                "source": "nvidia_orchestrator",
            }
            brain.remediations.update(validation_result.get("remediations", {}))
            brain.final_report = build_nvidia_final_report(validation_result, target_url)

            if validation_result.get("status") == "terminated":
                brain.terminate()
            else:
                brain.state.phase = "analyze"
                brain.state.status = BrainStatus.COMPLETE
                await safe_send_json(
                    websocket,
                    {
                        "type": "analyze",
                        "phase": "analyze",
                        "msg": (
                            f"ANALYZE: NVIDIA VALIDATION LOOP COMPLETE. "
                            f"{len(validation_result.get('findings', []))} CONFIRMED SIGNAL(S) LOCKED."
                        ),
                        "brain": brain.state.snapshot(),
                        "results": brain.serialize_results(),
                        "final_report": brain.serialize_final_report(),
                    }
                )
                await persist_with_log("Final NVIDIA scan")
        else:
            async for log in brain.stream(
                user_id=str(user_id) if user_id else None,
                resolved_scan_id=resolved_scan_id,
                resolved_session_id=resolved_session_id,
                storage=aether_storage,
            ):
                if not active_scans.get(scan_id, {}).get("active"):
                    brain.terminate()
                    await safe_send_json(
                        websocket,
                        {
                            "type": "error",
                            "phase": "analyze",
                            "msg": "SCAN_TERMINATED_BY_SAFETY_GATE",
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
                        try_persist("Plan-stage")

                if log["phase"] in {"execute", "analyze"}:
                    try_persist(f"{log['phase'].capitalize()}-stage")
    except BrainBoundaryError as error:
        logger.exception("Scan %s failed with a guarded runtime error", scan_id)
        await persist_and_emit_failure(error.message, error.phase)
    except WebSocketDisconnect:
        if brain.state.status != BrainStatus.COMPLETE:
            await persist_and_emit_failure("Websocket disconnected before scan completion.", "analyze")
    except Exception:
        logger.exception("Scan %s failed with an unexpected orchestration error", scan_id)
        await persist_and_emit_failure(
            "Unexpected orchestration failure. Review backend logs and retry the scan.",
            "analyze",
        )
    finally:
        try_persist("Final", allow_retry=True)
        active_scans.pop(scan_id, None)
        brain_sessions.pop(scan_id, None)


@app.post("/api/v1/scan/kill/{scan_id}")
async def kill_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan = active_scans.get(scan_id)
    if not scan:
        return {"status": "scan_not_found"}

    if scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="ACCESS DENIED TO THIS SCAN SESSION.")

    scan["active"] = False
    brain = brain_sessions.get(scan_id)
    if brain:
        brain.terminate()
    return {"status": "termination_sequence_initiated", "scan_id": scan_id}


@app.get("/api/v1/scans")
async def list_scans(user_id: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before listing scans.")

    return scan_storage.fetch_all_scans(user_id=user_id)


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before fetching scan %s", scan_id)

    record = scan_storage.fetch_scan(scan_id=scan_id, user_id=current_user)
    if not record:
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    return record


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

    user_id = websocket.query_params.get("user_id")

    record = scan_storage.fetch_scan(scan_id, user_id=user_id) if user_id else None
    if not record:
        await websocket.send_json({"type": "error", "phase": "remediate", "msg": "SCAN RECORD NOT FOUND OR ACCESS DENIED."})
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
                "msg": "REMEDIATION GENERATION FAILED. REVIEW BACKEND LOGS AND RETRY.",
            },
        )
