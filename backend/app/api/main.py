from contextlib import asynccontextmanager
from pathlib import Path
import asyncio
import base64
from datetime import datetime, timezone
import io
import json
import logging
import os
import sys
import tempfile
import uuid
from typing import Dict, List
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Windows-specific fix for Playwright and asyncio subprocess handling
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uuid as _uuid
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field

from app.api.auth_routes import router as auth_router
from app.orchestrator.attack_orchestrator import AttackOrchestrator, GlobalAbort
from app.orchestrator.brain import BrainBoundaryError, BrainOrchestrator, BrainStatus
from app.services.domain_verification import DomainVerificationManager
from app.services.git_integration_service import GitIntegrationService
from app.services.report_generator import render_pdf_report
from app.services.storage import ScanStorage
from app.api.deps import get_current_user, check_scan_quota
from app.api.shield import AetherShieldMiddleware
from app.tools.validators import is_safe_url

logger = logging.getLogger("aether.api")


class ScanCreateRequest(BaseModel):
    target_url: str = Field(min_length=3)
    consent_confirmed: bool = False

def get_allowed_origins() -> List[str]:
    environment = os.getenv("ENVIRONMENT", "development")
    frontend_url = os.getenv("FRONTEND_URL", "")
    if frontend_url:
        return [url.strip() for url in frontend_url.split(",") if url.strip()]
    if environment == "production":
        return []  # Must set FRONTEND_URL in production
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


_MAX_REQUEST_BYTES = 5 * 1024 * 1024  # 5 MB


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Enforce global request timeout."""

    def __init__(self, app, timeout: float = 30.0):
        super().__init__(app)
        self.timeout = timeout

    async def dispatch(self, request: Request, call_next):
        try:
            return await asyncio.wait_for(call_next(request), timeout=self.timeout)
        except asyncio.TimeoutError:
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=504,
                content={"detail": "Request timeout"},
            )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > _MAX_REQUEST_BYTES:
            return Response(
                content="Request body too large",
                status_code=413,
                media_type="text/plain",
            )
        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(_uuid.uuid4())
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Logs structured request/response data for debugging and audit."""

    def __init__(self, app):
        super().__init__(app)
        self._logger = logging.getLogger("aether.request")

    async def dispatch(self, request: Request, call_next):
        import time
        start = time.monotonic()
        request_id = request.headers.get("x-request-id", "")

        response = await call_next(request)

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        self._logger.info(
            "%s %s %s %sms req_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            request_id,
        )
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
        return response


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Redirect HTTP to HTTPS in production."""

    async def dispatch(self, request: Request, call_next):
        if os.getenv("ENVIRONMENT") == "production":
            if request.headers.get("x-forwarded-proto", "https") != "https":
                from starlette.responses import RedirectResponse
                url = str(request.url).replace("http://", "https://", 1)
                return RedirectResponse(url=url, status_code=301)
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AETHER Engine starting up...")
    yield
    logger.info("AETHER Engine shutting down...")
    for scan_id in list(active_scans.keys()):
        active_scans[scan_id]["shutdown"] = True
    for ws in list(dashboard_connections):
        try:
            await ws.close()
        except Exception:
            pass
    dashboard_connections.clear()
    scan_storage.close()
    logger.info("Shutdown complete.")


app = FastAPI(title="AETHER Engine API", lifespan=lifespan)
app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AetherShieldMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(StructuredLoggingMiddleware)
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(RequestTimeoutMiddleware, timeout=float(os.getenv("REQUEST_TIMEOUT", "30")))

active_scans: Dict[str, Dict[str, str | bool]] = {}
brain_sessions: Dict[str, BrainOrchestrator] = {}
dashboard_connections: set = set()
scan_storage = ScanStorage()
domain_verification_manager = DomainVerificationManager(scan_storage)
git_integration_service = GitIntegrationService(scan_storage)

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


def attach_git_remediation_summary(final_report: dict, *, target_url: str, user_id: str | None, remediations: dict) -> dict:
    enriched_report = dict(final_report or {})
    enriched_report["auto_remediation"] = git_integration_service.build_git_summary(
        target_url=target_url,
        user_id=user_id,
        has_remediations=bool(remediations),
    )
    return enriched_report


def build_git_result_summary(pr_result: dict) -> dict:
    return {
        "provider": pr_result.get("provider"),
        "target_id": pr_result.get("target_id"),
        "repository": pr_result.get("repository"),
        "branch": pr_result.get("branch"),
        "base_branch": pr_result.get("base_branch"),
        "pull_request_url": pr_result.get("pull_request_url"),
        "pull_request_number": pr_result.get("pull_request_number"),
    }


def extract_screenshot_bytes(vulnerability: dict) -> bytes | None:
    evidence = vulnerability.get("evidence") or {}
    artifact = evidence.get("artifact") if isinstance(evidence, dict) else None
    screenshot_base64 = artifact.get("screenshot_base64") if isinstance(artifact, dict) else None
    if not screenshot_base64:
        return None
    try:
        return base64.b64decode(screenshot_base64)
    except Exception:
        logger.exception("Failed to decode screenshot artifact for vulnerability %s", vulnerability.get("id"))
        return None


def extract_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else None


def derive_public_api_base_url(websocket: WebSocket) -> str | None:
    configured = (
        os.getenv("AETHER_PUBLIC_API_URL", "").strip().rstrip("/")
        or os.getenv("VITE_API_URL", "").strip().rstrip("/")
    )
    if configured:
        return configured

    forwarded_proto = websocket.headers.get("x-forwarded-proto")
    scheme = forwarded_proto or ("https" if websocket.url.scheme == "wss" else "http")
    host = websocket.headers.get("x-forwarded-host") or websocket.headers.get("host") or websocket.url.netloc
    if not host:
        return None
    return f"{scheme}://{host}"


@app.get("/health")
async def healthcheck():
    db_health = scan_storage.check_database_health()
    return {
        "status": "online" if db_health.get("healthy", False) else "degraded",
        "engine": "O-P-E-A Flow Active",
        "database": db_health,
    }


@app.get("/api/v1/health")
async def api_healthcheck():
    db_health = scan_storage.check_database_health()
    pool_stats = scan_storage.get_pool_stats()
    return {
        "status": "online" if db_health.get("healthy", False) else "degraded",
        "active_scans": len(active_scans),
        "brain_sessions": len(brain_sessions),
        "auth_configured": bool(os.getenv("AETHER_JWT_SECRET")),
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "database": db_health,
        "connection_pool": pool_stats,
        "scan_persistence_ready": scan_storage.database_configured(),
        "plan_persistence_supported": bool(os.getenv("DATABASE_URL")),
    }


@app.get("/api/v1/verification/status")
async def get_verification_status(domain: str, user_id: str | None = Depends(get_current_user)):
    """Get verification status for a domain."""
    verification = await domain_verification_manager.verify_target(f"https://{domain}", user_id=user_id)
    return {
        "domain": domain,
        "verification": verification.model_dump(),
        "rate_limit_status": domain_verification_manager.get_rate_limit_status(domain),
    }


@app.post("/api/v1/scans")
@app.post("/api/v1/scan", include_in_schema=False)
@app.post("/scan", include_in_schema=False)
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

    consent_logged = scan_storage.log_consent(
        user_id=user_id,
        target_url=normalized_target,
        ip_address=extract_client_ip(request),
    )
    if not consent_logged:
        raise HTTPException(status_code=503, detail="CONSENT COULD NOT BE PERSISTED. HUNT ABORTED.")

    try:
        target_id = scan_storage.get_or_create_target(
            target_url=normalized_target,
            user_id=user_id
        )
        logger.info("Target acquired: target_id=%s domain=%s user_id=%s", target_id, normalized_target, user_id)
    except Exception as error:
        logger.exception("Failed to get or create target: %s", str(error))
        raise HTTPException(status_code=503, detail="TARGET REGISTRATION FAILED. HUNT ABORTED.")

    result = create_scan_record(normalized_target, user_id=user_id)

    import asyncio
    asyncio.create_task(broadcast_dashboard_update({
        "type": "scan_update",
        "scan": {
            "id": result["scan_id"],
            "target_url": normalized_target,
            "status": "pending",
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    }))

    return result


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

    try:
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
            brain.final_report = attach_git_remediation_summary(
                build_nvidia_final_report(validation_result, target_url),
                target_url=target_url,
                user_id=str(user_id) if user_id else None,
                remediations=brain.serialize_remediations(),
            )

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


@app.post("/api/v1/scan/{scan_id}/pause")
async def pause_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan = active_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or not active.")
    if scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="ACCESS DENIED.")
    brain = brain_sessions.get(scan_id)
    if not brain:
        raise HTTPException(status_code=404, detail="Brain session not found.")
    brain.pause("OPERATOR REQUESTED PAUSE VIA API.")
    return {"status": "paused", "scan_id": scan_id}


@app.post("/api/v1/scan/{scan_id}/resume")
async def resume_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan = active_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or not active.")
    if scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="ACCESS DENIED.")
    brain = brain_sessions.get(scan_id)
    if not brain:
        raise HTTPException(status_code=404, detail="Brain session not found.")
    brain.resume("OPERATOR REQUESTED RESUME VIA API.")
    return {"status": "resumed", "scan_id": scan_id}


@app.post("/api/v1/scan/{scan_id}/terminate")
async def terminate_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan = active_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or not active.")
    if scan.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="ACCESS DENIED.")
    scan["active"] = False
    brain = brain_sessions.get(scan_id)
    if brain:
        brain.terminate()
    return {"status": "terminated", "scan_id": scan_id}


@app.delete("/api/v1/scans/{scan_id}")
async def delete_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    scan_storage.ensure_schema()
    deleted = scan_storage.delete_scan(scan_id, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    active_scans.pop(scan_id, None)
    brain_sessions.pop(scan_id, None)
    return {"message": "Scan deleted successfully"}


@app.post("/api/v1/scans/{scan_id}/rerun")
async def rerun_scan(scan_id: str, user_id: str = Depends(check_scan_quota)):
    """Re-run a failed or completed scan."""
    scan_storage.ensure_schema()
    record = scan_storage.fetch_scan(scan_id=scan_id, user_id=user_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found.")
    
    target_url = record.get("target_url")
    if not target_url:
        raise HTTPException(status_code=400, detail="Scan record is missing target URL.")
    
    # Create a new scan with the same target
    result = create_scan_record(target_url, user_id=user_id)
    
    # Broadcast dashboard update
    import asyncio
    asyncio.create_task(broadcast_dashboard_update({
        "type": "scan_update",
        "scan": {
            "id": result["scan_id"],
            "target_url": target_url,
            "status": "pending",
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    }))
    
    return {
        "message": "Scan re-run initiated",
        "original_scan_id": scan_id,
        "new_scan_id": result["scan_id"],
        "target_url": target_url,
    }


@app.get("/api/v1/scans/compare")
async def compare_scans(ids: str, user_id: str = Depends(get_current_user)):
    scan_storage.ensure_schema()
    scan_id_list = [i.strip() for i in ids.split(",") if i.strip()]
    if len(scan_id_list) < 2:
        raise HTTPException(status_code=400, detail="Provide at least 2 scan IDs to compare.")
    scans = scan_storage.fetch_scans_by_ids(scan_id_list, user_id)
    if len(scans) < 2:
        raise HTTPException(status_code=404, detail="Not enough matching scans found.")
    result = []
    for scan in scans:
        vulns = scan_storage.fetch_vulnerabilities(str(scan["id"]), user_id)
        result.append({
            "scan_id": str(scan["id"]),
            "target_url": scan.get("target_url"),
            "status": scan.get("status"),
            "threat_level": scan.get("threat_level"),
            "created_at": scan.get("created_at").isoformat() if scan.get("created_at") else None,
            "vulnerability_count": len(vulns),
            "vulnerabilities": [{"title": v.get("title"), "severity": v.get("severity"), "category": v.get("category")} for v in vulns],
        })
    return {"comparison": result}


@app.get("/api/v1/scans/{scan_id}/export")
async def export_scan(scan_id: str, format: str = "json", user_id: str = Depends(get_current_user)):
    scan_storage.ensure_schema()
    record = scan_storage.fetch_scan(scan_id, user_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found.")
    vulnerabilities = scan_storage.fetch_vulnerabilities(scan_id, user_id)
    profiles = scan_storage.fetch_profiles(scan_id, user_id)

    export_data = {
        "scan_id": scan_id,
        "target_url": record.get("target_url"),
        "status": record.get("status"),
        "threat_level": record.get("threat_level"),
        "created_at": record.get("created_at").isoformat() if record.get("created_at") else None,
        "completed_at": record.get("completed_at").isoformat() if record.get("completed_at") else None,
        "final_report": record.get("final_report"),
        "vulnerabilities": [
            {
                "id": v.get("id"),
                "title": v.get("title"),
                "severity": v.get("severity"),
                "category": v.get("category"),
                "detail": v.get("detail"),
                "attack_vector": v.get("attack_vector"),
                "evidence_snippet": v.get("evidence_snippet"),
                "provided_solution": v.get("provided_solution"),
            }
            for v in vulnerabilities
        ],
        "profiles": [
            {
                "label": p.get("label"),
                "summary": p.get("summary"),
                "details": p.get("details"),
            }
            for p in profiles
        ],
    }

    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "id", "title", "severity", "category", "detail", "attack_vector", "evidence_snippet", "provided_solution"
        ])
        writer.writeheader()
        for v in export_data["vulnerabilities"]:
            writer.writerow(v)
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"},
        )

    return export_data


@app.get("/api/v1/scans/{scan_id}/remediation-history")
async def get_remediation_history(scan_id: str, user_id: str = Depends(get_current_user)):
    scan_storage.ensure_schema()
    history = scan_storage.fetch_remediation_history(scan_id, user_id)
    return {"history": history}


@app.get("/api/v1/scans")
async def list_scans(user_id: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before listing scans.")

    scans = scan_storage.fetch_all_scans(user_id=user_id)
    
    # Add verification status for each scan's target domain
    for scan in scans:
        target_url = scan.get("target_url", "")
        if target_url:
            domain = domain_verification_manager._extract_domain(target_url)
            if domain:
                # Check if target is verified in the database
                record = scan_storage.fetch_target_verification_record(domain, user_id=user_id)
                scan["is_verified"] = bool(record.get("is_verified")) if record else False
            else:
                scan["is_verified"] = False
        else:
            scan["is_verified"] = False
    
    return scans


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: str = Depends(get_current_user)):
    try:
        scan_storage.ensure_schema()
    except Exception:
        logger.exception("Schema sync failed before fetching scan %s", scan_id)

    record = scan_storage.fetch_scan(scan_id=scan_id, user_id=current_user)
    if not record:
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    final_report = record.get("final_report") or {}
    if "auto_remediation" not in final_report:
        record["final_report"] = attach_git_remediation_summary(
            final_report,
            target_url=record.get("target_url", ""),
            user_id=current_user,
            remediations=record.get("remediations") or {},
        )
    return record


@app.get("/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}/evidence/screenshot")
async def get_vulnerability_screenshot(scan_id: str, vuln_id: str, user_id: str = Depends(get_current_user)):
    record = scan_storage.fetch_scan(scan_id=scan_id, user_id=user_id)
    if not record:
        raise HTTPException(status_code=404, detail="SCAN RECORD NOT FOUND.")

    vulnerabilities = scan_storage.fetch_vulnerabilities(scan_id=scan_id, user_id=user_id)
    vulnerability = next((item for item in vulnerabilities if str(item.get("id")) == vuln_id), None)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="VULNERABILITY NOT FOUND.")

    screenshot_bytes = extract_screenshot_bytes(vulnerability)
    if not screenshot_bytes:
        raise HTTPException(status_code=404, detail="SCREENSHOT EVIDENCE NOT FOUND.")

    return StreamingResponse(io.BytesIO(screenshot_bytes), media_type="image/png")


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
            if action == "generate_fix":
                vuln_id = (payload.get("vuln_id") or "").strip()
                remediation = await brain.generate_fix(vuln_id)
                persisted = scan_storage.save_remediations(scan_id=scan_id, user_id=user_id, remediations=brain.serialize_remediations())
                brain.final_report = attach_git_remediation_summary(
                    brain.serialize_final_report(),
                    target_url=record.get("target_url", ""),
                    user_id=user_id,
                    remediations=brain.serialize_remediations(),
                )
                scan_storage.save_final_report(scan_id=scan_id, user_id=user_id, final_report=brain.serialize_final_report())
                await safe_send_json(
                    websocket,
                    {
                        "type": "remediate",
                        "phase": "remediate",
                        "msg": f"REMEDIATE: FIX PACKAGE GENERATED FOR {vuln_id.upper() or 'UNKNOWN FINDING'}.",
                        "remediation": remediation,
                        "remediations": brain.serialize_remediations(),
                        "final_report": brain.serialize_final_report(),
                        "persisted": persisted,
                    }
                )
                continue

            if action == "create_pull_request":
                vuln_id = (payload.get("vuln_id") or "").strip()
                target_id = (payload.get("target_id") or "").strip()
                if not vuln_id:
                    await safe_send_json(websocket, {"type": "error", "phase": "remediate", "msg": "VULNERABILITY ID IS REQUIRED FOR PULL REQUEST CREATION."})
                    continue
                if not target_id:
                    await safe_send_json(websocket, {"type": "error", "phase": "remediate", "msg": "GIT TARGET ID IS REQUIRED FOR PULL REQUEST CREATION."})
                    continue

                vulnerabilities = scan_storage.fetch_vulnerabilities(scan_id=scan_id, user_id=user_id)
                vulnerability = next((item for item in vulnerabilities if str(item.get("id")) == vuln_id), None)
                remediation = brain.serialize_remediations().get(vuln_id)
                if not vulnerability or not remediation:
                    await safe_send_json(websocket, {"type": "error", "phase": "remediate", "msg": "GENERATE A REMEDIATION PACKAGE BEFORE OPENING A PULL REQUEST."})
                    continue

                await safe_send_json(
                    websocket,
                    {
                        "type": "git_push_status",
                        "phase": "remediate",
                        "status": "pending",
                        "msg": f"REMEDIATE: STAGING GIT REMEDIATION PR FOR {vuln_id.upper()}.",
                    }
                )
                pr_payload = git_integration_service.build_pr_payload(
                    scan_id=scan_id,
                    target_url=record.get("target_url", ""),
                    vulnerability=vulnerability,
                    remediation_payload=remediation,
                    public_api_base_url=derive_public_api_base_url(websocket),
                )
                try:
                    pr_result = await asyncio.to_thread(
                        git_integration_service.stage_remediation_pr,
                        target_id,
                        pr_payload,
                        user_id,
                    )
                except Exception as error:
                    await safe_send_json(
                        websocket,
                        {
                            "type": "git_push_status",
                            "phase": "remediate",
                            "status": "error",
                            "msg": f"GIT REMEDIATION PR FAILED: {str(error).upper()}",
                        }
                    )
                    continue

                brain.final_report = attach_git_remediation_summary(
                    brain.serialize_final_report(),
                    target_url=record.get("target_url", ""),
                    user_id=user_id,
                    remediations=brain.serialize_remediations(),
                )
                auto_remediation = dict(brain.serialize_final_report().get("auto_remediation") or {})
                auto_remediation["last_pull_request"] = build_git_result_summary(pr_result)
                brain.final_report["auto_remediation"] = auto_remediation
                scan_storage.save_final_report(scan_id=scan_id, user_id=user_id, final_report=brain.serialize_final_report())
                await safe_send_json(
                    websocket,
                    {
                        "type": "git_push_status",
                        "phase": "remediate",
                        "status": "success",
                        "msg": f"REMEDIATE: PULL REQUEST OPENED FOR {vuln_id.upper()}.",
                        "git_result": build_git_result_summary(pr_result),
                        "final_report": brain.serialize_final_report(),
                    }
                )
                continue

            else:
                await safe_send_json(websocket, {"type": "error", "phase": "remediate", "msg": "UNKNOWN REMEDIATION ACTION."})
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


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await websocket.accept()

    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.send_json({"type": "error", "msg": "AUTHENTICATION REQUIRED."})
        await websocket.close(code=1008)
        return

    import jwt as pyjwt

    jwt_secret = os.getenv("AETHER_JWT_SECRET", "").strip()
    if not jwt_secret:
        await websocket.send_json({"type": "error", "msg": "AUTH NOT CONFIGURED."})
        await websocket.close(code=1008)
        return

    try:
        payload = pyjwt.decode(token, jwt_secret, algorithms=["HS256"], audience="authenticated")
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("No subject")
    except Exception:
        await websocket.send_json({"type": "error", "msg": "INVALID TOKEN."})
        await websocket.close(code=1008)
        return

    dashboard_connections.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        dashboard_connections.discard(websocket)


async def broadcast_dashboard_update(payload: dict):
    disconnected = set()
    for ws in dashboard_connections:
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.add(ws)
    dashboard_connections.difference_update(disconnected)
