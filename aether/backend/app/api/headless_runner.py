"""Headless scan runner invoked by the Next.js API."""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv

env_path = Path(__file__).resolve().parents[2] / ".env"
if env_path.exists():
    load_dotenv(env_path)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("headless_runner")


async def run_scan(scan_id: str, target_url: str, user_id: str):
    from app.orchestrator.attack_orchestrator import AttackOrchestrator, GlobalAbort
    from app.orchestrator.brain import BrainOrchestrator, BrainStatus, BrainBoundaryError
    from app.services.domain_verification import DomainVerificationManager
    from app.services.storage import ScanStorage

    storage = ScanStorage()
    brain = BrainOrchestrator(scan_id=scan_id, target_url=target_url)
    verification_manager = DomainVerificationManager(storage)

    nvidia_mode = os.getenv("AETHER_USE_NVIDIA_ORCHESTRATOR", "").lower() in {"1", "true", "yes", "on"}

    def on_stage_update(payload):
        logger.info("[scan:%s] %s: %s", scan_id, payload.get("phase", "?"), payload.get("msg", ""))

    def on_finding_discovered(finding):
        logger.warning("[scan:%s] FINDING: %s [%s]", scan_id, finding.get("title", "unknown"), finding.get("severity", "?"))

    is_aborted = False

    def check_abort():
        return is_aborted

    def get_abort_reason():
        return "SCAN_TERMINATED_BY_SAFETY_GATE"

    try:
        storage.ensure_schema()

        session_id = f"sess_{scan_id}"

        if nvidia_mode:
            orchestrator = AttackOrchestrator(
                user_id=user_id,
                scan_id=scan_id,
                session_id=session_id,
                storage_engine=None,
                global_abort=GlobalAbort(is_triggered=check_abort, reason=get_abort_reason),
                on_stage_update=on_stage_update,
                on_finding_discovered=on_finding_discovered,
                verification_service=verification_manager,
            )
            validation_result = await orchestrator.run_validation_loop(target_url)

            findings = validation_result.get("findings", [])
            remediation_map = validation_result.get("remediations", {})

            severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            highest_severity = "low"
            for f in findings:
                sev = str(f.get("severity", "low")).lower()
                if severity_rank.get(sev, 0) > severity_rank[highest_severity]:
                    highest_severity = sev

            remediation_steps = [
                r.get("summary") for r in remediation_map.values() if r.get("summary")
            ][:4]
            if not remediation_steps:
                remediation_steps = [
                    f.get("provided_solution") for f in findings if f.get("provided_solution")
                ][:4]
            if len(remediation_steps) < 2:
                remediation_steps.extend([
                    "Review every confirmed signal against the local validation trace.",
                    "Patch the exposed control and rerun the scan.",
                ][: 2 - len(remediation_steps)])

            brain.final_report = {
                "threat_level": highest_severity,
                "risk_impact": (
                    f"NVIDIA validation completed against {target_url} with {len(findings)} confirmed signal(s), "
                    f"highest severity {highest_severity.upper()}."
                ),
                "remediation_steps": remediation_steps,
            }
            brain.remediations = remediation_map
            brain.execution_results["audit_engine"] = {
                "target_url": target_url,
                "findings": findings,
                "profiles": validation_result.get("profiles", []),
                "source": "nvidia_orchestrator",
            }
            brain.state.phase = "analyze"
            brain.state.status = BrainStatus.COMPLETE
        else:
            async for log in brain.stream(user_id=user_id, resolved_scan_id=scan_id, resolved_session_id=f"sess_{scan_id}"):
                if log.get("phase") == "plan" and brain.state.status == BrainStatus.PAUSED:
                    brain.resume("HEADLESS_AUTO_RESUME")
                if log.get("phase") in {"execute", "analyze"}:
                    logger.info("[scan:%s] %s stage", scan_id, log["phase"])

        storage.persist_full_pipeline(
            scan_id=scan_id,
            user_id=user_id,
            target_url=target_url,
            initial_plan=brain.serialize_initial_plan(),
            brain_status=brain.state.status.value,
            session_id=f"sess_{scan_id}",
            results=brain.serialize_results(),
            final_report=brain.serialize_final_report(),
            remediations=brain.serialize_remediations(),
        )
        logger.info("[scan:%s] Scan completed successfully.", scan_id)

    except BrainBoundaryError as e:
        brain.fail(e.message, phase=e.phase)
        logger.error("[scan:%s] Scan failed: %s", scan_id, e.message)
    except Exception as e:
        brain.fail("Unexpected headless orchestration failure.")
        logger.exception("[scan:%s] Unexpected error: %s", scan_id, e)
    finally:
        storage.close()


def main():
    parser = argparse.ArgumentParser(description="AETHER Headless Scan Runner")
    parser.add_argument("--scan-id", required=True, help="Scan UUID")
    parser.add_argument("--target-url", required=True, help="Target URL to scan")
    parser.add_argument("--user-id", required=True, help="User UUID")
    args = parser.parse_args()

    asyncio.run(run_scan(args.scan_id, args.target_url, args.user_id))


if __name__ == "__main__":
    main()
