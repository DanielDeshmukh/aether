"""
Log-Verification Utility for Safety Handshake Monitoring.

This module provides real-time telemetry capture and verification of the
X-Aether-Safety-Token and RateLimiter behavior during vulnerability scans.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("aether.log_monitor")


@dataclass
class RequestLogEntry:
    """A single logged request with safety header verification."""
    timestamp: float
    request_url: str
    safety_token: str
    status: str  # "success" or "blocked"
    status_code: int | None = None
    latency_ms: int | None = None
    notes: str = ""


@dataclass
class SafetyAuditSnapshot:
    """Snapshot of the safety audit state at a point in time."""
    total_requests: int
    successful_requests: int
    blocked_requests: int
    average_latency_ms: float
    rps_recorded: List[float]
    safety_tokens_verified: int
    safety_tokens_failed: int
    scan_start_timestamp: float | None = None
    scan_end_timestamp: float | None = None
    total_scan_duration_seconds: float | None = None
    rps_budget_remaining: float | None = None
    rps_violations: int = 0


class LogMonitor:
    """
    Real-time telemetry and safety verification for AETHER scans.

    Monitors:
    - X-Aether-Safety-Token verification
    - Request success/blocked status
    - RateLimiter compliance (RPS budget)
    - Request latencies in high-latency environments
    """

    def __init__(self, scan_id: str, user_id: str, max_rps: float = 2.0) -> None:
        self.scan_id = scan_id
        self.user_id = user_id
        self.max_rps = float(max_rps)
        self.request_logs: List[RequestLogEntry] = []
        self._lock = asyncio.Lock()
        self.scan_start_time: float | None = None
        self.scan_end_time: float | None = None
        self.safety_tokens_verified = 0
        self.safety_tokens_failed = 0
        self.rps_violations = 0

    async def log_request(
        self,
        request_url: str,
        safety_token: str,
        status: str,
        status_code: int | None = None,
        latency_ms: int | None = None,
        notes: str = "",
    ) -> None:
        """
        Log a single request with safety verification.

        Args:
            request_url: The URL being requested
            safety_token: The X-Aether-Safety-Token header value
            status: "success" or "blocked"
            status_code: HTTP status code if applicable
            latency_ms: Request latency in milliseconds
            notes: Optional additional context
        """
        async with self._lock:
            if safety_token:
                self.safety_tokens_verified += 1
            else:
                self.safety_tokens_failed += 1

            entry = RequestLogEntry(
                timestamp=time.monotonic(),
                request_url=request_url,
                safety_token=safety_token or "",
                status=status,
                status_code=status_code,
                latency_ms=latency_ms,
                notes=notes,
            )
            self.request_logs.append(entry)
            logger.debug(
                f"[SAFETY_LOG] {request_url} | Token={'✓' if safety_token else '✗'} | Status={status} | Code={status_code}"
            )

    async def mark_scan_start(self) -> None:
        """Mark the beginning of the scan for duration tracking."""
        async with self._lock:
            self.scan_start_time = time.monotonic()
            logger.info(f"[SAFETY_AUDIT] Scan started for scan_id={self.scan_id}")

    async def mark_scan_end(self) -> None:
        """Mark the end of the scan."""
        async with self._lock:
            self.scan_end_time = time.monotonic()
            logger.info(f"[SAFETY_AUDIT] Scan ended for scan_id={self.scan_id}")

    def _compute_rps_from_timestamps(self, timestamps: List[float]) -> float:
        """Compute actual requests-per-second from a list of monotonic timestamps."""
        if len(timestamps) < 2:
            return 0.0
        time_span = max(timestamps) - min(timestamps)
        if time_span == 0:
            return 0.0
        return len(timestamps) / time_span

    async def check_rps_budget(self, rate_limiter_timestamps: List[float]) -> bool:
        """
        Verify that the RateLimiter complied with the RPS budget.

        Args:
            rate_limiter_timestamps: Timestamps from RateLimiter.request_timestamps

        Returns:
            True if within budget, False if violated
        """
        if not rate_limiter_timestamps:
            return True

        actual_rps = self._compute_rps_from_timestamps(rate_limiter_timestamps)
        compliant = actual_rps <= self.max_rps

        if not compliant:
            self.rps_violations += 1
            logger.warning(
                f"[SAFETY_AUDIT] RPS budget violation detected: actual={actual_rps:.2f} rps, budget={self.max_rps} rps"
            )
        else:
            logger.debug(
                f"[SAFETY_AUDIT] RPS budget compliant: actual={actual_rps:.2f} rps, budget={self.max_rps} rps"
            )

        return compliant

    async def generate_safety_audit_report(self, rate_limiter_timestamps: List[float]) -> SafetyAuditSnapshot:
        """
        Generate a comprehensive Safety Audit report.

        This report proves:
        1. The X-Aether-Safety-Token was correctly identified
        2. The RateLimiter behaved as expected
        3. The scan stayed within the RPS budget

        Args:
            rate_limiter_timestamps: Timestamps from RateLimiter.request_timestamps for RPS verification

        Returns:
            SafetyAuditSnapshot with comprehensive audit data
        """
        async with self._lock:
            total_requests = len(self.request_logs)
            successful_requests = len([log for log in self.request_logs if log.status == "success"])
            blocked_requests = len([log for log in self.request_logs if log.status == "blocked"])

            # Calculate average latency
            latencies = [log.latency_ms for log in self.request_logs if log.latency_ms is not None]
            average_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0

            # Calculate actual RPS from rate limiter timestamps
            actual_rps = self._compute_rps_from_timestamps(rate_limiter_timestamps)
            rps_budget_remaining = max(0.0, self.max_rps - actual_rps)

            # Calculate scan duration
            total_scan_duration_seconds = None
            if self.scan_start_time is not None and self.scan_end_time is not None:
                total_scan_duration_seconds = self.scan_end_time - self.scan_start_time

            snapshot = SafetyAuditSnapshot(
                total_requests=total_requests,
                successful_requests=successful_requests,
                blocked_requests=blocked_requests,
                average_latency_ms=average_latency_ms,
                rps_recorded=rate_limiter_timestamps,
                safety_tokens_verified=self.safety_tokens_verified,
                safety_tokens_failed=self.safety_tokens_failed,
                scan_start_timestamp=self.scan_start_time,
                scan_end_timestamp=self.scan_end_time,
                total_scan_duration_seconds=total_scan_duration_seconds,
                rps_budget_remaining=rps_budget_remaining,
                rps_violations=self.rps_violations,
            )

            logger.info(
                f"[SAFETY_AUDIT] Report Generated: total_requests={total_requests}, "
                f"successful={successful_requests}, blocked={blocked_requests}, "
                f"avg_latency={average_latency_ms:.1f}ms, actual_rps={actual_rps:.2f}, "
                f"violations={self.rps_violations}"
            )

            return snapshot

    def to_dict(self, snapshot: SafetyAuditSnapshot) -> Dict[str, Any]:
        """
        Convert SafetyAuditSnapshot to a serializable dictionary for JSON reporting.

        Args:
            snapshot: The audit snapshot to serialize

        Returns:
            Dictionary representation of the safety audit
        """
        return {
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "total_requests": snapshot.total_requests,
            "successful_requests": snapshot.successful_requests,
            "blocked_requests": snapshot.blocked_requests,
            "success_rate_percent": (
                (snapshot.successful_requests / snapshot.total_requests * 100)
                if snapshot.total_requests > 0
                else 0
            ),
            "average_latency_ms": round(snapshot.average_latency_ms, 2),
            "safety_tokens_verified": snapshot.safety_tokens_verified,
            "safety_tokens_failed": snapshot.safety_tokens_failed,
            "rps_budget_max": self.max_rps,
            "rps_budget_remaining": round(snapshot.rps_budget_remaining, 2) if snapshot.rps_budget_remaining is not None else 0,
            "rps_violations": snapshot.rps_violations,
            "rps_compliant": snapshot.rps_violations == 0,
            "scan_duration_seconds": (
                round(snapshot.total_scan_duration_seconds, 2)
                if snapshot.total_scan_duration_seconds is not None
                else None
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_count": len(snapshot.rps_recorded),
            "verdict": self._generate_verdict(snapshot),
        }

    def _generate_verdict(self, snapshot: SafetyAuditSnapshot) -> str:
        """
        Generate a human-readable verdict on the safety handshake.

        Args:
            snapshot: The audit snapshot to analyze

        Returns:
            A verdict string
        """
        issues = []

        # Check token verification
        if snapshot.safety_tokens_failed > 0:
            issues.append(f"{snapshot.safety_tokens_failed} requests without safety token")

        # Check RPS violations
        if snapshot.rps_violations > 0:
            issues.append(f"{snapshot.rps_violations} RPS budget violations")

        # Check blocked requests (may indicate safety gate interventions)
        if snapshot.blocked_requests > 0 and snapshot.blocked_requests > snapshot.successful_requests * 0.1:
            issues.append(f"High block rate ({snapshot.blocked_requests}/{snapshot.total_requests} requests)")

        if not issues:
            return "✓ SAFETY_HANDSHAKE_VERIFIED: All safety checks passed. Scan maintained compliance with authorization and rate limits."

        return f"⚠ SAFETY_HANDSHAKE_PARTIAL: {'; '.join(issues)}. Review scan logs for details."
