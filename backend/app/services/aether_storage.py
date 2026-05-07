import os
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.types.json import Jsonb


class AetherStorage:
    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or os.getenv("DATABASE_URL", "").strip()
        if not self.database_url:
            raise RuntimeError("DATABASE_URL is required for AetherStorage")

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.database_url)

    def log_transaction(self, user_id: uuid.UUID, table_name: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"DEBUG: [{timestamp}] User {user_id} is inserting into {table_name}")

    def insert_consent(
        self,
        user_id: uuid.UUID,
        target_url: str,
        ip_address: str | None = None,
        confirmed_at: datetime | None = None,
    ) -> uuid.UUID:
        self.log_transaction(user_id, "consent_logs")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    insert into public.consent_logs (user_id, target_url, ip_address, confirmed_at)
                    values (%s, %s, %s, coalesce(%s, timezone('utc', now())))
                    returning id
                    """,
                    (user_id, target_url, ip_address, confirmed_at),
                )
                row = cursor.fetchone()
            connection.commit()
        return row[0]

    def create_scan(
        self,
        user_id: uuid.UUID,
        target_url: str,
        status: str = "pending",
        threat_level: str = "unknown",
        initial_plan: dict[str, Any] | None = None,
        thought_trace: dict[str, Any] | list[Any] | None = None,
        results: dict[str, Any] | None = None,
        final_report: dict[str, Any] | None = None,
        remediations: dict[str, Any] | None = None,
        completed_at: datetime | None = None,
    ) -> uuid.UUID:
        self.log_transaction(user_id, "scans")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    insert into public.scans (
                        user_id,
                        target_url,
                        status,
                        threat_level,
                        initial_plan,
                        thought_trace,
                        results,
                        final_report,
                        remediations,
                        completed_at
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    returning id
                    """,
                    (
                        user_id,
                        target_url,
                        status,
                        threat_level,
                        Jsonb(initial_plan or {"steps": []}),
                        Jsonb(thought_trace) if thought_trace is not None else None,
                        Jsonb(results or {}),
                        Jsonb(final_report or {}),
                        Jsonb(remediations or {}),
                        completed_at,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return row[0]

    def update_scan_trace(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        trace: dict[str, Any] | list[Any],
    ) -> bool:
        self.log_transaction(user_id, "scans")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    update public.scans
                    set thought_trace = %s
                    where id = %s and user_id = %s
                    """,
                    (Jsonb(trace), scan_id, user_id),
                )
                updated = cursor.rowcount > 0
            connection.commit()
        return updated

    def create_session(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        target_url: str,
        status: str = "started",
        threat_level: str | None = None,
        scan_started_at: datetime | None = None,
        scan_completed_at: datetime | None = None,
    ) -> uuid.UUID:
        self.log_transaction(user_id, "scan_sessions")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    insert into public.scan_sessions (
                        scan_id,
                        user_id,
                        target_url,
                        status,
                        threat_level,
                        scan_started_at,
                        scan_completed_at
                    )
                    values (%s, %s, %s, %s, %s, coalesce(%s, timezone('utc', now())), %s)
                    returning id
                    """,
                    (
                        scan_id,
                        user_id,
                        target_url,
                        status,
                        threat_level,
                        scan_started_at,
                        scan_completed_at,
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return row[0]

    def insert_vulnerability(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        category: str,
        title: str,
        severity: str,
        detail: str,
        session_id: uuid.UUID | None = None,
        attack_vector: str | None = None,
        detected_threat: str | None = None,
        evidence_snippet: str | None = None,
        provided_solution: str | None = None,
        evidence: dict[str, Any] | None = None,
        vulnerability_id: str | None = None,
    ) -> str:
        self.log_transaction(user_id, "vulnerabilities")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    insert into public.vulnerabilities (
                        id,
                        user_id,
                        scan_id,
                        session_id,
                        attack_vector,
                        detected_threat,
                        evidence_snippet,
                        provided_solution,
                        category,
                        title,
                        severity,
                        detail,
                        evidence
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    returning id
                    """,
                    (
                        vulnerability_id or str(uuid.uuid4()),
                        user_id,
                        scan_id,
                        session_id,
                        attack_vector,
                        detected_threat,
                        evidence_snippet,
                        provided_solution,
                        category,
                        title,
                        severity,
                        detail,
                        Jsonb(evidence or {}),
                    ),
                )
                row = cursor.fetchone()
            connection.commit()
        return row[0]
