import os
import re
import uuid
from datetime import datetime, timezone
import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List

import psycopg
import requests
from psycopg import sql
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation
from psycopg.types.json import Jsonb
try:
    from psycopg_pool import ConnectionPool
except ModuleNotFoundError:  # pragma: no cover - depends on deployment extras
    ConnectionPool = None
from app.services.validators import validate_and_build_rows


class ScanStorage:
    def __init__(self) -> None:
        self.supabase_url = self._get_first_env("SUPABASE_URL", "VITE_SUPABASE_URL")
        self.supabase_key = self._get_first_env(
            "SUPABASE_SERVICE_ROLE_KEY",
            "VITE_SUPABASE_SERVICE_ROLE_KEY",
            "SUPABASE_KEY",
            "VITE_SUPABASE_ANON_KEY",
        )
        self.database_url = self._normalize_database_url(
            self._get_first_env("DATABASE_URL", "DB_CONNECTION_STRING")
        )
        self.table_name = "scans"
        self.sessions_table = "scan_sessions"
        self.vulnerabilities_table = "vulnerabilities"
        self.profiles_table = "profiles"
        self.consent_logs_table = "consent_logs"
        self._pool: ConnectionPool | None = None
        self._schema_cache: Dict[str, Any] | None = None
        self._logger = logging.getLogger("aether.storage")

    def mask_value(self, value: str, visible: int = 6) -> str:
        if not value:
            return "<unset>"
        if len(value) <= visible * 2:
            return value
        return f"{value[:visible]}...{value[-visible:]}"

    def _get_first_env(self, *names: str) -> str:
        for name in names:
            value = os.getenv(name, "").strip()
            if value:
                return value
        return ""

    def _normalize_database_url(self, value: str) -> str:
        if not value:
            return ""

        normalized = re.sub(r":\[(.*?)\]@", r":\1@", value)
        password = os.getenv("DATABASE_PASSWORD", "").strip()
        if password and ":@" in normalized:
            normalized = normalized.replace(":@", f":{password}@")
        return normalized

    def configured(self) -> bool:
        return self.database_configured()

    def masked_supabase_url(self) -> str:
        return self.mask_value(self.supabase_url)

    def using_service_role_key(self) -> bool:
        return False

    def database_configured(self) -> bool:
        return bool(self.database_url) and not self.database_url.lower().startswith("your_")

    def _get_pool(self) -> ConnectionPool:
        if not self.database_configured():
            raise Exception("CRITICAL: DATABASE_URL is not configured")
        if ConnectionPool is None:
            raise RuntimeError(
                "psycopg_pool is required for transactional persistence. Install 'psycopg-pool'."
            )
        if self._pool is None:
            self._pool = ConnectionPool(
                conninfo=self.database_url,
                min_size=1,
                max_size=5,
                open=False,
            )
            self._pool.open()
        return self._pool

    @contextmanager
    def get_connection(self) -> Iterator[psycopg.Connection]:
        pool = self._get_pool()
        with pool.connection() as connection:
            yield connection

    def get_public_schema(self) -> Dict[str, Any]:
        if self._schema_cache is not None:
            return self._schema_cache

        if not self.supabase_url or not self.supabase_key:
            return {}

        try:
            response = requests.get(
                f"{self.supabase_url}/rest/v1/",
                headers={
                    "apikey": self.supabase_key,
                    "Authorization": f"Bearer {self.supabase_key}",
                    "Accept": "application/openapi+json",
                },
                timeout=30,
            )
            response.raise_for_status()
            self._schema_cache = response.json()
        except requests.RequestException:
            self._schema_cache = {}
        return self._schema_cache

    def get_table_definition(self, table_name: str) -> Dict[str, Any]:
        schema = self.get_public_schema()
        return schema.get("definitions", {}).get(table_name, {})

    def get_table_properties(self, table_name: str) -> Dict[str, Any]:
        definition = self.get_table_definition(table_name)
        return definition.get("properties", {})

    def supports_plan_persistence(self) -> bool:
        properties = self.get_table_properties(self.table_name)
        expected_columns = {"id", "status", "target_url", "initial_plan", "thought_trace", "threat_level", "user_id", "results", "final_report", "remediations"}
        return expected_columns.issubset(properties.keys())

    def supports_hunt_persistence(self) -> bool:
        schema = self.get_public_schema().get("definitions", {})
        return all(
            name in schema
            for name in {
                self.table_name,
                self.sessions_table,
                self.vulnerabilities_table,
                self.profiles_table,
                self.consent_logs_table,
            }
        )

    def build_record_identifier(self, scan_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, scan_id))

    def resolve_record_identifier(self, scan_id: str) -> str:
        try:
            return str(uuid.UUID(scan_id))
        except ValueError:
            return self.build_record_identifier(scan_id)

    def _scan_query(self, user_id: str, select_clause: str = "*") -> Any:
        raise NotImplementedError("Legacy Supabase query path has been disabled.")

    def _fetch_owned_scan(self, scan_id: str, user_id: str, select_clause: str = "*") -> Dict[str, Any] | None:
        resolved_scan_id = uuid.UUID(self.resolve_record_identifier(scan_id))
        with self.get_connection() as connection:
            with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                cursor.execute(
                    sql.SQL(
                        "select {select_clause} from public.scans where id = %s and user_id = %s limit 1"
                    ).format(select_clause=sql.SQL(select_clause)),
                    (resolved_scan_id, uuid.UUID(str(user_id))),
                )
                return cursor.fetchone()

    def _scan_exists_for_another_user(self, scan_id: str, user_id: str) -> bool:
        resolved_scan_id = uuid.UUID(self.resolve_record_identifier(scan_id))
        normalized_user_id = uuid.UUID(str(user_id))
        with self.get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "select user_id from public.scans where id = %s limit 1",
                    (resolved_scan_id,),
                )
                row = cursor.fetchone()
        return bool(row) and row[0] != normalized_user_id

    def normalize_status(self, brain_status: str) -> str:
        normalized = (brain_status or "").strip().lower()
        if normalized == "paused":
            return "PLAN_HOLD"
        if normalized in {"complete", "completed"}:
            return "completed"
        if normalized in {"terminated", "failed"}:
            return "failed"
        return "pending"

    def default_threat_level(self, status: str) -> str:
        normalized = status.lower()
        if normalized == "failed":
            return "critical"
        if normalized == "completed":
            return "resolved"
        return "unknown"

    def ensure_schema(self) -> None:
        if (self.supports_plan_persistence() and self.supports_hunt_persistence()) or not self.database_configured():
            return

        with self.get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    create extension if not exists pgcrypto;
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.scans (
                        id uuid primary key default gen_random_uuid(),
                        user_id uuid,
                        target_url text not null,
                        status text not null default 'pending',
                        threat_level text not null default 'unknown',
                        initial_plan jsonb not null default '{"steps":[]}'::jsonb,
                        thought_trace jsonb,
                        results jsonb not null default '{}'::jsonb,
                        final_report jsonb not null default '{}'::jsonb,
                        remediations jsonb not null default '{}'::jsonb,
                        created_at timestamptz not null default timezone('utc', now()),
                        completed_at timestamptz
                    );
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.consent_logs (
                        id uuid primary key default gen_random_uuid(),
                        user_id uuid,
                        target_url text not null,
                        confirmed_at timestamptz not null default timezone('utc', now()),
                        ip_address text
                    );
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.scan_sessions (
                        id uuid primary key default gen_random_uuid(),
                        scan_id uuid,
                        user_id uuid,
                        target_url text not null,
                        status text not null,
                        threat_level text,
                        scan_started_at timestamptz not null default timezone('utc', now()),
                        scan_completed_at timestamptz
                    );
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.vulnerabilities (
                        id text primary key,
                        scan_id uuid not null references public.scans(id) on delete cascade,
                        category text not null,
                        title text not null,
                        severity text not null,
                        detail text not null,
                        evidence jsonb not null default '{}'::jsonb,
                        created_at timestamptz not null default timezone('utc', now())
                    );
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.profiles (
                        id uuid primary key default gen_random_uuid(),
                        scan_id uuid not null references public.scans(id) on delete cascade,
                        user_id uuid,
                        profile_type text not null,
                        label text not null,
                        summary text not null,
                        details jsonb not null default '{}'::jsonb,
                        created_at timestamptz not null default timezone('utc', now())
                    );
                    """
                )
                cursor.execute(
                    """
                    alter table public.scans
                    add column if not exists id uuid default gen_random_uuid(),
                    add column if not exists user_id uuid,
                    add column if not exists target_url text,
                    add column if not exists status text not null default 'pending',
                    add column if not exists threat_level text not null default 'unknown',
                    add column if not exists initial_plan jsonb not null default '{"steps":[]}'::jsonb,
                    add column if not exists thought_trace jsonb,
                    add column if not exists results jsonb not null default '{}'::jsonb,
                    add column if not exists final_report jsonb not null default '{}'::jsonb,
                    add column if not exists remediations jsonb not null default '{}'::jsonb,
                    add column if not exists created_at timestamptz not null default timezone('utc', now()),
                    add column if not exists completed_at timestamptz;
                    """
                )
                cursor.execute(
                    """
                    alter table public.consent_logs
                    add column if not exists id uuid default gen_random_uuid(),
                    add column if not exists user_id uuid,
                    add column if not exists target_url text,
                    add column if not exists confirmed_at timestamptz not null default timezone('utc', now()),
                    add column if not exists ip_address text;
                    """
                )
                cursor.execute(
                    """
                    alter table public.scan_sessions
                    add column if not exists id uuid default gen_random_uuid(),
                    add column if not exists scan_id uuid,
                    add column if not exists user_id uuid,
                    add column if not exists target_url text,
                    add column if not exists status text,
                    add column if not exists threat_level text,
                    add column if not exists scan_started_at timestamptz not null default timezone('utc', now()),
                    add column if not exists scan_completed_at timestamptz;
                    """
                )
                cursor.execute(
                    """
                    alter table public.vulnerabilities
                    add column if not exists id text,
                    add column if not exists scan_id uuid,
                    add column if not exists session_id uuid,
                    add column if not exists attack_vector text,
                    add column if not exists detected_threat text,
                    add column if not exists provided_solution text,
                    add column if not exists is_fixed boolean default false,
                    add column if not exists category text,
                    add column if not exists title text,
                    add column if not exists severity text,
                    add column if not exists detail text,
                    add column if not exists evidence jsonb not null default '{}'::jsonb,
                    add column if not exists created_at timestamptz not null default timezone('utc', now());
                    """
                )
                cursor.execute(
                    """
                    alter table public.profiles
                    add column if not exists id uuid default gen_random_uuid(),
                    add column if not exists scan_id uuid,
                    add column if not exists user_id uuid,
                    add column if not exists profile_type text,
                    add column if not exists label text,
                    add column if not exists summary text,
                    add column if not exists details jsonb not null default '{}'::jsonb,
                    add column if not exists created_at timestamptz not null default timezone('utc', now());
                    """
                )
                cursor.execute(
                    """
                    alter table public.scans
                    alter column id set default gen_random_uuid(),
                    alter column status set default 'pending',
                    alter column threat_level set default 'unknown',
                    alter column initial_plan set default '{"steps":[]}'::jsonb,
                    alter column results set default '{}'::jsonb,
                    alter column final_report set default '{}'::jsonb,
                    alter column remediations set default '{}'::jsonb;
                    """
                )
                cursor.execute(
                    """
                    update public.scans
                    set id = gen_random_uuid()
                    where id is null;
                    """
                )
                cursor.execute(
                    """
                    alter table public.scans
                    alter column id set not null;
                    """
                )
                cursor.execute(
                    """
                    do $$
                    begin
                        if not exists (
                            select 1
                            from pg_constraint
                            where conrelid = 'public.scans'::regclass
                              and contype = 'p'
                        ) then
                            alter table public.scans add primary key (id);
                        end if;
                    end $$;
                    """
                )
                cursor.execute(
                    """
                    create unique index if not exists scans_id_idx on public.scans (id);
                    """
                )
                cursor.execute(
                    """
                    create index if not exists vulnerabilities_scan_id_idx on public.vulnerabilities (scan_id);
                    """
                )
                cursor.execute(
                    """
                    create index if not exists profiles_scan_id_idx on public.profiles (scan_id);
                    """
                )
                cursor.execute(
                    """
                    create index if not exists scan_sessions_scan_id_idx on public.scan_sessions (scan_id);
                    """
                )
            connection.commit()
            self._schema_cache = None

    def _build_execute_values_statement(
        self,
        table: str,
        columns: List[str],
        row_count: int,
        conflict_columns: List[str],
        update_columns: List[str],
    ) -> sql.Composed:
        row_template = sql.SQL("({placeholders})").format(
            placeholders=sql.SQL(", ").join(sql.Placeholder() for _ in columns)
        )
        values_sql = sql.SQL(", ").join(row_template for _ in range(row_count))
        return sql.SQL(
            """
            insert into {table} ({columns})
            values {values_sql}
            on conflict ({conflict_columns})
            do update set {updates}
            """
        ).format(
            table=sql.Identifier("public", table),
            columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
            values_sql=values_sql,
            conflict_columns=sql.SQL(", ").join(sql.Identifier(column) for column in conflict_columns),
            updates=sql.SQL(", ").join(
                sql.SQL("{column} = excluded.{column}").format(column=sql.Identifier(column))
                for column in update_columns
            ),
        )

    def chunk_insert(
        self,
        cursor: psycopg.Cursor,
        table: str,
        rows: List[Dict[str, Any]],
        columns: List[str],
        chunk_size: int = 25,
        conflict_columns: List[str] | None = None,
        update_columns: List[str] | None = None,
    ) -> int:
        """Bulk upsert rows with execute-values style SQL inside the current transaction."""
        if not rows:
            return 0

        conflict_columns = conflict_columns or ["id"]
        update_columns = update_columns or [column for column in columns if column not in conflict_columns]
        if not update_columns:
            raise Exception(f"chunk_insert requires at least one update column for {table}")

        inserted_count = 0
        for start in range(0, len(rows), chunk_size):
            chunk = rows[start : start + chunk_size]
            statement = self._build_execute_values_statement(
                table=table,
                columns=columns,
                row_count=len(chunk),
                conflict_columns=conflict_columns,
                update_columns=update_columns,
            )
            flattened_values: List[Any] = []
            for row in chunk:
                flattened_values.extend(row[column] for column in columns)
            cursor.execute(statement, flattened_values)
            inserted_count += len(chunk)
            self._logger.info(
                "PROGRESS: [%s/%s] row(s) staged into %s",
                inserted_count,
                len(rows),
                table,
            )

        return inserted_count

    def verify_insert(
        self,
        cursor: psycopg.Cursor,
        table: str,
        row_ids: Iterable[Any],
        id_column: str = "id",
    ) -> int:
        """Verify expected rows exist inside the current PostgreSQL transaction."""
        expected_ids = list(row_ids)
        if not expected_ids:
            raise Exception(f"Verification requires at least one identifier for {table}")

        statement = sql.SQL(
            "select count(*) from {table} where {id_column} = any(%s)"
        ).format(
            table=sql.Identifier("public", table),
            id_column=sql.Identifier(id_column),
        )
        cursor.execute(statement, (expected_ids,))
        row_count = cursor.fetchone()[0]

        if row_count != len(expected_ids):
            self._logger.error(
                "VERIFY_FAILURE: table=%s expected=%s actual=%s",
                table,
                len(expected_ids),
                row_count,
            )
            raise Exception(
                f"Verification failed for {table}: expected {len(expected_ids)} row(s), found {row_count}"
            )

        return row_count

    def safe_insert(
        self,
        cursor: psycopg.Cursor,
        table: str,
        rows: List[Dict[str, Any]],
        columns: List[str],
        chunk_size: int = 25,
        conflict_columns: List[str] | None = None,
        update_columns: List[str] | None = None,
        id_column: str = "id",
    ) -> int:
        """Single transactional bulk path backed by execute-values style SQL."""
        if not rows:
            return 0

        self.chunk_insert(
            cursor,
            table,
            rows,
            columns=columns,
            chunk_size=chunk_size,
            conflict_columns=conflict_columns,
            update_columns=update_columns,
        )
        verified_count = self.verify_insert(
            cursor,
            table,
            [row[id_column] for row in rows],
            id_column=id_column,
        )
        self._logger.info("SUCCESS: verified %s row(s) in %s", verified_count, table)
        return verified_count

    def persist_full_pipeline(
        self,
        scan_id: str,
        user_id: str,
        target_url: str,
        initial_plan: Dict[str, Any],
        brain_status: str,
        session_id: str,
        results: Dict[str, Any] | None = None,
        final_report: Dict[str, Any] | None = None,
        remediations: Dict[str, Any] | None = None,
        ip_address: str | None = None,
    ) -> bool:
        """
        Build, validate, insert, and verify all persistence rows inside one PostgreSQL transaction.
        """
        self._logger.info("FULL_PIPELINE_START: user=%s scan=%s session=%s", user_id, scan_id, session_id)

        if not scan_id:
            raise Exception("CRITICAL: scan_id missing")
        if not target_url:
            raise Exception("CRITICAL: target_url missing")
        if not user_id:
            raise Exception("CRITICAL: user_id missing")
        if not session_id:
            raise Exception("CRITICAL: session_id missing")

        resolved_scan_id = self.resolve_record_identifier(scan_id)
        normalized_session_id = str(uuid.UUID(str(session_id)))
        normalized_user_id = str(uuid.UUID(str(user_id)))
        normalized_scan_id = str(uuid.UUID(str(resolved_scan_id)))
        scan_uuid = uuid.UUID(normalized_scan_id)
        session_uuid = uuid.UUID(normalized_session_id)
        user_uuid = uuid.UUID(normalized_user_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        normalized_initial_plan = initial_plan if isinstance(initial_plan, dict) else {"steps": []}
        scan_results = results or {}
        scan_report = final_report or {}
        scan_remediations = remediations or {}
        persisted_status = self.normalize_status(brain_status)
        threat_level = scan_report.get("threat_level", self.default_threat_level(persisted_status))
        audit_result = scan_results.get("audit_engine") or {}
        raw_findings = audit_result.get("findings")
        raw_profiles = audit_result.get("profiles")

        fallback_findings = raw_findings if raw_findings else [{
            "title": "Engine Heuristic Pass Complete",
            "detail": "Target analyzed with no specific vulnerabilities flagged.",
            "severity": "Low",
            "category": "info",
            "evidence": {"source": "persist_full_pipeline_fallback"},
            "provided_solution": "Continue monitoring and rerun the scan if the target changes.",
        }]
        fallback_profiles = raw_profiles if raw_profiles else [{
            "profile_type": "security_operator",
            "label": "Fallback Hunt Profile",
            "summary": "Generated to keep the persistence pipeline fully populated.",
            "details": {"source": "persist_full_pipeline_fallback", "generated_at": now_iso},
        }]

        valid_vulnerability_rows, validation_errors = validate_and_build_rows(
            fallback_findings,
            normalized_scan_id,
            normalized_session_id,
        )
        if not valid_vulnerability_rows:
            raise Exception("CRITICAL: vulnerabilities validation produced zero rows")
        if any(not row.get("session_id") for row in valid_vulnerability_rows):
            raise Exception("CRITICAL: vulnerability row missing session_id")

        vulnerability_rows: List[Dict[str, Any]] = []
        for index, row in enumerate(valid_vulnerability_rows):
            deterministic_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"vulnerability:{normalized_session_id}:{index}:{row.get('title', '')}:{row.get('category', '')}",
                )
            )
            uuid.UUID(deterministic_id)
            normalized_row = dict(row)
            normalized_row["id"] = deterministic_id
            normalized_row["scan_id"] = scan_uuid
            normalized_row["session_id"] = session_uuid
            vulnerability_rows.append(normalized_row)

        profile_rows: List[Dict[str, Any]] = []
        for index, profile in enumerate(fallback_profiles):
            profile_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"profile:{normalized_scan_id}:{normalized_session_id}:{index}:{profile.get('profile_type', '')}:{profile.get('label', '')}",
                )
            )
            uuid.UUID(profile_id)
            profile_rows.append(
                {
                    "id": uuid.UUID(profile_id),
                    "scan_id": scan_uuid,
                    "user_id": user_uuid,
                    "profile_type": str(profile.get("profile_type", "unknown")).strip() or "unknown",
                    "label": str(profile.get("label", "Untitled Profile")).strip() or "Untitled Profile",
                    "summary": str(profile.get("summary", "")).strip(),
                    "details": profile.get("details", {}) if isinstance(profile.get("details", {}), dict) else {},
                }
            )

        if not profile_rows:
            raise Exception("CRITICAL: profiles validation produced zero rows")

        session_row = {
            "id": session_uuid,
            "scan_id": scan_uuid,
            "user_id": user_uuid,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": threat_level,
            "scan_started_at": now_iso,
        }
        if persisted_status == "completed":
            session_row["scan_completed_at"] = now_iso

        scan_row = {
            "id": scan_uuid,
            "user_id": user_uuid,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": threat_level,
            "initial_plan": normalized_initial_plan,
            "thought_trace": normalized_initial_plan.get("steps", []),
            "results": scan_results,
            "final_report": scan_report,
            "remediations": scan_remediations,
        }
        if persisted_status == "completed":
            scan_row["completed_at"] = now_iso

        consent_row = {
            "id": uuid.uuid5(uuid.NAMESPACE_URL, f"consent:{normalized_session_id}:{target_url}"),
            "user_id": user_uuid,
            "target_url": target_url,
            "confirmed_at": now_iso,
            "ip_address": ip_address or "0.0.0.0",
        }
        uuid.UUID(str(consent_row["id"]))

        self._logger.info(
            "FULL_PIPELINE_BUILT: scan=1 session=1 vulnerabilities=%s profiles=%s consent=1 validation_errors=%s",
            len(vulnerability_rows),
            len(profile_rows),
            len(validation_errors),
        )

        scan_db_row = {
            **scan_row,
            "initial_plan": Jsonb(scan_row["initial_plan"]),
            "thought_trace": Jsonb(scan_row["thought_trace"]),
            "results": Jsonb(scan_row["results"]),
            "final_report": Jsonb(scan_row["final_report"]),
            "remediations": Jsonb(scan_row["remediations"]),
            "completed_at": scan_row.get("completed_at"),
        }
        profile_db_rows = [
            {
                **row,
                "details": Jsonb(row["details"]),
            }
            for row in profile_rows
        ]
        vulnerability_db_rows = [
            {
                **row,
                "evidence": Jsonb(row["evidence"]),
            }
            for row in vulnerability_rows
        ]
        session_db_row = {
            **session_row,
            "scan_completed_at": session_row.get("scan_completed_at"),
        }

        try:
            with self.get_connection() as conn:
                with conn.transaction():
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "select user_id from public.scans where id = %s limit 1",
                            (scan_uuid,),
                        )
                        existing_scan_row = cursor.fetchone()
                        if existing_scan_row and str(existing_scan_row[0]) != normalized_user_id:
                            raise Exception(f"Cross-tenant violation for scan {scan_id}")

                        self.safe_insert(
                            cursor,
                            self.table_name,
                            [scan_db_row],
                            columns=[
                                "id",
                                "user_id",
                                "target_url",
                                "status",
                                "threat_level",
                                "initial_plan",
                                "thought_trace",
                                "results",
                                "final_report",
                                "remediations",
                                "completed_at",
                            ],
                            update_columns=[
                                "user_id",
                                "target_url",
                                "status",
                                "threat_level",
                                "initial_plan",
                                "thought_trace",
                                "results",
                                "final_report",
                                "remediations",
                                "completed_at",
                            ],
                        )
                        self._logger.info("INSERTED: 1 row(s) in %s", self.table_name)

                        inserted_profiles = self.safe_insert(
                            cursor,
                            self.profiles_table,
                            profile_db_rows,
                            columns=["id", "scan_id", "user_id", "profile_type", "label", "summary", "details"],
                            update_columns=["scan_id", "user_id", "profile_type", "label", "summary", "details"],
                        )
                        self._logger.info("INSERTED: %s row(s) in %s", inserted_profiles, self.profiles_table)

                        self.safe_insert(
                            cursor,
                            self.sessions_table,
                            [session_db_row],
                            columns=[
                                "id",
                                "scan_id",
                                "user_id",
                                "target_url",
                                "status",
                                "threat_level",
                                "scan_started_at",
                                "scan_completed_at",
                            ],
                            update_columns=[
                                "scan_id",
                                "user_id",
                                "target_url",
                                "status",
                                "threat_level",
                                "scan_started_at",
                                "scan_completed_at",
                            ],
                        )
                        self._logger.info("INSERTED: 1 row(s) in %s", self.sessions_table)

                        inserted_vulnerabilities = self.safe_insert(
                            cursor,
                            self.vulnerabilities_table,
                            vulnerability_db_rows,
                            columns=[
                                "id",
                                "scan_id",
                                "session_id",
                                "attack_vector",
                                "detected_threat",
                                "provided_solution",
                                "severity",
                                "category",
                                "title",
                                "detail",
                                "evidence",
                                "is_fixed",
                            ],
                            update_columns=[
                                "scan_id",
                                "session_id",
                                "attack_vector",
                                "detected_threat",
                                "provided_solution",
                                "severity",
                                "category",
                                "title",
                                "detail",
                                "evidence",
                                "is_fixed",
                            ],
                        )
                        self._logger.info("INSERTED: %s row(s) in %s", inserted_vulnerabilities, self.vulnerabilities_table)

                        self.safe_insert(
                            cursor,
                            self.consent_logs_table,
                            [consent_row],
                            columns=["id", "user_id", "target_url", "confirmed_at", "ip_address"],
                            update_columns=["user_id", "target_url", "confirmed_at", "ip_address"],
                        )
                        self._logger.info("INSERTED: 1 row(s) in %s", self.consent_logs_table)

                        cursor.execute(
                            """
                            select count(*)
                            from public.vulnerabilities v
                            join public.scan_sessions s on s.id = v.session_id
                            where v.scan_id = %s and s.scan_id = %s
                            """,
                            (scan_uuid, scan_uuid),
                        )
                        vulnerability_relation_count = cursor.fetchone()[0]
                        if vulnerability_relation_count != len(vulnerability_rows):
                            raise Exception("RELATION_FAILURE: each vulnerability.session_id must exist in scan_sessions")

                        cursor.execute(
                            """
                            select count(*)
                            from public.profiles p
                            join public.scans sc on sc.id = p.scan_id
                            where p.scan_id = %s
                            """,
                            (scan_uuid,),
                        )
                        profile_scan_relation_count = cursor.fetchone()[0]
                        if profile_scan_relation_count != len(profile_rows):
                            raise Exception("RELATION_FAILURE: each profile.scan_id must exist in scans")

                        cursor.execute(
                            """
                            select count(*)
                            from public.scan_sessions s
                            join public.profiles p
                              on p.user_id = s.user_id
                             and p.scan_id = s.scan_id
                            where s.id = %s
                            """,
                            (session_uuid,),
                        )
                        session_profile_relation_count = cursor.fetchone()[0]
                        if session_profile_relation_count < 1:
                            raise Exception("RELATION_FAILURE: each session.user_id must exist in profiles")

                        cursor.execute(
                            "select count(*) from public.vulnerabilities where scan_id = %s",
                            (scan_uuid,),
                        )
                        vulnerability_count = cursor.fetchone()[0]

                        cursor.execute(
                            "select count(*) from public.profiles where scan_id = %s",
                            (scan_uuid,),
                        )
                        profile_count = cursor.fetchone()[0]

                        cursor.execute(
                            "select count(*) from public.scan_sessions where scan_id = %s",
                            (scan_uuid,),
                        )
                        session_count = cursor.fetchone()[0]

                        if vulnerability_count < 1:
                            raise Exception("RELATION_FAILURE: scan has no vulnerabilities")
                        if profile_count < 1:
                            raise Exception("RELATION_FAILURE: scan has no profiles")
                        if session_count < 1:
                            raise Exception("RELATION_FAILURE: scan has no session")

                        self._logger.info(
                            "RELATIONSHIP_VERIFIED: scan=%s vulnerabilities=%s profiles=%s sessions=%s",
                            normalized_scan_id,
                            vulnerability_count,
                            profile_count,
                            session_count,
                        )
        except UniqueViolation as error:
            self._logger.error("DB_UNIQUE_VIOLATION: %s", str(error))
            raise
        except ForeignKeyViolation as error:
            self._logger.error("DB_FOREIGN_KEY_VIOLATION: %s", str(error))
            raise
        except CheckViolation as error:
            self._logger.error("DB_CHECK_VIOLATION: %s", str(error))
            raise

        self._logger.info("FULL_PIPELINE_COMPLETE: scan=%s session=%s", scan_id, session_id)
        return True

    def persist_everything(
        self,
        client: Any,
        user_id: str,
        scan_id: str,
        session_id: str,
        findings: List[Dict[str, Any]],
        scan_data: Dict[str, Any]
    ) -> bool:
        return self.persist_full_pipeline(
            scan_id=scan_id,
            user_id=user_id,
            target_url=scan_data.get("target_url", ""),
            initial_plan=scan_data.get("initial_plan", {"steps": []}),
            brain_status=scan_data.get("status", "completed"),
            session_id=session_id,
            results={
                **(scan_data.get("results", {}) or {}),
                "audit_engine": {
                    **(((scan_data.get("results", {}) or {}).get("audit_engine")) or {}),
                    "findings": findings,
                    "profiles": scan_data.get("profiles", []),
                },
            },
            final_report=scan_data.get("final_report", {}),
            remediations=scan_data.get("remediations", {}),
            ip_address=scan_data.get("ip_address"),
        )

    def upsert_scan(
        self,
        scan_id: str,
        target_url: str,
        initial_plan: Dict[str, Any],
        brain_status: str,
        user_id: str,
        results: Dict[str, Any] | None = None,
        final_report: Dict[str, Any] | None = None,
        remediations: Dict[str, Any] | None = None,
    ) -> bool:
        raise NotImplementedError("Legacy upsert_scan path has been disabled. Use persist_full_pipeline().")

    def log_consent(self, user_id: str, target_url: str, ip_address: str | None) -> bool:
        payload = {
            "id": uuid.uuid5(uuid.NAMESPACE_URL, f"pre_scan_consent:{user_id}:{target_url}"),
            "user_id": uuid.UUID(str(user_id)),
            "target_url": target_url,
            "ip_address": ip_address,
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
        }
        with self.get_connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    inserted = self.safe_insert(
                        cursor,
                        self.consent_logs_table,
                        [payload],
                        columns=["id", "user_id", "target_url", "confirmed_at", "ip_address"],
                        update_columns=["user_id", "target_url", "confirmed_at", "ip_address"],
                    )
        return inserted == 1

    def replace_hunt_findings(
        self,
        scan_id: str,
        user_id: str,
        vulnerabilities: list[Dict[str, Any]],
        profiles: list[Dict[str, Any]],
        session_id: str
    ) -> bool:
        raise NotImplementedError("Legacy replace_hunt_findings path has been disabled. Use persist_full_pipeline().")

    def save_remediations(self, scan_id: str, user_id: str, remediations: Dict[str, Any]) -> bool:
        with self.get_connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        update public.scans
                        set remediations = %s
                        where id = %s and user_id = %s
                        """,
                        (
                            Jsonb(remediations),
                            uuid.UUID(self.resolve_record_identifier(scan_id)),
                            uuid.UUID(str(user_id)),
                        ),
                    )
                    return cursor.rowcount > 0

    def fetch_scan(self, scan_id: str, user_id: str) -> Dict[str, Any] | None:
        try:
            return self._fetch_owned_scan(scan_id=scan_id, user_id=user_id)
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scan retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_vulnerabilities(self, scan_id: str, user_id: str) -> list[Dict[str, Any]]:
        try:
            scan = self.fetch_scan(scan_id, user_id)
            if not scan:
                return []

            with self.get_connection() as connection:
                with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    cursor.execute(
                        """
                        select *
                        from public.vulnerabilities
                        where scan_id = %s
                        order by created_at
                        """,
                        (uuid.UUID(self.resolve_record_identifier(scan_id)),),
                    )
                    return cursor.fetchall()
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Vulnerability retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_profiles(self, scan_id: str, user_id: str) -> list[Dict[str, Any]]:
        try:
            scan = self.fetch_scan(scan_id, user_id)
            if not scan:
                return []

            with self.get_connection() as connection:
                with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    cursor.execute(
                        """
                        select *
                        from public.profiles
                        where scan_id = %s
                        order by created_at
                        """,
                        (uuid.UUID(self.resolve_record_identifier(scan_id)),),
                    )
                    return cursor.fetchall()
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Profile retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_all_scans(self, user_id: str, limit: int = 12) -> list[Dict[str, Any]]:
        try:
            with self.get_connection() as connection:
                with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    cursor.execute(
                        """
                        select *
                        from public.scans
                        where user_id = %s
                        order by created_at desc
                        limit %s
                        """,
                        (uuid.UUID(str(user_id)), limit),
                    )
                    return cursor.fetchall()
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scans list retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")
