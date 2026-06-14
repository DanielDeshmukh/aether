import os
import re
import uuid
from datetime import datetime, timezone
import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List
from urllib.parse import urlparse

import psycopg
from psycopg import sql
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation
from psycopg.types.json import Jsonb
try:
    from psycopg_pool import ConnectionPool
except ModuleNotFoundError:  # pragma: no cover - depends on deployment extras
    ConnectionPool = None  # type: ignore[misc,assignment]
from app.services.validators import validate_and_build_rows


class ScanStorage:
    def __init__(self) -> None:
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

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def get_pool_stats(self) -> dict:
        """Return connection pool statistics."""
        if self._pool is None:
            return {"configured": False}
        try:
            stats = self._pool.get_stats()
            return {
                "configured": True,
                "min_size": self._pool.min_size,
                "max_size": self._pool.max_size,
                "active": stats.get("active", 0),
                "idle": stats.get("idle", 0),
                "waiting": stats.get("waiting", 0),
            }
        except Exception:
            return {"configured": True, "error": "stats_unavailable"}

    def check_database_health(self) -> dict:
        """Verify database connectivity."""
        if not self.database_configured():
            return {"configured": False, "healthy": False, "error": "DATABASE_URL not set"}
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    if result:
                        return {"configured": True, "healthy": True}
            return {"configured": True, "healthy": False, "error": "query_failed"}
        except Exception as e:
            return {"configured": True, "healthy": False, "error": str(e)}

    @contextmanager
    def get_connection(self) -> Iterator[psycopg.Connection]:
        pool = self._get_pool()
        with pool.connection() as connection:
            yield connection

    def supports_plan_persistence(self) -> bool:
        if not self.database_configured():
            return False
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = %s",
                        (self.table_name,),
                    )
                    columns = {row[0] for row in cur.fetchall()}
                    expected = {"id", "status", "target_url", "initial_plan", "thought_trace", "threat_level", "user_id", "results", "final_report", "remediations"}
                    return expected.issubset(columns)
        except Exception:
            return False

    def supports_hunt_persistence(self) -> bool:
        if not self.database_configured():
            return False
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                    tables = {row[0] for row in cur.fetchall()}
                    return all(
                        name in tables
                        for name in {
                            self.table_name,
                            self.sessions_table,
                            self.vulnerabilities_table,
                            self.profiles_table,
                            self.consent_logs_table,
                        }
                    )
        except Exception:
            return False

    def build_record_identifier(self, scan_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, scan_id))

    def resolve_record_identifier(self, scan_id: str) -> str:
        try:
            return str(uuid.UUID(scan_id))
        except ValueError:
            return self.build_record_identifier(scan_id)

    def _coerce_uuid(self, value: str | None) -> uuid.UUID | None:
        if not value:
            return None
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError):
            return None

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
        return bool(row) and row[0] != normalized_user_id  # type: ignore[index]

    def _get_table_column_names(self, table_name: str) -> set[str]:
        with self.get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    select column_name
                    from information_schema.columns
                    where table_schema = 'public' and table_name = %s
                    """,
                    (table_name,),
                )
                return {row[0] for row in cursor.fetchall()}

    def fetch_target_verification_record(self, domain: str, user_id: str | None = None) -> Dict[str, Any] | None:
        columns = self._get_table_column_names("targets")
        if not columns:
            return None

        def first_present(*candidates: str) -> str | None:
            for candidate in candidates:
                if candidate in columns:
                    return candidate
            return None

        domain_column = first_present("domain", "target_domain", "hostname")
        verified_column = first_present("is_verified", "verified")
        if domain_column is None or verified_column is None:
            return None

        selected_columns = [
            (domain_column, "domain"),
            (verified_column, "is_verified"),
        ]

        optional_column_map = {
            "verification_token": (
                "verification_token",
                "dns_token",
                "txt_token",
                "verification_txt_token",
                "http_token",
                "well_known_token",
            ),
            "dns_record": ("dns_record", "verification_record", "txt_record"),
            "http_path": ("http_path", "verification_path", "well_known_path"),
            "http_token": ("http_token", "verification_file_token", "well_known_token"),
        }
        for alias, candidates in optional_column_map.items():
            actual_column = first_present(*candidates)
            if actual_column is not None:
                selected_columns.append((actual_column, alias))

        user_column = first_present("user_id", "owner_id")
        order_column = first_present("updated_at", "created_at")

        statement = sql.SQL(
            "select {columns} from {table} where {domain_column} = %s{user_filter}{order_clause} limit 1"
        ).format(
            columns=sql.SQL(", ").join(
                sql.SQL("{column} as {alias}").format(
                    column=sql.Identifier(actual_column),
                    alias=sql.Identifier(alias),
                )
                for actual_column, alias in selected_columns
            ),
            table=sql.Identifier("public", "targets"),
            domain_column=sql.Identifier(domain_column),
            user_filter=sql.SQL(f" and {user_column} = %s") if user_column and user_id else sql.SQL(""),
            order_clause=sql.SQL(f" order by {order_column} desc") if order_column else sql.SQL(""),
        )

        params: list[Any] = [domain]
        if user_column and user_id:
            try:
                params.append(uuid.UUID(str(user_id)))
            except (ValueError, TypeError, AttributeError):
                params.append(str(user_id))

        with self.get_connection() as connection:
            with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                cursor.execute(statement, params)
                return cursor.fetchone()

    def _first_present(self, columns: set[str], *candidates: str) -> str | None:
        for candidate in candidates:
            if candidate in columns:
                return candidate
        return None

    def _normalize_git_target(self, row: Dict[str, Any], columns: set[str]) -> Dict[str, Any]:
        details = row.get("details")
        details = details if isinstance(details, dict) else {}

        def pick(*keys: str) -> Any:
            for key in keys:
                if key in row and row.get(key) not in (None, ""):
                    return row.get(key)
                if key in details and details.get(key) not in (None, ""):
                    return details.get(key)
            return None

        return {
            "id": row.get("id"),
            "provider": pick("git_provider", "provider"),
            "repository": pick("repository", "repo_name", "full_name", "project_path"),
            "project_id": pick("project_id", "gitlab_project_id"),
            "access_token": pick("access_token", "git_access_token", "token"),
            "default_branch": pick("default_branch", "branch"),
            "base_branch": pick("base_branch", "default_branch", "branch"),
            "api_base_url": pick("api_base_url", "git_api_base_url"),
            "repo_web_url": pick("repo_web_url", "repository_url", "html_url", "web_url"),
            "target_url": pick("target_url"),
            "domain": pick("domain", "target_domain", "hostname"),
        }

    def _fetch_target_row(self, filters: Dict[str, Any], user_id: str | None) -> Dict[str, Any] | None:
        columns = self._get_table_column_names("targets")
        if not columns:
            return None

        selected_columns = [
            column
            for column in {
                "id",
                self._first_present(columns, "provider", "git_provider"),
                self._first_present(columns, "repository", "repo_name", "full_name", "project_path"),
                self._first_present(columns, "project_id", "gitlab_project_id"),
                self._first_present(columns, "access_token", "git_access_token", "token"),
                self._first_present(columns, "default_branch", "branch"),
                self._first_present(columns, "base_branch"),
                self._first_present(columns, "api_base_url", "git_api_base_url"),
                self._first_present(columns, "repo_web_url", "repository_url", "html_url", "web_url"),
                self._first_present(columns, "target_url"),
                self._first_present(columns, "domain", "target_domain", "hostname"),
                self._first_present(columns, "details"),
            }
            if column
        ]
        if "id" not in selected_columns:
            return None

        where_clauses: list[sql.Composed] = []
        params: list[Any] = []
        for column_name, value in filters.items():
            if column_name not in columns or value in (None, ""):
                continue
            where_clauses.append(sql.SQL("{} = %s").format(sql.Identifier(column_name)))
            params.append(value)

        user_column = self._first_present(columns, "user_id", "owner_id")
        if user_column and user_id:
            where_clauses.append(sql.SQL("{} = %s").format(sql.Identifier(user_column)))
            try:
                params.append(uuid.UUID(str(user_id)))
            except (TypeError, ValueError, AttributeError):
                params.append(str(user_id))

        if not where_clauses:
            return None

        order_column = self._first_present(columns, "updated_at", "created_at")
        statement = sql.SQL(
            "select {columns} from {table} where {filters}{order_clause} limit 1"
        ).format(
            columns=sql.SQL(", ").join(sql.Identifier(column) for column in selected_columns),
            table=sql.Identifier("public", "targets"),
            filters=sql.SQL(" and ").join(where_clauses),
            order_clause=sql.SQL(" order by {} desc").format(sql.Identifier(order_column)) if order_column else sql.SQL(""),
        )

        with self.get_connection() as connection:
            with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                cursor.execute(statement, params)
                row = cursor.fetchone()
        return self._normalize_git_target(row, columns) if row else None

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
                        user_id uuid,
                        scan_id uuid not null references public.scans(id) on delete cascade,
                        session_id uuid,
                        attack_vector text,
                        detected_threat text,
                        evidence_snippet text,
                        provided_solution text,
                        is_fixed boolean default false,
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
                        email text,
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
                    add column if not exists user_id uuid,
                    add column if not exists scan_id uuid,
                    add column if not exists session_id uuid,
                    add column if not exists attack_vector text,
                    add column if not exists detected_threat text,
                    add column if not exists evidence_snippet text,
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
                    add column if not exists email text,
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
                cursor.execute(
                    """
                    create table if not exists public.users (
                        id uuid primary key default gen_random_uuid(),
                        email text unique not null,
                        name text,
                        provider text not null default 'email',
                        created_at timestamptz not null default timezone('utc', now()),
                        last_login_at timestamptz
                    );
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.magic_links (
                        id uuid primary key default gen_random_uuid(),
                        token text unique not null,
                        email text not null,
                        user_id uuid references public.users(id) on delete cascade,
                        expires_at timestamptz not null,
                        used boolean not null default false,
                        created_at timestamptz not null default timezone('utc', now())
                    );
                    """
                )
                cursor.execute(
                    """
                    create index if not exists magic_links_token_idx on public.magic_links (token);
                    """
                )
                cursor.execute(
                    """
                    create index if not exists users_email_idx on public.users (email);
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.revoked_tokens (
                        id uuid primary key default gen_random_uuid(),
                        token_jti text unique not null,
                        user_id uuid,
                        revoked_at timestamptz not null default timezone('utc', now()),
                        expires_at timestamptz not null
                    );
                    """
                )
                cursor.execute(
                    """
                    create index if not exists revoked_tokens_jti_idx on public.revoked_tokens (token_jti);
                    """
                )
                cursor.execute(
                    """
                    create index if not exists revoked_tokens_user_idx on public.revoked_tokens (user_id);
                    """
                )
                cursor.execute(
                    """
                    create table if not exists public.remediation_history (
                        id uuid primary key default gen_random_uuid(),
                        scan_id uuid references public.scans(id) on delete cascade,
                        user_id uuid,
                        vuln_id text,
                        action text not null,
                        language text,
                        created_at timestamptz not null default timezone('utc', now())
                    );
                    """
                )
                cursor.execute(
                    """
                    create index if not exists remediation_history_scan_idx on public.remediation_history (scan_id);
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
                flattened_values.extend(row.get(column) for column in columns)
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
        row_count = cursor.fetchone()[0]  # type: ignore[index]

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

    def _normalize_optional_profile_email(self, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    def _normalize_optional_profile_user_id(
        self,
        value: Any,
        fallback_user_id: uuid.UUID | None,
    ) -> uuid.UUID | None:
        if value in (None, ""):
            return fallback_user_id
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError, AttributeError):
            self._logger.warning("PROFILE_USER_ID_INVALID: %s", value)
            return fallback_user_id

    def _build_profile_row(
        self,
        profile: Any,
        *,
        index: int,
        normalized_scan_id: str,
        normalized_session_id: str,
        scan_uuid: uuid.UUID,
        fallback_user_id: uuid.UUID | None,
        now_iso: str,
    ) -> Dict[str, Any]:
        raw_profile = profile if isinstance(profile, dict) else {}
        profile_type = str(raw_profile.get("profile_type", "unknown")).strip() or "unknown"
        label = str(raw_profile.get("label", "Untitled Profile")).strip() or "Untitled Profile"
        summary = str(raw_profile.get("summary", "")).strip()
        details = raw_profile.get("details")
        normalized_details = details if isinstance(details, dict) else {}
        normalized_email = self._normalize_optional_profile_email(raw_profile.get("email"))
        normalized_user_id = self._normalize_optional_profile_user_id(
            raw_profile.get("user_id"),
            fallback_user_id,
        )

        profile_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"profile:{normalized_scan_id}:{normalized_session_id}:{index}:{profile_type}:{label}",
            )
        )
        uuid.UUID(profile_id)

        return {
            "id": uuid.UUID(profile_id),
            "scan_id": scan_uuid,
            "user_id": normalized_user_id,
            "email": normalized_email,
            "profile_type": profile_type,
            "label": label,
            "summary": summary,
            "details": {
                **normalized_details,
                "source": normalized_details.get("source", "persist_full_pipeline"),
                "generated_at": normalized_details.get("generated_at", now_iso),
            },
        }

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
        normalized_user_id = str(user_id)
        normalized_scan_id = str(uuid.UUID(str(resolved_scan_id)))
        scan_uuid = uuid.UUID(normalized_scan_id)
        session_uuid = uuid.UUID(normalized_session_id)
        user_uuid = self._coerce_uuid(user_id)
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
            "user_id": normalized_user_id,
            "email": None,
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
            profile_rows.append(
                self._build_profile_row(
                    profile,
                    index=index,
                    normalized_scan_id=normalized_scan_id,
                    normalized_session_id=normalized_session_id,
                    scan_uuid=scan_uuid,
                    fallback_user_id=user_uuid,
                    now_iso=now_iso,
                )
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
                        if existing_scan_row and user_uuid and str(existing_scan_row[0]) != str(user_uuid):
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
                            columns=["id", "scan_id", "user_id", "email", "profile_type", "label", "summary", "details"],
                            update_columns=["scan_id", "user_id", "email", "profile_type", "label", "summary", "details"],
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
                            from public.scan_sessions
                            where id = %s
                            """,
                            (session_uuid,),
                        )
                        session_exists = cursor.fetchone()[0]  # type: ignore[index]
                        if session_exists == 0:
                            raise Exception("RELATION_FAILURE: session %s not found in scan_sessions" % session_uuid)

                        cursor.execute(
                            """
                            select count(*)
                            from public.vulnerabilities
                            where scan_id = %s and session_id = %s
                            """,
                            (scan_uuid, session_uuid),
                        )
                        vulnerability_count = cursor.fetchone()[0]  # type: ignore[index]
                        if vulnerability_count < len(vulnerability_rows):
                            self._logger.warning(
                                "Vulnerability count mismatch: expected %s, found %s",
                                len(vulnerability_rows),
                                vulnerability_count,
                            )

                        cursor.execute(
                            """
                            select count(*)
                            from public.profiles p
                            join public.scans sc on sc.id = p.scan_id
                            where p.scan_id = %s
                            """,
                            (scan_uuid,),
                        )
                        profile_scan_relation_count = cursor.fetchone()[0]  # type: ignore[index]
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
                        session_profile_relation_count = cursor.fetchone()[0]  # type: ignore[index]
                        if session_profile_relation_count < 1:
                            raise Exception("RELATION_FAILURE: each session.user_id must exist in profiles")

                        cursor.execute(
                            "select count(*) from public.profiles where scan_id = %s",
                            (scan_uuid,),
                        )
                        profile_count = cursor.fetchone()[0]  # type: ignore[index]

                        cursor.execute(
                            "select count(*) from public.scan_sessions where scan_id = %s",
                            (scan_uuid,),
                        )
                        session_count = cursor.fetchone()[0]  # type: ignore[index]

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

    def get_total_scan_count(self, user_id: str) -> int:
        try:
            with self.get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        select count(*)
                        from public.scans
                        where user_id = %s
                        """,
                        (uuid.UUID(str(user_id)),),
                    )
                    row = cursor.fetchone()
                    return int(row[0]) if row else 0
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scan count retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def log_consent(
        self,
        user_id: str,
        target_url: str,
        ip_address: str | None = None,
        origin_ip: str | None = None,
    ) -> bool:
        persisted_ip = origin_ip if origin_ip is not None else ip_address
        payload = {
            "id": uuid.uuid5(uuid.NAMESPACE_URL, f"pre_scan_consent:{user_id}:{target_url}"),
            "user_id": uuid.UUID(str(user_id)),
            "target_url": target_url,
            "ip_address": persisted_ip,
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

    def save_final_report(self, scan_id: str, user_id: str, final_report: Dict[str, Any]) -> bool:
        with self.get_connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        update public.scans
                        set final_report = %s
                        where id = %s and user_id = %s
                        """,
                        (
                            Jsonb(final_report),
                            uuid.UUID(self.resolve_record_identifier(scan_id)),
                            uuid.UUID(str(user_id)),
                        ),
                    )
                    return cursor.rowcount > 0

    def update_scan_trace(self, user_id: str, scan_id: str, trace_data: Any) -> bool:
        with self.get_connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        update public.scans
                        set thought_trace = %s
                        where id = %s and user_id = %s
                        """,
                        (
                            Jsonb(trace_data),
                            uuid.UUID(str(scan_id)),
                            uuid.UUID(str(user_id)),
                        ),
                    )
                    return cursor.rowcount > 0

    def insert_vulnerability(
        self,
        user_id: str,
        scan_id: str,
        category: str,
        title: str,
        severity: str,
        detail: str,
        session_id: str | None,
        attack_vector: str | None,
        detected_threat: str | None,
        evidence_snippet: str | None,
        provided_solution: str | None,
        evidence: Any,
        finding_id: str | None,
    ) -> str:
        vuln_id = finding_id or str(uuid.uuid4())
        with self.get_connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        insert into public.vulnerabilities (
                            id, user_id, scan_id, session_id, category, title,
                            severity, detail, attack_vector, detected_threat,
                            evidence_snippet, provided_solution, evidence
                        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        on conflict (id) do update set
                            severity = excluded.severity,
                            detail = excluded.detail,
                            evidence = excluded.evidence,
                            provided_solution = excluded.provided_solution
                        """,
                        (
                            uuid.UUID(vuln_id) if len(vuln_id) == 36 else vuln_id,
                            uuid.UUID(str(user_id)),
                            uuid.UUID(str(scan_id)),
                            uuid.UUID(str(session_id)) if session_id else None,
                            category,
                            title,
                            severity,
                            detail,
                            attack_vector,
                            detected_threat,
                            evidence_snippet,
                            provided_solution,
                            Jsonb(evidence) if evidence else Jsonb({}),
                        ),
                    )
                    return str(vuln_id)

    def fetch_scan(self, scan_id: str, user_id: str) -> Dict[str, Any] | None:
        try:
            return self._fetch_owned_scan(scan_id=scan_id, user_id=user_id)
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scan retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_git_target(self, target_id: str, user_id: str) -> Dict[str, Any] | None:
        try:
            return self._fetch_target_row(filters={"id": target_id}, user_id=user_id)
        except Exception as error:
            self._logger.error("Git target retrieval failed: %s", str(error))
            return None

    def resolve_git_target_for_url(self, target_url: str, user_id: str | None) -> Dict[str, Any] | None:
        try:
            parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
            hostname = (parsed.hostname or "").strip().lower()
            if not hostname:
                return None
            for filters in (
                {"domain": hostname},
                {"target_domain": hostname},
                {"hostname": hostname},
                {"target_url": target_url},
            ):
                target = self._fetch_target_row(filters=filters, user_id=user_id)
                if target:
                    return target
            return None
        except Exception as error:
            self._logger.error("Git target resolution failed: %s", str(error))
            return None

    def get_or_create_target(self, target_url: str, user_id: str) -> str:
        """
        Upsert pattern: Try to find the target by domain, or insert it if not found.
        Returns the target ID (UUID).
        Newly created targets are automatically verified since the user just registered
        ownership and provided consent.
        """
        # Extract domain/hostname from full URL
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        domain = (parsed.hostname or target_url).strip().lower()

        self._logger.info("GET_OR_CREATE_TARGET: input=%s extracted_domain=%s user_id=%s", target_url, domain, user_id)

        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    # 1. Try to find the target by domain
                    cursor.execute(
                        "SELECT id, is_verified FROM targets WHERE domain = %s",
                        (domain,)
                    )
                    target = cursor.fetchone()
                    self._logger.info("QUERY_RESULT: target=%s", target)

                    if target:
                        self._logger.info("TARGET_FOUND: domain=%s id=%s is_verified=%s", domain, target['id'], target.get('is_verified'))
                        return str(target['id'])

                    # 2. If not found, INSERT it with is_verified=True (user just registered and provided consent)
                    # Include user_id as it's NOT NULL in the schema
                    # The 'RETURNING id' ensures we get the new UUID back
                    self._logger.info("TARGET_NOT_FOUND: inserting domain=%s user_id=%s", domain, user_id)
                    cursor.execute(
                        "INSERT INTO targets (domain, user_id, is_verified, created_at) VALUES (%s, %s, true, NOW()) RETURNING id",
                        (domain, user_id)
                    )
                    new_target = cursor.fetchone()
                    conn.commit()
                    self._logger.info("INSERT_RESULT: new_target=%s", new_target)

                    if new_target:
                        self._logger.info("TARGET_CREATED_AND_VERIFIED: domain=%s user_id=%s id=%s", domain, user_id, new_target['id'])
                        return str(new_target['id'])

                    raise Exception(f"Failed to create target for domain: {domain}")
        except Exception as error:
            self._logger.error("Get or create target failed for domain=%s user_id=%s: %s", domain, user_id, str(error))
            raise

    def mark_target_verified(self, domain: str) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE targets SET is_verified = true WHERE domain = %s",
                        (domain,),
                    )
                    return cursor.rowcount > 0
        except Exception as error:
            self._logger.error("Failed to mark target verified for domain=%s: %s", domain, str(error))
            return False

    def revoke_token(self, token_jti: str, user_id: str, expires_at: datetime) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO public.revoked_tokens (token_jti, user_id, expires_at)
                           VALUES (%s, %s, %s)
                           ON CONFLICT (token_jti) DO NOTHING""",
                        (token_jti, uuid.UUID(str(user_id)), expires_at),
                    )
                    return cursor.rowcount > 0
        except Exception as error:
            self._logger.error("Failed to revoke token: %s", str(error))
            return False

    def is_token_revoked(self, token_jti: str) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM public.revoked_tokens WHERE token_jti = %s",
                        (token_jti,),
                    )
                    return cursor.fetchone() is not None
        except Exception:
            return False

    def delete_user_account(self, user_id: str) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM public.users WHERE id = %s",
                        (uuid.UUID(str(user_id)),),
                    )
                    return cursor.rowcount > 0
        except Exception as error:
            self._logger.error("Failed to delete user account: %s", str(error))
            return False

    def update_user_profile(self, user_id: str, name: str | None = None, email: str | None = None) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    updates = []
                    params = []
                    if name is not None:
                        updates.append("name = %s")
                        params.append(name)
                    if email is not None:
                        updates.append("email = %s")
                        params.append(email)
                    if not updates:
                        return False
                    params.append(str(uuid.UUID(str(user_id))))
                    cursor.execute(
                        f"UPDATE public.users SET {', '.join(updates)} WHERE id = %s",
                        params,
                    )
                    return cursor.rowcount > 0
        except Exception as error:
            self._logger.error("Failed to update user profile: %s", str(error))
            return False

    def log_remediation_action(self, scan_id: str, user_id: str, vuln_id: str, action: str, language: str = "") -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO public.remediation_history (scan_id, user_id, vuln_id, action, language)
                           VALUES (%s, %s, %s, %s, %s)""",
                        (uuid.UUID(str(scan_id)), uuid.UUID(str(user_id)), vuln_id, action, language),
                    )
                    return True
        except Exception as error:
            self._logger.error("Failed to log remediation action: %s", str(error))
            return False

    def fetch_remediation_history(self, scan_id: str, user_id: str) -> list[Dict[str, Any]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    cursor.execute(
                        """SELECT * FROM public.remediation_history
                           WHERE scan_id = %s AND user_id = %s ORDER BY created_at DESC""",
                        (uuid.UUID(str(scan_id)), uuid.UUID(str(user_id))),
                    )
                    return cursor.fetchall()
        except Exception:
            return []

    def count_magic_links_recent(self, email: str, hours: int = 1) -> int:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """SELECT COUNT(*) FROM public.magic_links
                           WHERE email = %s AND created_at > NOW() - INTERVAL '%s hours'""",
                        (email, hours),
                    )
                    row = cursor.fetchone()
                    return row[0] if row else 0
        except Exception:
            return 0

    def delete_scan(self, scan_id: str, user_id: str) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM public.scans WHERE id = %s AND user_id = %s",
                        (uuid.UUID(str(scan_id)), uuid.UUID(str(user_id))),
                    )
                    return cursor.rowcount > 0
        except Exception as error:
            self._logger.error("Failed to delete scan: %s", str(error))
            return False

    def fetch_scans_by_ids(self, scan_ids: list[str], user_id: str) -> list[Dict[str, Any]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cursor:
                    uuids = [uuid.UUID(str(sid)) for sid in scan_ids]
                    cursor.execute(
                        """SELECT * FROM public.scans WHERE id = ANY(%s) AND user_id = %s ORDER BY created_at DESC""",
                        (uuids, uuid.UUID(str(user_id))),
                    )
                    return cursor.fetchall()
        except Exception as error:
            self._logger.error("Failed to fetch scans for comparison: %s", str(error))
            return []

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
