import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import psycopg
import requests
from supabase import Client, create_client


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
        self.vulnerabilities_table = "vulnerabilities"
        self.profiles_table = "profiles"
        self.consent_logs_table = "consent_logs"
        self._client: Client | None = None
        self._schema_cache: Dict[str, Any] | None = None

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
        return (
            bool(self.supabase_url)
            and bool(self.supabase_key)
            and not self.supabase_url.lower().startswith("your_")
            and not self.supabase_key.lower().startswith("your_")
        )

    def masked_supabase_url(self) -> str:
        return self.mask_value(self.supabase_url)

    def using_service_role_key(self) -> bool:
        service_role_key = self._get_first_env("SUPABASE_SERVICE_ROLE_KEY", "VITE_SUPABASE_SERVICE_ROLE_KEY")
        return bool(service_role_key) and self.supabase_key == service_role_key

    def database_configured(self) -> bool:
        return bool(self.database_url) and not self.database_url.lower().startswith("your_")

    def get_client(self) -> Client | None:
        if not self.configured():
            return None

        if self._client is None:
            self._client = create_client(self.supabase_url, self.supabase_key)

        return self._client

    def get_public_schema(self) -> Dict[str, Any]:
        if self._schema_cache is not None:
            return self._schema_cache

        if not self.configured():
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
        return all(name in schema for name in {self.table_name, self.vulnerabilities_table, self.profiles_table, self.consent_logs_table})

    def build_record_identifier(self, scan_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, scan_id))

    def resolve_record_identifier(self, scan_id: str) -> str:
        try:
            return str(uuid.UUID(scan_id))
        except ValueError:
            return self.build_record_identifier(scan_id)

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

        with psycopg.connect(self.database_url) as connection:
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
                    alter table public.vulnerabilities
                    add column if not exists id text,
                    add column if not exists scan_id uuid,
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
            connection.commit()
            self._schema_cache = None

    def upsert_scan(
        self,
        scan_id: str,
        target_url: str,
        initial_plan: Dict[str, Any],
        brain_status: str,
        results: Dict[str, Any] | None = None,
        final_report: Dict[str, Any] | None = None,
        remediations: Dict[str, Any] | None = None,
        user_id: str | None = None,
    ) -> bool:
        client = self.get_client()
        if client is None:
            return False

        persisted_status = self.normalize_status(brain_status)
        payload = {
            "id": self.build_record_identifier(scan_id),
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": (final_report or {}).get("threat_level", self.default_threat_level(persisted_status)),
            "initial_plan": initial_plan,
            "thought_trace": initial_plan.get("steps", []),
            "results": results or {},
            "final_report": final_report or {},
            "remediations": remediations or {},
        }
        if user_id:
            payload["user_id"] = user_id
        if persisted_status == "completed":
            payload["completed_at"] = datetime.now(timezone.utc).isoformat()

        response = client.table(self.table_name).upsert(payload, on_conflict="id").execute()
        data = getattr(response, "data", None)
        return data is not None

    def log_consent(self, user_id: str | None, target_url: str, ip_address: str | None) -> bool:
        client = self.get_client()
        if client is None:
            return False

        payload = {
            "target_url": target_url,
            "ip_address": ip_address,
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
        }
        if user_id:
            payload["user_id"] = user_id

        response = client.table(self.consent_logs_table).insert(payload).execute()
        return getattr(response, "data", None) is not None

    def replace_hunt_findings(
        self,
        scan_id: str,
        vulnerabilities: list[Dict[str, Any]],
        profiles: list[Dict[str, Any]],
    ) -> bool:
        client = self.get_client()
        if client is None:
            return False

        resolved_scan_id = self.resolve_record_identifier(scan_id)
        client.table(self.vulnerabilities_table).delete().eq("scan_id", resolved_scan_id).execute()
        client.table(self.profiles_table).delete().eq("scan_id", resolved_scan_id).execute()

        success = True

        if vulnerabilities:
            vulnerability_rows = [
                {
                    "id": vulnerability["id"],
                    "scan_id": resolved_scan_id,
                    "category": vulnerability.get("category", "unknown"),
                    "title": vulnerability.get("title", "Untitled Finding"),
                    "severity": vulnerability.get("severity", "unknown"),
                    "detail": vulnerability.get("detail", ""),
                    "evidence": vulnerability.get("evidence", {}),
                }
                for vulnerability in vulnerabilities
            ]
            response = client.table(self.vulnerabilities_table).upsert(vulnerability_rows, on_conflict="id").execute()
            success = success and getattr(response, "data", None) is not None

        if profiles:
            profile_rows = [
                {
                    "scan_id": resolved_scan_id,
                    "profile_type": profile.get("profile_type", "unknown"),
                    "label": profile.get("label", "Untitled Profile"),
                    "summary": profile.get("summary", ""),
                    "details": profile.get("details", {}),
                }
                for profile in profiles
            ]
            response = client.table(self.profiles_table).insert(profile_rows).execute()
            success = success and getattr(response, "data", None) is not None

        return success

    def save_remediations(self, scan_id: str, remediations: Dict[str, Any]) -> bool:
        client = self.get_client()
        if client is None:
            return False

        response = (
            client.table(self.table_name)
            .update({"remediations": remediations})
            .eq("id", self.resolve_record_identifier(scan_id))
            .execute()
        )
        return getattr(response, "data", None) is not None

    def fetch_scan(self, scan_id: str) -> Dict[str, Any] | None:
        client = self.get_client()
        if client is None:
            return None

        response = (
            client.table(self.table_name)
            .select("*")
            .eq("id", self.resolve_record_identifier(scan_id))
            .limit(1)
            .execute()
        )
        data = getattr(response, "data", None) or []
        return data[0] if data else None

    def fetch_vulnerabilities(self, scan_id: str) -> list[Dict[str, Any]]:
        client = self.get_client()
        if client is None:
            return []

        response = (
            client.table(self.vulnerabilities_table)
            .select("*")
            .eq("scan_id", self.resolve_record_identifier(scan_id))
            .order("created_at")
            .execute()
        )
        return getattr(response, "data", None) or []

    def fetch_profiles(self, scan_id: str) -> list[Dict[str, Any]]:
        client = self.get_client()
        if client is None:
            return []

        response = (
            client.table(self.profiles_table)
            .select("*")
            .eq("scan_id", self.resolve_record_identifier(scan_id))
            .order("created_at")
            .execute()
        )
        return getattr(response, "data", None) or []
