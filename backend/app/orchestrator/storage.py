import os
import re
import uuid
from datetime import datetime, timezone
import logging
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
        self.sessions_table = "scan_sessions"
        self.vulnerabilities_table = "vulnerabilities"
        self.profiles_table = "profiles"
        self.consent_logs_table = "consent_logs"
        self._client: Client | None = None
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

    def _scan_query(self, user_id: str, select_clause: str = "*") -> Any:
        client = self.get_client()
        if client is None:
            return None
        return client.table(self.table_name).select(select_clause).eq("user_id", user_id)

    def _fetch_owned_scan(self, scan_id: str, user_id: str, select_clause: str = "*") -> Dict[str, Any] | None:
        query = self._scan_query(user_id=user_id, select_clause=select_clause)
        if query is None:
            return None

        response = query.eq("id", self.resolve_record_identifier(scan_id)).limit(1).execute()
        data = getattr(response, "data", None) or []
        return data[0] if data else None

    def _scan_exists_for_another_user(self, scan_id: str, user_id: str) -> bool:
        client = self.get_client()
        if client is None:
            return False

        response = (
            client.table(self.table_name)
            .select("id,user_id")
            .eq("id", self.resolve_record_identifier(scan_id))
            .limit(1)
            .execute()
        )
        data = getattr(response, "data", None) or []
        return bool(data) and data[0].get("user_id") != user_id

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
                    create table if not exists public.scan_sessions (
                        id uuid primary key default gen_random_uuid(),
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
                    alter table public.scan_sessions
                    add column if not exists id uuid default gen_random_uuid(),
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
                    add column if not exists id uuid default gen_random_uuid(),
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

    def persist_scan_results(
        self,
        scan_id: str,
        user_id: str,
        target_url: str,
        brain_status: str,
        initial_plan: Dict[str, Any],
        results: Dict[str, Any],
        final_report: Dict[str, Any],
        remediations: Dict[str, Any]
    ) -> bool:
        """Guaranteed multi-table persistence for final scan results."""
        assert scan_id is not None
        assert user_id is not None

        client = self.get_client()
        if client is None:
            raise Exception("Database client initialization failed")

        threat_level = (final_report or {}).get("threat_level", "unknown").lower()
        persisted_status = self.normalize_status(brain_status)
        resolved_scan_id = self.resolve_record_identifier(scan_id)

        # 1. CREATE SCAN SESSION
        session = client.table(self.sessions_table).insert({
            "user_id": user_id,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": threat_level
        }).execute()

        if not session.data:
            raise Exception("Scan session creation failed")

        session_id = session.data[0]["id"]
        print("SESSION:", session_id)

        # 2. UPSERT SCAN RECORD
        scan_payload = {
            "id": resolved_scan_id,
            "user_id": user_id,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": threat_level,
            "initial_plan": initial_plan or {"steps": []},
            "thought_trace": initial_plan.get("steps", []) if isinstance(initial_plan, dict) else [],
            "results": results or {},
            "final_report": final_report or {},
            "remediations": remediations or {},
        }
        if persisted_status == "completed":
            scan_payload["completed_at"] = datetime.now(timezone.utc).isoformat()
        
        scan_res = client.table(self.table_name).upsert(scan_payload, on_conflict="id").execute()
        if not scan_res.data:
            raise Exception(f"Scan upsert failed for ID {scan_id}")

        # 3. EXTRACT ALL FINDINGS (Audit + Header)
        audit_findings = results.get("audit_engine", {}).get("findings", [])
        header_findings = results.get("header_audit", {}).get("findings", [])
        all_findings = audit_findings + header_findings
        print("FINDINGS COUNT:", len(all_findings))

        # 4. INSERT INTO VULNERABILITIES (One row per finding)
        for f in all_findings:
            payload = {
                "session_id": session_id,
                "scan_id": resolved_scan_id,
                "attack_vector": f.get("category", "unknown"),
                "detected_threat": f.get("title", "unknown"),
                "title": f.get("title", "Untitled"),
                "detail": f.get("detail", ""),
                "severity": f.get("severity", "Low").capitalize(),
                "evidence": f.get("evidence", {}),
                "provided_solution": "Refer to remediation steps",
                "category": f.get("category", "general")
            }

            v_res = client.table(self.vulnerabilities_table).insert(payload).execute()
            if not v_res.data:
                raise Exception(f"Failed to insert vulnerability: {payload['title']}")

        # 5. INSERT PROFILES
        profiles_data = results.get("audit_engine", {}).get("profiles", [])
        for p in profiles_data:
            p_res = client.table(self.profiles_table).upsert({
                "scan_id": resolved_scan_id,
                "profile_type": p.get("profile_type"),
                "label": p.get("label"),
                "summary": p.get("summary"),
                "details": p.get("details", {})
            }).execute()

            if not p_res.data:
                raise Exception("Profile insert failed")

        return True

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
        session_id: str | None = None,
    ) -> bool:
        # 1. Mandatory Response Validation
        assert scan_id is not None, "scan_id is required"
        assert user_id is not None, "user_id is required"
        assert isinstance(results or {}, dict), "results must be a dictionary"
        assert isinstance(final_report or {}, dict), "final_report must be a dictionary"

        client = self.get_client()
        if client is None:
            raise Exception("Database client initialization failed")

        if self._scan_exists_for_another_user(scan_id=scan_id, user_id=user_id):
            raise Exception(f"Cross-tenant violation: scan {scan_id} does not belong to {user_id}")

        persisted_status = self.normalize_status(brain_status)
        
        # 2. FULL SCANS TABLE UPSERT PAYLOAD
        scan_payload = {
            "id": self.build_record_identifier(scan_id),
            "user_id": user_id,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": (final_report or {}).get("threat_level", self.default_threat_level(persisted_status)),
            "initial_plan": initial_plan,
            "thought_trace": initial_plan.get("steps", []) if isinstance(initial_plan, dict) else [],
            "results": results or {},
            "final_report": final_report or {},
            "remediations": remediations or {},
        }
        if persisted_status == "completed":
            payload["completed_at"] = datetime.now(timezone.utc).isoformat()
        else:
            scan_payload["completed_at"] = None

        print(f"DEBUG: INSERTING SCAN: {scan_payload['id']} for {target_url}")

        # 3. Strict Upsert with RETURN CHECK
        res = client.table(self.table_name).upsert(scan_payload, on_conflict="id").execute()
        if not res.data:
            raise Exception(f"Scan upsert failed - no data returned for ID {scan_id}")

        # 4. Update Scan Session
        session_payload = {
            "id": session_id or self.resolve_record_identifier(f"sess_{scan_id}"),
            "user_id": user_id,
            "target_url": target_url,
            "status": persisted_status,
            "threat_level": scan_payload["threat_level"],
            "scan_started_at": datetime.now(timezone.utc).isoformat()
        }
        if persisted_status == "completed":
            session_payload["scan_completed_at"] = scan_payload.get("completed_at")
        
        s_res = client.table(self.sessions_table).upsert(session_payload, on_conflict="id").execute()
        if not s_res.data:
             raise Exception(f"Session upsert failed for {session_payload['id']}")

        return True

    def upsert_vulnerabilities(
        self, 
        scan_id: str, 
        user_id: str, 
        findings: list[Dict[str, Any]], 
        session_id: str | None = None
    ) -> bool:
        assert scan_id is not None
        assert isinstance(findings, list)

        client = self.get_client()
        if client is None:
             raise Exception("Database client initialization failed")

        resolved_scan_id = self.resolve_record_identifier(scan_id)
        resolved_session_id = session_id or self.resolve_record_identifier(f"sess_{scan_id}")

        # VULNERABILITIES INSERT LOOP (NO SKIP)
        for v in findings:
            payload = {
                "scan_id": resolved_scan_id,
                "session_id": resolved_session_id,
                "attack_vector": v.get("attack_vector", "unknown"),
                "detected_threat": v.get("detected_threat", v.get("title", "unknown")),
                "title": v.get("title", "Untitled"),
                "detail": v.get("detail", ""),
                "severity": v.get("severity", "Low").capitalize(),
                "evidence": v.get("evidence", {}),
                "provided_solution": v.get("provided_solution", ""),
                "category": v.get("category", "general"),
                "is_fixed": False
            }

            print(f"DEBUG: INSERTING VULN: {payload['title']} [{payload['severity']}]")

            res = client.table(self.vulnerabilities_table).upsert(
                payload, 
                on_conflict="scan_id,title"
            ).execute()

            if not res.data:
                raise Exception(f"Failed inserting vulnerability: {payload['title']}")

        return True

    def merge_profile_details(self, user_id: str, new_details: Dict[str, Any]) -> bool:
        """Upserts profile data using JSONB merge logic."""
        client = self.get_client()
        if client is None: return False

        existing = client.table(self.profiles_table).select("details").eq("user_id", user_id).maybe_single().execute()
        current_details = getattr(existing, "data", {}).get("details", {}) if existing.data else {}
        current_details.update(new_details)

        res = client.table(self.profiles_table).upsert({
            "user_id": user_id,
            "details": current_details
        }, on_conflict="user_id").execute()
        return getattr(res, "data", None) is not None

    def log_consent(self, user_id: str, target_url: str, ip_address: str | None) -> bool:
        client = self.get_client()
        if client is None:
            return False

        payload = {
            "user_id": user_id,
            "target_url": target_url,
            "ip_address": ip_address,
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
        }

        response = client.table(self.consent_logs_table).insert(payload).execute()
        return getattr(response, "data", None) is not None

    def replace_hunt_findings(
        self,
        scan_id: str,
        user_id: str,
        vulnerabilities: list[Dict[str, Any]],
        profiles: list[Dict[str, Any]],
    ) -> bool:
        client = self.get_client()
        if client is None:
            return False

        resolved_scan_id = self.resolve_record_identifier(scan_id)

        scan_check = client.table(self.table_name).select("id").eq("id", resolved_scan_id).eq("user_id", user_id).execute()
        if not getattr(scan_check, "data", None):
            return False

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

    def save_remediations(self, scan_id: str, user_id: str, remediations: Dict[str, Any]) -> bool:
        client = self.get_client()
        if client is None:
            return False

        response = (
            client.table(self.table_name)
            .update({"remediations": remediations})
            .eq("id", self.resolve_record_identifier(scan_id))
            .eq("user_id", user_id)
            .execute()
        )
        return getattr(response, "data", None) is not None

    def fetch_scan(self, scan_id: str, user_id: str) -> Dict[str, Any] | None:
        try:
            return self._fetch_owned_scan(scan_id=scan_id, user_id=user_id)
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scan retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_vulnerabilities(self, scan_id: str, user_id: str) -> list[Dict[str, Any]]:
        client = self.get_client()
        if client is None:
            return []

        try:
            # First verify the scan belongs to the user
            scan = self.fetch_scan(scan_id, user_id)
            if not scan:
                return []

            resolved_scan_id = self.resolve_record_identifier(scan_id)
            response = (
                client.table(self.vulnerabilities_table)
                .select("*")
                .eq("scan_id", resolved_scan_id)
                .order("created_at")
                .execute()
            )
            return getattr(response, "data", None) or []
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Vulnerability retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_profiles(self, scan_id: str, user_id: str) -> list[Dict[str, Any]]:
        client = self.get_client()
        if client is None:
            return []

        try:
            # First verify the scan belongs to the user
            scan = self.fetch_scan(scan_id, user_id)
            if not scan:
                return []

            resolved_scan_id = self.resolve_record_identifier(scan_id)
            response = (
                client.table(self.profiles_table)
                .select("*")
                .eq("scan_id", resolved_scan_id)
                .order("created_at")
                .execute()
            )
            return getattr(response, "data", None) or []
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Profile retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")

    def fetch_all_scans(self, user_id: str, limit: int = 12) -> list[Dict[str, Any]]:
        client = self.get_client()
        if client is None:
            return []

        try:
            response = (
                self._scan_query(user_id=user_id)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            return getattr(response, "data", None) or []
        except Exception as error:
            from fastapi import HTTPException
            self._logger.error("Scans list retrieval failed: %s", str(error))
            raise HTTPException(status_code=500, detail="DATA_RETRIEVAL_FAILURE")
