import os
import re
from typing import Any, Dict, List

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
        self.session_table_name = "scan_sessions"
        self._client: Client | None = None
        self._schema_cache: Dict[str, Any] | None = None

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

    def supports_plan_persistence(self) -> bool:
        definition = self.get_table_definition(self.table_name)
        properties = definition.get("properties", {})
        return {"scan_id", "target_url", "initial_plan"}.issubset(properties.keys())

    def supports_session_persistence(self) -> bool:
        definition = self.get_table_definition(self.session_table_name)
        properties = definition.get("properties", {})
        return {"user_id", "target_url", "status"}.issubset(properties.keys())

    def ensure_schema(self) -> None:
        if not self.database_configured():
            return

        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    create table if not exists public.scans (
                        scan_id text primary key,
                        target_url text not null,
                        initial_plan jsonb not null default '[]'::jsonb,
                        brain_status text not null default 'running',
                        created_at timestamptz not null default timezone('utc', now()),
                        updated_at timestamptz not null default timezone('utc', now())
                    );
                    """
                )
                cursor.execute(
                    """
                    alter table public.scans
                    add column if not exists target_url text,
                    add column if not exists initial_plan jsonb not null default '[]'::jsonb,
                    add column if not exists brain_status text not null default 'running',
                    add column if not exists created_at timestamptz not null default timezone('utc', now()),
                    add column if not exists updated_at timestamptz not null default timezone('utc', now());
                    """
                )
                cursor.execute(
                    """
                    create unique index if not exists scans_scan_id_idx on public.scans (scan_id);
                    """
                )
            connection.commit()

    def upsert_scan(
        self,
        scan_id: str,
        target_url: str,
        initial_plan: List[Dict[str, Any]],
        brain_status: str,
        user_id: str | None = None,
    ) -> bool:
        client = self.get_client()
        if client is None:
            return False

        if self.supports_plan_persistence():
            payload = {
                "scan_id": scan_id,
                "target_url": target_url,
                "initial_plan": initial_plan,
                "brain_status": brain_status,
            }
            client.table(self.table_name).upsert(payload, on_conflict="scan_id").execute()
            return True

        if self.supports_session_persistence() and user_id:
            payload = {
                "user_id": user_id,
                "target_url": target_url,
                "status": brain_status,
            }
            client.table(self.session_table_name).insert(payload).execute()
            return True

        return False

    def fetch_scan(self, scan_id: str) -> Dict[str, Any] | None:
        client = self.get_client()
        if client is None or not self.supports_plan_persistence():
            return None

        response = client.table(self.table_name).select("*").eq("scan_id", scan_id).limit(1).execute()
        data = getattr(response, "data", None) or []
        return data[0] if data else None
