import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

try:
    import dns.resolver as dns_resolver
except ImportError:  # pragma: no cover - resolved when requirements are installed
    dns_resolver = None  # type: ignore[assignment]


logger = logging.getLogger("aether.domain_verification")


class VerificationMethodResult(BaseModel):
    method: str
    success: bool
    expected_location: str
    expected_value: str | None = None
    detail: str


class DomainVerificationResult(BaseModel):
    domain: str
    allowed: bool
    is_verified: bool = False
    record_found: bool = False
    failure_message: str | None = None
    dns: VerificationMethodResult | None = None
    http: VerificationMethodResult | None = None


class DomainVerificationManager:
    def __init__(self, storage: Any) -> None:
        self.storage = storage

    def _extract_domain(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return (parsed.hostname or "").strip().lower()

    def _default_dns_record_name(self, domain: str) -> str:
        return f"_aether-verification.{domain}"

    def _default_http_path(self) -> str:
        return "/.well-known/aether-verification.json"

    def _http_url_for_domain(self, domain: str, path: str) -> str:
        scheme = "http" if domain in {"localhost", "127.0.0.1", "::1"} else "https"
        return f"{scheme}://{domain}{path}"

    async def verify_via_dns(self, domain: str, expected_token: str, record_name: str | None = None) -> VerificationMethodResult:
        target_record = record_name or self._default_dns_record_name(domain)

        def lookup_txt() -> VerificationMethodResult:
            if dns_resolver is None:
                return VerificationMethodResult(
                    method="dns",
                    success=False,
                    expected_location=target_record,
                    expected_value=expected_token,
                    detail="dnspython is not installed, so TXT verification could not run.",
                )
            try:
                answers = dns_resolver.resolve(target_record, "TXT")
            except Exception as error:
                return VerificationMethodResult(
                    method="dns",
                    success=False,
                    expected_location=target_record,
                    expected_value=expected_token,
                    detail=f"Missing TXT record lookup result for {target_record}: {error}",
                )

            txt_values: list[str] = []
            for answer in answers:
                if hasattr(answer, "strings"):
                    txt_values.extend(
                        part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                        for part in answer.strings
                    )
                else:
                    txt_values.append(str(answer).replace('"', ""))
            joined_values = " ".join(value.strip() for value in txt_values if value).strip()
            if expected_token and expected_token in joined_values:
                return VerificationMethodResult(
                    method="dns",
                    success=True,
                    expected_location=target_record,
                    expected_value=expected_token,
                    detail=f"TXT record {target_record} contains the expected verification token.",
                )
            return VerificationMethodResult(
                method="dns",
                success=False,
                expected_location=target_record,
                expected_value=expected_token,
                detail=f"TXT record {target_record} was found, but the expected verification token was not present.",
            )

        return await asyncio.to_thread(lookup_txt)

    async def verify_via_http(self, domain: str, expected_token: str, path: str | None = None) -> VerificationMethodResult:
        http_path = path or self._default_http_path()
        expected_url = self._http_url_for_domain(domain, http_path)
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(expected_url, headers={"Accept": "application/json"})
        except Exception as error:
            return VerificationMethodResult(
                method="http",
                success=False,
                expected_location=expected_url,
                expected_value=expected_token,
                detail=f"Missing HTTP verification file at {expected_url}: {error}",
            )

        if response.status_code != 200:
            return VerificationMethodResult(
                method="http",
                success=False,
                expected_location=expected_url,
                expected_value=expected_token,
                detail=f"Missing HTTP verification file at {expected_url}: expected 200 OK but received {response.status_code}.",
            )

        try:
            payload = response.json()
        except json.JSONDecodeError:
            return VerificationMethodResult(
                method="http",
                success=False,
                expected_location=expected_url,
                expected_value=expected_token,
                detail=f"Verification file at {expected_url} is not valid JSON.",
            )

        token_candidates = [
            payload.get("token"),
            payload.get("verification_token"),
            payload.get("value"),
            payload.get("txt_token"),
        ]
        if any(candidate == expected_token for candidate in token_candidates):
            return VerificationMethodResult(
                method="http",
                success=True,
                expected_location=expected_url,
                expected_value=expected_token,
                detail=f"Verification file at {expected_url} contains the expected token.",
            )
        return VerificationMethodResult(
            method="http",
            success=False,
            expected_location=expected_url,
            expected_value=expected_token,
            detail=f"Verification file at {expected_url} is present, but the expected token is missing.",
        )

    async def verify_target(self, target_url: str, user_id: str | None = None) -> DomainVerificationResult:
        domain = self._extract_domain(target_url)
        if not domain:
            return DomainVerificationResult(
                domain="",
                allowed=False,
                failure_message="DOMAIN VERIFICATION FAILED: target hostname could not be resolved from the scan request.",
            )

        record = self.storage.fetch_target_verification_record(domain, user_id=user_id)
        if not record:
            return DomainVerificationResult(
                domain=domain,
                allowed=False,
                record_found=False,
                failure_message=(
                    f"DOMAIN VERIFICATION FAILED: no public.targets record was found for `{domain}`. "
                    "Create the target record and complete DNS or HTTP ownership verification before scanning."
                ),
            )

        is_verified = bool(record.get("is_verified"))
        if is_verified:
            return DomainVerificationResult(
                domain=domain,
                allowed=True,
                is_verified=True,
                record_found=True,
            )

        expected_token = str(record.get("verification_token") or record.get("http_token") or "").strip()
        if not expected_token:
            return DomainVerificationResult(
                domain=domain,
                allowed=False,
                is_verified=False,
                record_found=True,
                failure_message=(
                    f"DOMAIN VERIFICATION FAILED: public.targets row for `{domain}` is missing a verification token, "
                    "so DNS and HTTP proof checks cannot run."
                ),
            )

        dns_result = await self.verify_via_dns(domain, expected_token, record.get("dns_record"))
        http_result = await self.verify_via_http(domain, expected_token, record.get("http_path"))

        if dns_result.success and http_result.success:
            await asyncio.to_thread(self.storage.mark_target_verified, domain)
            return DomainVerificationResult(
                domain=domain,
                allowed=True,
                is_verified=True,
                record_found=True,
                dns=dns_result,
                http=http_result,
            )
        else:
            missing_requirements: list[str] = []
            if not dns_result.success:
                missing_requirements.append(
                    f"missing TXT record `{dns_result.expected_location}` with token `{expected_token}`"
                )
            if not http_result.success:
                missing_requirements.append(
                    f"missing verification file `{http_result.expected_location}` with JSON token `{expected_token}`"
                )
            failure_message = "DOMAIN VERIFICATION FAILED: " + " and ".join(missing_requirements) + "."

        logger.warning("Domain verification blocked scan for %s: %s", domain, failure_message)
        return DomainVerificationResult(
            domain=domain,
            allowed=False,
            is_verified=False,
            record_found=True,
            failure_message=failure_message,
            dns=dns_result,
            http=http_result,
        )
