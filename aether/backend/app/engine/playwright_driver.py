import hashlib
from typing import Any, Dict


def build_aether_safety_token(scan_id: str, user_id: str) -> str:
    material = f"{scan_id}:{user_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def build_safety_headers(scan_id: str, user_id: str) -> Dict[str, str]:
    return {
        "X-Aether-Safety-Token": build_aether_safety_token(scan_id, user_id),
    }


async def create_hardened_browser_context(browser: Any, *, scan_id: str, user_id: str, extra_headers: Dict[str, str] | None = None) -> Any:
    headers = build_safety_headers(scan_id, user_id)
    if extra_headers:
        headers.update(extra_headers)
    return await browser.new_context(extra_http_headers=headers)
