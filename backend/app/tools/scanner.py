import asyncio
from typing import Any, Dict, List
from urllib.parse import urlparse


COMMON_PORTS = [80, 443, 8080, 3000, 5000]


async def _probe_port(hostname: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    try:
        connection = asyncio.open_connection(hostname, port)
        reader, writer = await asyncio.wait_for(connection, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {"port": port, "state": "open"}
    except Exception:
        return {"port": port, "state": "closed"}


async def port_scan(target_url: str) -> Dict[str, Any]:
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    hostname = parsed.hostname or ""

    if not hostname:
        return {"host": "", "ports": [], "open_ports": [], "error": "Port scan could not start because the hostname was invalid."}

    try:
        results = await asyncio.gather(*[_probe_port(hostname, port) for port in COMMON_PORTS])
    except Exception as error:
        return {
            "host": hostname,
            "ports": [],
            "open_ports": [],
            "error": f"Port scan failed for {hostname}: {error}",
        }

    open_ports = [result["port"] for result in results if result["state"] == "open"]
    return {"host": hostname, "ports": results, "open_ports": open_ports}


def format_port_logs(scan_result: Dict[str, Any]) -> List[str]:
    if scan_result.get("error"):
        return [f"[EXECUTE] PORT_SCAN: {scan_result['error'].upper()}."]

    host = scan_result.get("host", "").upper() or "UNKNOWN HOST"
    open_ports = scan_result.get("open_ports", [])
    if open_ports:
        return [
            f"[EXECUTE] PORT_SCAN: {host} RESPONDED ON {', '.join(str(port) for port in open_ports)}.",
            f"[EXECUTE] PORT_SCAN: CLOSED OR FILTERED PORTS REMAIN UNDER OBSERVATION.",
        ]

    return [
        f"[EXECUTE] PORT_SCAN: NO COMMON WEB PORTS RESPONDED ON {host}.",
        "[EXECUTE] PORT_SCAN: TARGET MAY BE FILTERED, IDLE, OR FRONTED BY UPSTREAM CONTROLS.",
    ]
