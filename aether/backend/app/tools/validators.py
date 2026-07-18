import socket
from urllib.parse import urlparse
import ipaddress


BLOCKED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)


def is_safe_url(url: str) -> bool:
    """
    Validates a URL to prevent SSRF and internal network scanning.
    Blocks private IP ranges, reserved ranges, and cloud metadata IPs.
    Strictly allows only http and https schemes.
    """
    try:
        parsed = urlparse(url)
        # 1. Ensure the scheme is strictly http or https
        if parsed.scheme not in ["http", "https"]:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # 2. Resolve the domain to an IP address
        try:
            ip_address_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_address_str)
        except (socket.gaierror, ValueError):
            # If resolution fails or IP is invalid, we don't allow it
            return False

        # 3. Block Cloud Metadata IPs
        if ip_address_str == "169.254.169.254":
            return False

        # 4. Block common private/reserved/internal ranges.
        if any(ip_obj in blocked_network for blocked_network in BLOCKED_NETWORKS):
            return False

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return False

        return True
    except Exception:
        return False
