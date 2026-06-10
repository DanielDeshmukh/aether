import os
import logging
from app.services.storage import ScanStorage

logger = logging.getLogger("aether.quota")

class QuotaManager:
    def __init__(self, storage: ScanStorage):
        self._storage = storage
        self._tier_limits = {
            "free": int(os.getenv("QUOTA_FREE_LIMIT", "3")),
            "pro": int(os.getenv("QUOTA_PRO_LIMIT", "50")),
            "enterprise": int(os.getenv("QUOTA_ENTERPRISE_LIMIT", "999")),
        }
    
    def get_limit(self, tier: str = "free") -> int:
        return self._tier_limits.get(tier, self._tier_limits["free"])
    
    def check_quota(self, user_id: str, tier: str = "free") -> dict:
        """Returns dict with 'allowed', 'used', 'limit', 'remaining'."""
        used = self._storage.get_total_scan_count(user_id)
        limit = self.get_limit(tier)
        return {
            "allowed": used < limit,
            "used": used,
            "limit": limit,
            "remaining": max(0, limit - used),
        }