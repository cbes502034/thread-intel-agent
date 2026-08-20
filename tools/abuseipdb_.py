import logging

import httpx

from config import ABUSEIPDB_API_KEY, ABUSEIPDB_REQUESTS_URL
from tools.http_client import get_client
from tools.normalize import to_serializable
from utils import duration, iscache

logger = logging.getLogger(__name__)


@duration
@iscache("abuseipdb")
async def abuseipdb_lookup(ip, collection):
    if not ABUSEIPDB_API_KEY:
        return {"error": "伺服器未設定 ABUSEIPDB_API_KEY", "error_type": "not_configured"}

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = await get_client().get(
            ABUSEIPDB_REQUESTS_URL, headers=headers, params=params
        )
    except httpx.TimeoutException:
        return {"error": "AbuseIPDB 連線逾時", "error_type": "timeout"}
    except httpx.HTTPError as exc:
        logger.warning("abuseipdb request failed for %s", ip, exc_info=True)
        return {"error": f"AbuseIPDB 連線失敗:{exc}", "error_type": "network"}

    if response.status_code == 429:
        # 這類暫時性失敗不會被寫進快取(見 cache.is_cacheable),
        # 否則一次 rate limit 會把該目標鎖住 24 小時。
        return {"error": "AbuseIPDB 已達速率上限", "error_type": "rate_limited"}
    if response.status_code in (401, 403):
        return {"error": "AbuseIPDB 金鑰無效或權限不足", "error_type": "auth"}
    if response.status_code != 200:
        return {
            "error": f"AbuseIPDB 回應失敗,status_code: {response.status_code}",
            "error_type": "http_error",
        }

    try:
        payload = response.json()
    except ValueError:
        return {"error": "AbuseIPDB 回應不是合法的 JSON", "error_type": "bad_response"}

    return to_serializable(payload.get("data", {}))
