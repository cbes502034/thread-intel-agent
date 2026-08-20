import logging

import httpx

from config import (
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_DOMAINS_REQUESTS_URL,
    VIRUSTOTAL_IP_REQUESTS_URL,
)
from tools.http_client import get_client
from tools.normalize import slim_virustotal
from utils import duration, iscache

logger = logging.getLogger(__name__)


async def _fetch(url: str, target: str, label: str):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "伺服器未設定 VIRUSTOTAL_API_KEY", "error_type": "not_configured"}

    try:
        response = await get_client().get(
            url.format(target), headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
    except httpx.TimeoutException:
        return {"error": f"VirusTotal {label} 查詢逾時", "error_type": "timeout"}
    except httpx.HTTPError as exc:
        logger.warning("virustotal request failed for %s", target, exc_info=True)
        return {"error": f"VirusTotal 連線失敗:{exc}", "error_type": "network"}

    if response.status_code == 404:
        return {"error": f"VirusTotal 查無此 {label}", "error_type": "not_found"}
    if response.status_code == 429:
        # 免費層每分鐘只有 4 次,這個錯誤刻意不進快取。
        return {"error": "VirusTotal 已達速率上限", "error_type": "rate_limited"}
    if response.status_code in (401, 403):
        return {"error": "VirusTotal 金鑰無效或權限不足", "error_type": "auth"}
    if response.status_code != 200:
        return {
            "error": f"VirusTotal 回應失敗,status_code: {response.status_code}",
            "error_type": "http_error",
        }

    try:
        payload = response.json()
    except ValueError:
        return {"error": "VirusTotal 回應不是合法的 JSON", "error_type": "bad_response"}

    return slim_virustotal(payload.get("data", {}))


@duration
@iscache("virustotal_ip")
async def virustotal_ip_lookup(ip, collection):
    return await _fetch(VIRUSTOTAL_IP_REQUESTS_URL, ip, "IP")


@duration
@iscache("virustotal_domain")
async def virustotal_domain_lookup(domain, collection):
    return await _fetch(VIRUSTOTAL_DOMAINS_REQUESTS_URL, domain, "domain")
