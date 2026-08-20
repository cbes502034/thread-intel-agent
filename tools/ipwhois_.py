import asyncio
import logging

import ipwhois

from config import EXTERNAL_TIMEOUT_SECONDS
from tools.normalize import to_serializable
from utils import duration, iscache

logger = logging.getLogger(__name__)


def _lookup(ip: str):
    return ipwhois.IPWhois(ip, timeout=int(EXTERNAL_TIMEOUT_SECONDS)).lookup_rdap()


@duration
@iscache("ipwhois")
async def ipwhois_lookup(ip, collection):
    """查詢 IP 的 RDAP 註冊資訊。

    查保留網段、或 RDAP 伺服器沒有對應紀錄時,ipwhois 會丟例外。
    這裡一律收斂成結構化錯誤,不讓單一來源失敗中斷整次分析。
    """
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_lookup, ip),
            timeout=EXTERNAL_TIMEOUT_SECONDS + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"IPWHOIS 查詢逾時({EXTERNAL_TIMEOUT_SECONDS} 秒)", "error_type": "timeout"}
    except ipwhois.exceptions.IPDefinedError as exc:
        return {"error": f"該 IP 屬於保留或私有網段:{exc}", "error_type": "reserved"}
    except ipwhois.exceptions.BaseIpwhoisException as exc:
        return {"error": f"IPWHOIS 查詢失敗:{exc}", "error_type": "lookup_failed"}
    except Exception as exc:
        logger.warning("ipwhois_lookup failed for %s", ip, exc_info=True)
        return {"error": f"IPWHOIS 查詢失敗:{exc}", "error_type": "lookup_failed"}

    if not result:
        return {"error": "IPWHOIS 沒有回傳任何資料", "error_type": "empty"}

    return to_serializable(result)
