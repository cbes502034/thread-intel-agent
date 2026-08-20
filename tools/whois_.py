import asyncio
import logging

import whois

from config import EXTERNAL_TIMEOUT_SECONDS
from tools.normalize import to_serializable
from utils import duration, iscache

try:
    from whois.exceptions import PywhoisError
except ImportError:  # 套件版本差異時退回一般例外
    PywhoisError = Exception

logger = logging.getLogger(__name__)


@duration
@iscache("whois")
async def whois_lookup(domain, collection):
    """查詢 domain 的 WHOIS 註冊資訊。

    `whois.whois()` 是同步且會走 socket 的呼叫,直接 await 會鎖住 event loop,
    所以丟到執行緒池。查不到時它會丟例外 —— 這裡收斂成結構化的錯誤回傳,
    讓 Agent 還能用其餘來源把分析做完,而不是整個請求 500。
    """
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                whois.whois, domain, timeout=int(EXTERNAL_TIMEOUT_SECONDS)
            ),
            timeout=EXTERNAL_TIMEOUT_SECONDS + 5,
        )
    except asyncio.TimeoutError:
        return {"error": f"WHOIS 查詢逾時({EXTERNAL_TIMEOUT_SECONDS} 秒)", "error_type": "timeout"}
    except PywhoisError as exc:
        return {"error": f"WHOIS 查無此網域或解析失敗:{exc}", "error_type": "not_found"}
    except Exception as exc:
        logger.warning("whois_lookup failed for %s", domain, exc_info=True)
        return {"error": f"WHOIS 查詢失敗:{exc}", "error_type": "lookup_failed"}

    if not result:
        return {"error": "WHOIS 沒有回傳任何資料", "error_type": "empty"}

    return to_serializable(dict(result))
