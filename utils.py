import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from time import perf_counter
from uuid import uuid4

from fastapi import HTTPException, Request, Security, status

from cache import get_cache, is_cacheable, make_cache_key, set_cache
from config import ADMIN_API_KEY, API_KEY_HEADER

logger = logging.getLogger(__name__)


def get_analysis_id(return_now: bool = False):
    uid = uuid4().hex[:6]
    now = datetime.now(timezone.utc)
    d = now.strftime("%Y%m%d")
    prefix = "ana"
    if return_now:
        return f"{prefix}_{d}_{uid}", now
    return f"{prefix}_{d}_{uid}"


def duration(fun):
    """在內層裝飾器回傳的 tuple 後面附加執行毫秒數。

    約定:被包裝的函式回傳 ``(結果, (其他資訊...))``,本裝飾器攤平成
    ``(結果, *其他資訊, 耗時)``。中間要再加裝飾器(例如重試)時,只要遵守
    同樣的約定,這裡完全不用改。
    """

    @wraps(fun)
    async def wrap(*args, **kwargs):
        start = perf_counter()
        back, middle_tuple = await fun(*args, **kwargs)
        exec_time = int((perf_counter() - start) * 1000)
        return back, *middle_tuple, exec_time

    return wrap


def iscache(name):
    def decorator(fun):
        @wraps(fun)
        async def wrap(arg, collection):
            cache_key = make_cache_key(name, arg)

            try:
                hit, value = await get_cache(collection, cache_key)
            except Exception:
                # 快取讀取失敗不該讓整次查詢失敗,退化成直接查來源。
                logger.warning("cache read failed for %s", cache_key, exc_info=True)
                hit, value = False, None

            if hit:
                return value, (True,)

            result = await fun(arg, collection)

            if is_cacheable(result):
                try:
                    await set_cache(collection, cache_key, result)
                except Exception:
                    # 外部 API 的回應偶爾含有 BSON 編不動的型別,
                    # 寫不進快取就算了,不要因此丟掉已經查到的結果。
                    logger.warning(
                        "cache write failed for %s", cache_key, exc_info=True
                    )

            return result, (False,)

        return wrap

    return decorator


async def verify_api_key(key: str | None = Security(API_KEY_HEADER)) -> str:
    """保護會改變系統狀態的端點。

    伺服器沒設定 ADMIN_API_KEY 時一律拒絕(fail closed),
    而不是讓端點在沒有金鑰的狀態下開著。
    """
    if not ADMIN_API_KEY:
        logger.error("ADMIN_API_KEY is not configured; refusing admin request")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API is not configured on this server",
        )

    if not key or not secrets.compare_digest(key, ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return key


def get_client_ip(request: Request) -> str:
    """取得呼叫端 IP。

    Render 這類 PaaS 會在 X-Forwarded-For 最左邊放上實際的來源 IP。
    這個值理論上可被偽造,所以 per-IP 限流只當作第一道防線,
    真正的保險是 DAILY_ANALYSIS_BUDGET 這個全站上限。
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
