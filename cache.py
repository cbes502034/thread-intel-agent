"""外部查詢結果的快取讀寫。

原本的版本有兩個會咬人的行為:

1. `if cache:` 判斷命中 —— 快取值是空 dict / 空 list 時會被當成 miss,
   每次都重新打外部 API。改用明確的 (命中?, 值) 回傳。
2. 錯誤也照樣寫進快取 —— 一次臨時的 429 rate limit 會讓那個目標接下來
   24 小時都查不到,跟快取的目的完全相反。改成只快取成功的結果。
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from config import CACHE_TTL_HOURS

# (是否命中, 值)。用 tuple 而不是靠值本身的真假,避免空 dict 被誤判成 miss。
CacheLookup = tuple[bool, Any]
MISS: CacheLookup = (False, None)


def make_cache_key(tool_name: str, target: str) -> str:
    """加上工具名稱前綴,避免不同來源對同一目標的結果互相覆蓋。"""
    return f"{tool_name}:{target}"


def is_cacheable(result: Any) -> bool:
    """工具回報錯誤時不寫入快取,免得把暫時性失敗醃成長期失敗。"""
    return not (isinstance(result, dict) and "error" in result)


async def get_cache(collection, key: str) -> CacheLookup:
    doc = await collection.find_one({"key": key})
    if not doc:
        return MISS

    expires_at = doc.get("expires_at")
    if expires_at is None:
        return MISS

    # MongoDB 取回的 datetime 可能不帶時區資訊,補上 UTC 才能比較。
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        return MISS

    return True, doc.get("value")


async def set_cache(
    collection, key: str, value: Any, ttl_hours: int = CACHE_TTL_HOURS
) -> None:
    await collection.update_one(
        {"key": key},
        {
            "$set": {
                "key": key,
                "value": value,
                "expires_at": datetime.now(timezone.utc)
                + timedelta(hours=ttl_hours),
            }
        },
        upsert=True,
    )
