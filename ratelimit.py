"""`POST /analyses` 的用量控管。

這個端點每次呼叫都會花掉 LLM token 與 VirusTotal / AbuseIPDB 的額度,
是整個系統唯一會直接產生費用的地方。原本它只靠一把寫死在前端原始碼裡的
API Key 保護 —— 等於沒有保護。

改成兩層限制:

* per-IP 滑動視窗:擋掉單一使用者的連點與腳本重跑。
* 全站每日總量:per-IP 可以靠換 IP 繞過,這層才是真正的預算天花板。

紀錄寫在獨立的 collection,計算的是「嘗試次數」而不是「成功次數」——
失敗的分析一樣燒掉了 token,不該不算數。
"""

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status

from config import (
    DAILY_ANALYSIS_BUDGET,
    RATE_LIMIT_PER_IP,
    RATE_LIMIT_WINDOW_MINUTES,
)


async def enforce_analysis_quota(collection, client_ip: str) -> None:
    """超出額度時丟出 429,否則記錄本次嘗試。"""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
    day_start = now - timedelta(days=1)

    daily_used = await collection.count_documents({"at": {"$gte": day_start}})
    if daily_used >= DAILY_ANALYSIS_BUDGET:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"本站今日分析額度已用盡({DAILY_ANALYSIS_BUDGET} 次),請明天再試。"
            ),
            headers={"Retry-After": "3600"},
        )

    recent = collection.find(
        {"client_ip": client_ip, "at": {"$gte": window_start}}
    ).sort("at", 1)
    recent_docs = await recent.to_list(length=RATE_LIMIT_PER_IP + 1)

    if len(recent_docs) >= RATE_LIMIT_PER_IP:
        oldest = recent_docs[0]["at"]
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        retry_after = int(
            (oldest + timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES) - now)
            .total_seconds()
        )
        retry_after = max(retry_after, 1)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"查詢過於頻繁,每 {RATE_LIMIT_WINDOW_MINUTES} 分鐘最多 "
                f"{RATE_LIMIT_PER_IP} 次,請於 {retry_after} 秒後再試。"
            ),
            headers={"Retry-After": str(retry_after)},
        )

    await collection.insert_one({"client_ip": client_ip, "at": now})
