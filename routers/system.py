import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response, status

from schemas import HealthResponse, StatsResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request, response: Response):
    """健康檢查。

    原本無論如何都回 {"status": "ok"} —— 資料庫掛掉時它照樣說健康,
    等於沒有檢查。這裡實際 ping 一次資料庫。
    """
    try:
        await request.app.state.db_client.admin.command("ping")
    except Exception:
        logger.warning("database ping failed", exc_info=True)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "database": "disconnected"}

    return {"status": "ok", "database": "connected"}


@router.get("/stats", response_model=StatsResponse)
async def stats(request: Request):
    analyses_collection = request.app.state.analyses
    blocklist_collection = request.app.state.blocklist
    tool_calls_collection = request.app.state.tool_calls

    total_analyses = await analyses_collection.count_documents({})
    high_count = await analyses_collection.count_documents(
        {"result.risk_level": "HIGH"}
    )
    high_risk_ratio = (high_count / total_analyses) if total_analyses > 0 else 0.0

    cache_hits = await tool_calls_collection.count_documents(
        {"type": "tool_result", "from_cache": True}
    )
    total_tool_results = await tool_calls_collection.count_documents(
        {"type": "tool_result"}
    )
    cache_hit_rate = (
        (cache_hits / total_tool_results) if total_tool_results > 0 else 0.0
    )

    # 跟 /blocklist 用同一套「未過期」條件,兩邊的數字才不會對不起來。
    blocklist_size = await blocklist_collection.count_documents(
        {"expires_at": {"$gt": datetime.now(timezone.utc)}}
    )

    return {
        "total_analyses": total_analyses,
        "high_risk_ratio": high_risk_ratio,
        "cache_hit_rate": cache_hit_rate,
        "blocklist_size": blocklist_size,
    }
