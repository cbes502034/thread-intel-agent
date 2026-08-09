from fastapi import APIRouter, Request

router = APIRouter(prefix="/system")

@router.get("/health")
async def health():
    return {"status": "ok"}


# @router.get("/stats")
# async def stats():
#     return {
#         "total_analyses": 0,
#         "high_risk_ratio": 0.0,
#         "cache_hit_rate": 0.0,
#         "blocklist_size": 0
#     }

@router.get("/stats")
async def stats(request: Request):
    analyses_collection = request.app.state.analyses
    blocklist_collection = request.app.state.blocklist
    tool_calls_collection = request.app.state.tool_calls

    total_analyses = await analyses_collection.count_documents({})
    high_count = await analyses_collection.count_documents({"result.risk_level": "HIGH"})
    high_risk_ratio = (high_count / total_analyses) if total_analyses > 0 else 0.0

    cache_hits = await tool_calls_collection.count_documents({"type": "tool_result", "from_cache": True})
    total_tool_results = await tool_calls_collection.count_documents({"type": "tool_result"})
    cache_hit_rate = (cache_hits / total_tool_results) if total_tool_results > 0 else 0.0

    blocklist_size = await blocklist_collection.count_documents({})

    return {
        "total_analyses": total_analyses,
        "high_risk_ratio": high_risk_ratio,
        "cache_hit_rate": cache_hit_rate,
        "blocklist_size": blocklist_size
    }