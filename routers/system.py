from fastapi import APIRouter

router = APIRouter(prefix="/system")

@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/stats")
async def stats():
    return {
        "total_analyses": 0,
        "high_risk_ratio": 0.0,
        "cache_hit_rate": 0.0,
        "blocklist_size": 0
    }