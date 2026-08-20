from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from config import BLOCKLIST_EXPIRE_DAYS
from schemas import (
    BlocklistCheckResponse,
    BlocklistCreateRequest,
    BlocklistItem,
    BlocklistResponse,
    DeleteResponse,
)
from utils import verify_api_key
from validation import InvalidTarget, normalize_target

router = APIRouter(prefix="/blocklist", tags=["blocklist"])


def _active_filter() -> dict:
    """只算還沒過期的項目。

    原本的查詢完全沒有比對 expires_at,所以 README 講的「30 天過期」
    在程式裡其實不存在 —— 寫進去的東西會一直有效。
    """
    return {"expires_at": {"$gt": datetime.now(timezone.utc)}}


def _iso(value) -> str:
    return value.isoformat() if value else ""


@router.get("/check/{target}", response_model=BlocklistCheckResponse)
async def check_blocklist(target: str, request: Request):
    """供外部系統(防火牆等)對接的公開查詢端點。"""
    try:
        _, normalized = normalize_target(target)
    except InvalidTarget:
        # 對接端可能送進奇怪的字串,回 400 比默默回報「未封鎖」誠實。
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{target}' 不是合法的 IP 位址或 domain 名稱",
        ) from None

    doc = await request.app.state.blocklist.find_one(
        {"target": normalized, **_active_filter()}
    )
    if not doc:
        return {"target": normalized, "blocked": False}

    return {
        "target": normalized,
        "blocked": True,
        "reason": doc.get("reason", ""),
        "risk_level": doc.get("risk_level", "UNKNOWN"),
        "expires_at": _iso(doc.get("expires_at")),
    }


@router.get("", response_model=BlocklistResponse)
async def get_blocklist(request: Request):
    collection = request.app.state.blocklist
    cursor = collection.find(_active_filter()).sort("added_at", -1)
    docs = await cursor.to_list(length=500)

    items = [
        BlocklistItem(
            target=doc.get("target", ""),
            target_type=doc.get("target_type", "ip"),
            reason=doc.get("reason", ""),
            risk_level=doc.get("risk_level", "UNKNOWN"),
            added_by=doc.get("added_by", "agent"),
            added_at=_iso(doc.get("added_at")),
            expires_at=_iso(doc.get("expires_at")),
            analysis_id=doc.get("analysis_id"),
        )
        for doc in docs
    ]
    total = await collection.count_documents(_active_filter())
    return {"items": items, "total": total}


@router.post("", response_model=BlocklistItem, status_code=status.HTTP_201_CREATED)
async def add_blocklist(
    body: BlocklistCreateRequest,
    request: Request,
    _: str = Depends(verify_api_key),
):
    """人工加入黑名單。

    `backend_contract.md` §2.8 有定義這個端點,但一直沒實作 ——
    前端的「👤 MANUAL」來源標籤因此永遠不會出現。
    """
    target_type, normalized = normalize_target(body.target)
    now = datetime.now(timezone.utc)
    expire_days = body.expire_days or BLOCKLIST_EXPIRE_DAYS

    doc = {
        "target": normalized,
        "target_type": target_type,
        "reason": body.reason,
        "risk_level": body.risk_level,
        "added_by": "manual",
        "added_at": now,
        "expires_at": now + timedelta(days=expire_days),
        "analysis_id": None,
    }
    await request.app.state.blocklist.update_one(
        {"target": normalized}, {"$set": doc}, upsert=True
    )

    return BlocklistItem(
        **{**doc, "added_at": _iso(now), "expires_at": _iso(doc["expires_at"])}
    )


@router.delete("/{target}", response_model=DeleteResponse)
async def delete_blocklist(
    target: str, request: Request, _: str = Depends(verify_api_key)
):
    try:
        _, normalized = normalize_target(target)
    except InvalidTarget:
        normalized = target.strip()

    result = await request.app.state.blocklist.delete_one({"target": normalized})
    if not result.deleted_count:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found in blocklist",
        )
    return {"success": True, "target": normalized}
