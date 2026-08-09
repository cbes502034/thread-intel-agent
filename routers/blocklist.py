from fastapi import APIRouter, Request, HTTPException, Depends
from utils import verify_api_key

router = APIRouter(prefix="/blocklist")

@router.get("/check/{target}")
async def check_blocklist(target: str, request: Request):
    collection = request.app.state.blocklist
    doc = await collection.find_one({"target":target})
    if not doc:
        return {
            "target": target,
            "blocked": False
        }
    return {
        "target": target,
        "blocked": True,
        "reason": doc["reason"],
        "risk_level": doc["risk_level"],
        "expires_at": doc["expires_at"].isoformat()
    }

@router.get("")
async def get_blocklist(request: Request):
    collection = request.app.state.blocklist
    cursor = collection.find({})
    docs = await cursor.to_list()
    items = []
    for doc in docs:
        items.append({
            "target":doc["target"],
            "target_type":doc["target_type"],
            "reason":doc["reason"],
            "risk_level":doc["risk_level"],
            "added_by":doc["added_by"],
            "added_at":doc["added_at"].isoformat(),
            "expires_at":doc["expires_at"].isoformat(),
            "analysis_id":doc["analysis_id"]
        })
    total = await collection.count_documents({})
    return {
        "items":items,
        "total":total
    }


@router.delete("/{target}")
async def delete_blocklist(target: str, request: Request, _: str=Depends(verify_api_key)):
    collection = request.app.state.blocklist
    result = await collection.delete_one({"target":target})
    deleted_count = result.deleted_count
    if not deleted_count:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")
    return {
        "success":True,
        "target":target
    }
        