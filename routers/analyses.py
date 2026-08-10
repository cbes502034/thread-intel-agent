from fastapi import APIRouter, Request, HTTPException, Depends
from agent import AI
from datetime import timedelta
from config import BLOCKLIST_EXPIRE_DAYS
from utils import verify_api_key
router = APIRouter(prefix="/analyses")

@router.get("")
async def get_analyses(request: Request):
    collection = request.app.state.analyses
    cursor = collection.find({})
    docs = await cursor.to_list()

    items = []
    for doc in docs:
        items.append(
            {
                "analysis_id": doc["analysis_id"],
                "target": doc["target"],
                "risk_level": doc["result"]["risk_level"],
                "summary": doc["result"]["summary"],
                "created_at": doc["created_at"].isoformat()
            }
        )
    total = await collection.count_documents({})
    return {
        "items": items,
        "total": total,
        "limit": 50,
        "skip": 0  
    }

@router.post("")
async def create_analysis(request: Request, _: str=Depends(verify_api_key)):
    body = await request.json()
    target = body.get("target", "") 
    ai = AI(target, request.app.state.cache, request.app.state.tool_calls)
    # analysis_id, now = get_analysis_id(return_now=True)
    await ai.run()
    doc = {
        "analysis_id": ai.analysis_id,
        "target": target,
        "target_type": ai.final_report["target_type"],
        "created_at": ai.now,
        "result": {
            "risk_level": ai.final_report["risk_level"],
            "summary": ai.final_report["summary"],
            "evidence": ai.final_report["evidence"],
            "sources_checked": ai.final_report["sources_checked"],
            "recommendation": ai.final_report["recommendation"]
        },
        "metadata": {
            "duration_ms": ai.duration_ms,
            "iterations": ai.iterations,
            "tool_calls_count": ai.tool_calls_count,
            "input_tokens": ai.result.usage.input_tokens,
            "output_tokens": ai.result.usage.output_tokens,
            "cache_hits": 0
        }
    }
    collection = request.app.state.analyses
    if ai.final_report["risk_level"] == "HIGH":
        blocklist_collection = request.app.state.blocklist
        blocklist_doc = {
            "target": target,
            "target_type": ai.final_report["target_type"],
            "reason": ai.final_report["summary"],
            "risk_level": ai.final_report["risk_level"],
            "added_by": "agent",
            "added_at": ai.now,
            "expires_at": ai.now + timedelta(days=BLOCKLIST_EXPIRE_DAYS),
            "analysis_id": ai.analysis_id
        }
        await blocklist_collection.update_one(
            {"target": target},
            {"$set": blocklist_doc},
            upsert=True
        )
    await collection.insert_one(doc)
    doc["created_at"] = ai.now.isoformat()
    doc.pop("_id", None)
    return doc

@router.get("/{analysis_id}")
async def get_analysis_by_id(analysis_id: str, request: Request):
    collection = request.app.state.analyses
    doc = await collection.find_one({"analysis_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    doc["created_at"] = doc["created_at"].isoformat()
    doc.pop("_id", None)
    return doc

@router.get("/{analysis_id}/thinking")
async def get_analysis_thinking(analysis_id: str, request: Request):
    collection = request.app.state.tool_calls
    cursor = collection.find({"analysis_id": analysis_id}).sort("timestamp", 1)
    docs = await cursor.to_list()
    for doc in docs:
        doc["timestamp"] = doc["timestamp"].isoformat()
        doc.pop("_id", None)
        
        
    return {
        "analysis_id": analysis_id,
        "steps": docs
    }