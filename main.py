from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from config import MONGODB_URL, BLOCKLIST_EXPIRE_DAYS
from utils import get_analysis_id
from contextlib import asynccontextmanager
from pymongo import AsyncMongoClient
from datetime import timedelta
from agent import AI

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)
    db = client["threat_intel"]
    app.state.analyses = db["analyses"]
    app.state.blocklist = db["blocklist"]
    app.state.cache = db["cache"]
    app.state.tool_calls = db["tool_calls"]
    yield
    client.close()
    
app = FastAPI(lifespan=lifespan)

@app.get("/api/v1/analyses")
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

# @app.post("/api/v1/blocklist")
# async def add_to_blocklist(request: Request):
#     body = await request.json()
#     ip = body.get("ip", "")
#     reason = body.get("reason", "")
#     risk_level = body.get("risk_level", "LOW")
#     now = datetime.now(timezone.utc)
#     doc = {
#         "ip": ip,
#         "reason": reason,
#         "risk_level": risk_level,
#         "added_by": "manual",
#         "added_at": now,
#         "expires_at": now + timedelta(days=BLOCKLIST_EXPIRE_DAYS),
#         "analysis_id": None
#     }
#     collection = request.app.state.blocklist
#     await collection.insert_one(doc)
#     doc["added_at"] = doc["added_at"].isoformat()
#     doc["expires_at"] = doc["expires_at"].isoformat()
#     doc.pop("_id", None)
#     return doc
    


@app.get("/api/v1/analyses/{analysis_id}")
async def get_analysis_by_id(analysis_id: str, request: Request):
    collection = request.app.state.analyses
    doc = await collection.find_one({"analysis_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    doc["created_at"] = doc["created_at"].isoformat()
    doc.pop("_id", None)
    return doc

@app.get("/api/v1/blocklist/check/{target}")
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
@app.get("/api/v1/analyses/{analysis_id}/thinking")
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

@app.get("/api/v1/blocklist")
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

@app.delete("/api/v1/blocklist/{target}")
async def delete_blocklist(target: str, request: Request):
    collection = request.app.state.blocklist
    result = await collection.delete_one({"target":target})
    deleted_count = result.deleted_count
    if not deleted_count:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")
    return {
        "success":True,
        "target":target
    }
        
@app.post("/api/v1/analyses")
async def create_analysis(request: Request):
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


app.mount("/", StaticFiles(directory="static", html=True), name="static")
