from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from config import MONGODB_URL, EXPIRATION_DAYS
print(f"MONGODB_URL: {MONGODB_URL}")
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pymongo import AsyncMongoClient
from uuid import uuid4

def get_analisis_id(return_now= False):
    uid = uuid4().hex[:6]
    now = datetime.now(timezone.utc)
    d = now.strftime("%Y%m%d")
    prefix = "ana"
    if return_now:
        return f"{prefix}_{d}_{uid}", now
    return f"{prefix}_{d}_{uid}"

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)
    db = client["threat_intel"]
    app.state.analyses = db["analyses"]
    app.state.blocklist = db["blocklist"]
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

@app.post("/api/v1/blocklist")
async def add_to_blocklist(request: Request):
    body = await request.json()
    ip = body.get("ip", "")
    reason = body.get("reason", "")
    risk_level = body.get("risk_level", "LOW")
    now = datetime.now(timezone.utc)
    doc = {
        "ip": ip,
        "reason": reason,
        "risk_level": risk_level,
        "added_by": "manual",
        "added_at": now,
        "expires_at": now + EXPIRATION_DAYS,
        "analysis_id": "null"



    }


@app.get("/api/v1/analyses/{analysis_id}")
async def get_analysis_by_id(analysis_id: str, request: Request):
    collection = request.app.state.analyses
    doc = await collection.find_one({"analysis_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    doc["created_at"] = doc["created_at"].isoformat()
    doc.pop("_id", None)
    return doc


@app.get("/api/v1/analyses/{analysis_id}")
async def get_analysis_by_id(analysis_id: str, request: Request):
    collection = request.app.state.analyses
    doc = await collection.find_one({"analysis_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    doc["created_at"] = doc["created_at"].isoformat()
    doc.pop("_id", None)
    return doc

@app.get("/api/v1/analyses/{analysis_id}/thinking")
async def get_analysis_thinking(analysis_id: str, request: Request):
    return {
        "analysis_id": analysis_id,
        "steps": []
    }

@app.get("api/v1/blocklist")
async def()
@app.post("/api/v1/analyses")
async def create_analysis(request: Request):
    body = await request.json()
    target = body.get("target", "")

    analysis_id, now = get_analisis_id(return_now=True)

    doc = {
        "analysis_id": analysis_id,
        "target": target,
        "target_type": "ip",
        "created_at": now,
        "result": {
            "risk_level": "LOW",
            "summary":"Mock",
            "evidence": [],
            "sources_checked": [],
            "recommendation": "Mock"
        },
        "metadata": {
            "duration_ms": 0,
            "iterations": 0,
            "tool_calls_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_hits": 0
        }
    }
    collection = request.app.state.analyses
    await collection.insert_one(doc)

    doc["created_at"] = now.isoformat()
    doc.pop("_id", None)
    return doc 

app.mount("/", StaticFiles(directory="static", html=True), name="static")
