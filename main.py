from fastapi import FastAPI, Request, HTTPException, APIRouter
from fastapi.staticfiles import StaticFiles
from config import MONGODB_URL, BLOCKLIST_EXPIRE_DAYS
from utils import get_analysis_id
from contextlib import asynccontextmanager
from pymongo import AsyncMongoClient
from datetime import timedelta
from agent import AI
from routers import analyses, blocklist, system

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

main_router = APIRouter(prefix="/api/v1")

main_router.include_router(analyses.router)
main_router.include_router(blocklist.router)
main_router.include_router(system.router)

app = FastAPI(lifespan=lifespan)
app.include_router(main_router)


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
    











app.mount("/", StaticFiles(directory="static", html=True), name="static")
