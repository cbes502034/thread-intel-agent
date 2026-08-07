from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from config import MONGODB_URL
from beanie import Document
from datetime import datetime
from contextlib import asynccontextmanager
from pymongo import AsyncMongoClient
from beanie import init_beanie
from uuid import uuid4
# class Analysis(Document):
#     analysis_id: str
#     target: str
#     target_type: str
#     created_at: datetime
#     result: dict
#     metadate: dict
    
#     class Settings:
#         name = "analyses"

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)
    db = client["threat_intel"]
    app.state.analyses = db["analyses"]
    yield
    client.close()
    
app = FastAPI(lifespan=lifespan)

@app.post("/api/v1/analyses")
async def create_analysis(request: Request):
    body = await request.json()
    target = body.get("target", "")
    return {
        "message": "success",
        "target": target,
    }

app.mount("/", StaticFiles(directory="static", html=True), name="static")
