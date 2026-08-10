from contextlib import asynccontextmanager
from config import MONGODB_URL
from pymongo import AsyncMongoClient
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)

    # 資料庫名稱
    db = client["threat_intel"]

    # 資料表名稱
    app.state.analyses = db["analyses"]
    app.state.blocklist = db["blocklist"]
    app.state.cache = db["cache"]
    app.state.tool_calls = db["tool_calls"]
    
    yield
    client.close()