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

app.mount("/", StaticFiles(directory="static", html=True), name="static")
