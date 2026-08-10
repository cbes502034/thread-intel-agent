from fastapi import FastAPI, APIRouter
from fastapi.staticfiles import StaticFiles
from database import lifespan
from routers import analyses, blocklist, system


main_router = APIRouter(prefix="/api/v1")

main_router.include_router(analyses.router)
main_router.include_router(blocklist.router)
main_router.include_router(system.router)

app = FastAPI(lifespan=lifespan)
app.include_router(main_router)

app.mount("/", StaticFiles(directory="static", html=True), name="static")
