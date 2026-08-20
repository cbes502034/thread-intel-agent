import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

from database import lifespan as db_lifespan
from routers import analyses, blocklist, system
from tools.http_client import close_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """資料庫生命週期之外,再加上共用 HTTP client 的收尾。"""
    async with db_lifespan(app):
        try:
            yield
        finally:
            await close_client()


main_router = APIRouter(prefix="/api/v1")
main_router.include_router(analyses.router)
main_router.include_router(blocklist.router)
main_router.include_router(system.router)

app = FastAPI(
    title="Threat Intel Agent",
    description="AI 驅動的 IP / Domain 威脅情資分析 API",
    version="1.1.0",
    lifespan=lifespan,
)
app.include_router(main_router)


@app.middleware("http")
async def security_headers(request, call_next):
    """基本的瀏覽器端防護標頭。

    頁面用了 Tailwind CDN 且有大量 inline script,所以 script-src 還是得放行
    inline —— CSP 在這裡不是防 XSS 的主力(主力是前端的輸出跳脫),
    但它能擋掉外部資源載入、表單外送與被嵌入 iframe。
    """
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


# static 一定要最後掛,否則會蓋掉上面的 API 路由。
# 注意:掛在 "/" 等於把整個目錄公開,所以這個目錄只放前端資產 ——
# 內部的設計文件已經移到 docs/,不再隨著網站對外提供。
app.mount("/", StaticFiles(directory="static", html=True), name="static")
