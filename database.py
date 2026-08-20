import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pymongo import ASCENDING, DESCENDING, AsyncMongoClient

from config import MONGODB_URL

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)

    # 資料庫名稱
    db = client["threat_intel"]

    # 資料表名稱
    app.state.db_client = client
    app.state.analyses = db["analyses"]
    app.state.blocklist = db["blocklist"]
    app.state.cache = db["cache"]
    app.state.tool_calls = db["tool_calls"]
    app.state.rate_limits = db["rate_limits"]

    await _ensure_indexes(app)

    yield
    await client.close()


async def _ensure_indexes(app: FastAPI) -> None:
    """建立查詢會用到的索引。

    每個端點都在做沒有索引的 collection scan,資料量一大就會明顯變慢。
    另外用 TTL 索引讓 MongoDB 自己清掉過期的快取與限流紀錄,
    不需要額外寫排程。

    索引建立失敗(例如既有資料違反 unique 條件)只記錄警告,不擋啟動 ——
    服務仍然可用,只是慢一點,總比整個起不來好。
    """
    specs = [
        (app.state.analyses, [("analysis_id", ASCENDING)], {"unique": True}),
        (app.state.analyses, [("created_at", DESCENDING)], {}),
        (app.state.analyses, [("result.risk_level", ASCENDING)], {}),
        (app.state.blocklist, [("target", ASCENDING)], {"unique": True}),
        (app.state.blocklist, [("expires_at", ASCENDING)], {}),
        (
            app.state.tool_calls,
            [("analysis_id", ASCENDING), ("timestamp", ASCENDING)],
            {},
        ),
        (app.state.tool_calls, [("type", ASCENDING), ("from_cache", ASCENDING)], {}),
        (app.state.cache, [("key", ASCENDING)], {"unique": True}),
        # expireAfterSeconds=0:以文件裡的 expires_at 當到期時間,由 MongoDB 自動刪。
        (app.state.cache, [("expires_at", ASCENDING)], {"expireAfterSeconds": 0}),
        (
            app.state.rate_limits,
            [("client_ip", ASCENDING), ("at", ASCENDING)],
            {},
        ),
        # 限流紀錄只要撐過最長的計算視窗(1 天)即可,留兩天當緩衝。
        (
            app.state.rate_limits,
            [("at", ASCENDING)],
            {"expireAfterSeconds": 60 * 60 * 48},
        ),
    ]

    for collection, keys, options in specs:
        try:
            await collection.create_index(keys, **options)
        except Exception:
            logger.warning(
                "failed to create index %s on %s", keys, collection.name, exc_info=True
            )
