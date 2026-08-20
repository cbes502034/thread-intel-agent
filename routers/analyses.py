import logging
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Query, Request, status

from agent import AI, AgentError
from config import BLOCKLIST_EXPIRE_DAYS
from ratelimit import enforce_analysis_quota
from schemas import (
    AnalysisListResponse,
    AnalysisResponse,
    AnalyzeRequest,
    ThinkingResponse,
)
from utils import get_client_ip
from validation import normalize_target

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.get("", response_model=AnalysisListResponse)
async def get_analyses(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
):
    """分析歷史列表。

    原本會 `find({})` 把整個 collection 撈進記憶體,回傳的 limit / skip 是寫死的
    假數字,而且沒有排序 —— 前端拿到的順序其實只是 MongoDB 的自然順序。
    """
    collection = request.app.state.analyses
    cursor = collection.find({}).sort("created_at", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)

    items = []
    for doc in docs:
        result = doc.get("result") or {}
        created_at = doc.get("created_at")
        items.append({
            "analysis_id": doc.get("analysis_id", ""),
            "target": doc.get("target", ""),
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "summary": result.get("summary", ""),
            "created_at": created_at.isoformat() if created_at else "",
        })

    total = await collection.count_documents({})
    return {"items": items, "total": total, "limit": limit, "skip": skip}


@router.post("", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def create_analysis(body: AnalyzeRequest, request: Request):
    """建立一次分析。

    這是整個系統唯一會產生費用的端點(LLM token + 外部 API 額度),
    所以用量控管擋在最前面,而且是在呼叫 Agent 之前就擋掉。
    """
    await enforce_analysis_quota(request.app.state.rate_limits, get_client_ip(request))

    # AnalyzeRequest 已經驗證並正規化過,這裡只是取回類型。
    target_type, target = normalize_target(body.target)

    ai = AI(target, request.app.state.cache, request.app.state.tool_calls)
    try:
        report = await ai.run()
    except AgentError as exc:
        logger.error("agent failed for %s: %s", target, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"分析未能完成:{exc}",
        ) from exc
    except Exception as exc:
        logger.exception("unexpected agent failure for %s", target)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="分析過程發生非預期錯誤,請稍後再試",
        ) from exc

    doc = {
        "analysis_id": ai.analysis_id,
        "target": target,
        # 用我們自己驗證出來的類型,而不是模型回報的。
        # 這個判斷是確定性的,沒有理由讓它有機會出錯。
        "target_type": target_type,
        "created_at": ai.now,
        "result": {
            "risk_level": report["risk_level"],
            "summary": report["summary"],
            "evidence": report["evidence"],
            "sources_checked": report["sources_checked"],
            "recommendation": report["recommendation"],
        },
        "metadata": {
            "duration_ms": ai.duration_ms,
            "iterations": ai.iterations,
            "tool_calls_count": ai.tool_calls_count,
            "input_tokens": ai.input_tokens,
            "output_tokens": ai.output_tokens,
            # 原本寫死 0,前端因此永遠顯示「0 cache hits」。
            "cache_hits": ai.cache_hits,
            "stopped_reason": ai.stopped_reason,
        },
    }

    await request.app.state.analyses.insert_one(doc)
    await _sync_blocklist(request, doc)

    doc["created_at"] = ai.now.isoformat()
    doc.pop("_id", None)
    return doc


async def _sync_blocklist(request: Request, doc) -> None:
    """讓黑名單跟著最新一次的判定走。

    原本只有「判到 HIGH 就加入」這個方向,所以一旦被加進去就永遠出不來 ——
    線上資料裡 185.220.101.42 第一次判 HIGH 之後,後續三次都判 MEDIUM,
    但黑名單紀錄一直留著。這裡補上降級時的移除。

    只動 Agent 自己加的紀錄;人工加入的項目要由人工移除。
    """
    collection = request.app.state.blocklist
    target = doc["target"]
    risk_level = doc["result"]["risk_level"]

    if risk_level == "HIGH":
        await collection.update_one(
            {"target": target},
            {
                "$set": {
                    "target": target,
                    "target_type": doc["target_type"],
                    "reason": doc["result"]["summary"],
                    "risk_level": risk_level,
                    "added_by": "agent",
                    "added_at": doc["created_at"],
                    "expires_at": doc["created_at"]
                    + timedelta(days=BLOCKLIST_EXPIRE_DAYS),
                    "analysis_id": doc["analysis_id"],
                }
            },
            upsert=True,
        )
        return

    removed = await collection.delete_one({"target": target, "added_by": "agent"})
    if removed.deleted_count:
        logger.info(
            "removed %s from blocklist after downgrade to %s", target, risk_level
        )


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_by_id(analysis_id: str, request: Request):
    collection = request.app.state.analyses
    doc = await collection.find_one({"analysis_id": analysis_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")

    created_at = doc.get("created_at")
    doc["created_at"] = created_at.isoformat() if created_at else ""
    doc.pop("_id", None)
    return doc


@router.get("/{analysis_id}/thinking", response_model=ThinkingResponse)
async def get_analysis_thinking(analysis_id: str, request: Request):
    collection = request.app.state.tool_calls
    cursor = collection.find({"analysis_id": analysis_id}).sort("timestamp", 1)
    docs = await cursor.to_list(length=200)

    steps = []
    for doc in docs:
        timestamp = doc.get("timestamp")
        doc["timestamp"] = timestamp.isoformat() if timestamp else ""
        doc.pop("_id", None)
        steps.append(doc)

    return {"analysis_id": analysis_id, "steps": steps}
