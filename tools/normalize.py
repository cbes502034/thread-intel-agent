"""外部 API 回應的正規化。

兩個目的:

1. **可序列化** —— WHOIS 會回傳 datetime、set 這類 BSON / JSON 不一定吃得下的
   型別。統一轉成字串,快取寫入與餵給模型的 payload 才不會炸。
2. **瘦身** —— VirusTotal 的 `last_analysis_results` 有 90 幾個引擎的完整結果,
   整包塞進對話會吃掉大量 token,在多輪迴圈裡尤其嚴重。只保留判斷用得到的
   統計欄位,以及實際判為惡意/可疑的引擎名稱。
"""

from datetime import date, datetime
from typing import Any

MAX_LIST_ITEMS = 20
MAX_STRING_LENGTH = 2000


def to_serializable(value: Any, _depth: int = 0) -> Any:
    """遞迴轉成 JSON / BSON 都吃得下的型別。"""
    if _depth > 12:
        return str(value)

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return value[:MAX_STRING_LENGTH]

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            # MongoDB 的欄位名不接受 $ 開頭,句點也會被當成巢狀路徑。
            str(k).replace("$", "_").replace(".", "_"): to_serializable(v, _depth + 1)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        items = list(value)[:MAX_LIST_ITEMS]
        return [to_serializable(v, _depth + 1) for v in items]

    return str(value)[:MAX_STRING_LENGTH]


def slim_virustotal(data: dict) -> dict:
    """只留下判定風險等級真正會用到的欄位。"""
    attributes = data.get("attributes") or {}
    analysis_results = attributes.get("last_analysis_results") or {}

    flagged = [
        engine
        for engine, verdict in analysis_results.items()
        if isinstance(verdict, dict)
        and verdict.get("category") in ("malicious", "suspicious")
    ]

    slim = {
        "id": data.get("id"),
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes"),
        "categories": attributes.get("categories"),
        "flagged_by": sorted(flagged)[:MAX_LIST_ITEMS],
        "flagged_count": len(flagged),
    }

    for optional in (
        "as_owner",
        "asn",
        "country",
        "network",
        "creation_date",
        "registrar",
        "tags",
    ):
        if optional in attributes:
            slim[optional] = attributes[optional]

    return to_serializable(slim)
