"""第二輪（風險判定）的提示組裝與輸出解析。

Agent、微調資料（finetune/build_sft.py）、評測（evaluation/run_eval.py）三處共用，
確保模型訓練時看到的格式與上線時完全一致。
"""
import json

from config import JUDGE_SYSTEM_PROMPT
from evidence import to_json

LEVELS = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
CONFIDENCES = ("high", "medium", "low")


def format_refs(refs):
    return "\n".join(f"[{i}] {r['title']}｜{r['heading']}：{r['text']}" for i, r in enumerate(refs, 1))


def build_judge_messages(evidence, refs=None):
    lines = [
        f"分析目標：{evidence['target']}",
        f"目標事實：{to_json(evidence['facts'])}",
        "證據：",
        to_json(evidence["sources"]),
    ]
    if refs:
        lines += ["參考準則：", format_refs(refs)]
    return [
        {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]


def parse_report(text):
    """解析並驗證模型輸出；不合格回傳 None。"""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("risk_level") not in LEVELS or data.get("target_type") not in ("ip", "domain"):
        return None
    if not isinstance(data.get("evidence"), list):
        return None
    items = []
    for e in data["evidence"]:
        if isinstance(e, dict) and e.get("source") and e.get("finding"):
            conf = e.get("confidence") if e.get("confidence") in CONFIDENCES else "low"
            items.append({"source": str(e["source"]), "finding": str(e["finding"]), "confidence": conf})
    return {
        "target_type": data["target_type"],
        "risk_level": data["risk_level"],
        "summary": str(data.get("summary") or ""),
        "evidence": items,
        "sources_checked": [str(x) for x in (data.get("sources_checked") or [])],
        "recommendation": str(data.get("recommendation") or ""),
    }


def fallback_report(evidence, reason):
    """判定模型兩次都沒產出合格報告時的保底結果（列為 UNKNOWN，不會誤封鎖）。"""
    return {
        "target_type": evidence["facts"]["type"],
        "risk_level": "UNKNOWN",
        "summary": f"判定模型未產出可解析的報告（{reason}），本次列為無法判定。",
        "evidence": [{"source": n, "finding": "已查詢，原始輸出請見思考過程", "confidence": "low"}
                     for n in evidence["sources"]],
        "sources_checked": list(evidence["sources"]),
        "recommendation": "請重新分析或由人工查證。",
    }
