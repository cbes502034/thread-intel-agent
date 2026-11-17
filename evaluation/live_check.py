"""實測：用真實外部 API（VirusTotal、AbuseIPDB、WHOIS、RDAP）跑完整 FastAPI 流程。

- 走 POST /api/v1/analyses（含輸入驗證、Agent、黑名單寫入），和前端呼叫的路徑一樣
- 資料庫換成記憶體版，不會寫進 MongoDB Atlas
- 每筆結果與「rubric 對同一份真實證據的判定」比對
- 為了不撞 VirusTotal 免費層每分鐘 4 次的限制，每個目標之間間隔 16 秒
- 只輸出判定摘要表，不保存外部 API 原始回應（VirusTotal 條款限制轉發原始資料）

用法：python -m evaluation.live_check [--out evaluation/results/live_check.md]
需要 .env 內的 VIRUSTOTAL_API_KEY、ABUSEIPDB_API_KEY，以及本機 Ollama。
"""
import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import httpx  # noqa: E402

from dataset.rubric import judge  # noqa: E402
from evaluation.memdb import MemCollection  # noqa: E402
from evidence import build_evidence  # noqa: E402

TARGETS = [
    ("8.8.8.8", "Google 公共 DNS（AbuseIPDB 白名單）"),
    ("1.1.1.1", "Cloudflare 公共 DNS"),
    ("185.220.101.42", "已知 Tor 出口節點，大量檢舉"),
    ("192.168.1.1", "RFC 1918 私有位址"),
    ("google.com", "高知名度網域"),
    ("github.com", "高知名度網域"),
    ("this-domain-should-not-exist-zx81q.com", "不存在的網域"),
    ("not_a_target!!", "格式錯誤（應被輸入驗證擋下）"),
]


async def main(out):
    import main as app_module            # 延後匯入：先切到專案根目錄讓 .env 生效
    from config import API_KEY

    app = app_module.app
    app.state.analyses, app.state.blocklist = MemCollection(), MemCollection()
    app.state.cache, app.state.tool_calls = MemCollection(), MemCollection()
    headers = {"X-API-Key": API_KEY or ""}
    rows = []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://live",
                                 timeout=600) as client:
        for i, (target, note) in enumerate(TARGETS):
            if i:
                await asyncio.sleep(16)
            t = time.time()
            r = await client.post("/api/v1/analyses", json={"target": target}, headers=headers)
            secs = round(time.time() - t, 1)
            if r.status_code != 200:
                rows.append((target, note, f"HTTP {r.status_code}", "—", "—", secs, r.json().get("detail", "")[:60]))
                print(rows[-1], flush=True)
                continue
            data = r.json()
            steps = [d for d in app.state.tool_calls.docs
                     if d["analysis_id"] == data["analysis_id"] and d["type"] == "tool_result"]
            ev = build_evidence(target, {d["tool_name"]: d["output"] for d in steps})
            expect = judge(ev)["risk_level"]
            got = data["result"]["risk_level"]
            rows.append((target, note, got, expect, "✓" if got == expect else "✗", secs,
                         "、".join(d["tool_name"] for d in steps)))
            print(rows[-1], flush=True)

    blocked = [d["target"] for d in app.state.blocklist.docs]
    lines = ["# 實測結果（真實外部 API）", "",
             f"執行時間：{time.strftime('%Y-%m-%d %H:%M')}；資料庫：記憶體版；黑名單寫入：{blocked or '無'}", "",
             "| 目標 | 說明 | 系統判定 | 準則判定 | 一致 | 秒數 | 查詢的工具 / 訊息 |",
             "|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(str(x) for x in row) + " |" for row in rows]
    judged = [r for r in rows if r[4] in ("✓", "✗")]
    lines += ["", f"一致率：{sum(r[4] == '✓' for r in judged)}/{len(judged)}"]
    text = "\n".join(lines)
    print(text)
    if out:
        (ROOT / out).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / out).write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evaluation/results/live_check.md")
    asyncio.run(main(ap.parse_args().out))
