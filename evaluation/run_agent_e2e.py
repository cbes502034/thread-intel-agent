"""端到端評測：真的跑完整 Agent（查證模型選工具 → 精簡證據 → RAG → 判定模型），
只有「外部 API」換成重播資料集的證據，資料庫換成記憶體版。

量測：
- e2e_accuracy        最終風險等級 vs 資料集標準答案
- judge_accuracy      最終風險等級 vs「依 Agent 實際蒐到的證據重算的標準答案」
                      （兩者差距 = 查證階段少查/查錯工具造成的損失）
- tool_recall         查證模型「自己」呼叫到該查工具的比例（不含系統補查）
- invalid_call_rate   查證模型提出「型別不符或不存在」工具呼叫的比例
- topup_rate          需要靠必查清單補查的案例比例

用法：python -m evaluation.run_agent_e2e --per-scenario 2 --out evaluation/results/e2e_test.json
"""
import argparse
import asyncio
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import AI  # noqa: E402
from dataset.rubric import judge  # noqa: E402
from evaluation.memdb import MemCollection  # noqa: E402
from evaluation.replay import replay_tools  # noqa: E402
from evaluation.run_eval import load_cases  # noqa: E402
from evidence import applicable_tools  # noqa: E402


def pick(cases, per_scenario, seed=7):
    groups = defaultdict(list)
    for c in cases:
        groups[c["scenario"]].append(c)
    rng = random.Random(seed)
    out = []
    for scen in sorted(groups):
        out += rng.sample(groups[scen], min(per_scenario, len(groups[scen])))
    return out


async def run_case(case):
    ev = case["evidence"]
    ai = AI(ev["target"], MemCollection(), MemCollection(), tool_funcs=replay_tools(ev))
    t = time.time()
    await ai.run()
    wanted = set(applicable_tools(ev["target"]))
    pred = ai.final_report["risk_level"]
    return {
        "id": case["id"], "target": ev["target"],
        "gold_full": case["gold"]["risk_level"],
        "gold_seen": judge(ai.evidence)["risk_level"],
        "pred": pred,
        "planner_calls": ai.planner_calls,
        "tools_run": list(ai.raw_results),
        "tool_recall": len(set(ai.planner_calls) & wanted) / len(wanted),   # 查證模型自己查到的比例
        "invalid_calls": sum(1 for n in ai.planner_calls if n not in wanted),
        "topped_up": bool(ai.topped_up),
        "iterations": ai.iterations,
        "seconds": round(time.time() - t, 1),
        "summary": ai.final_report["summary"][:160],
    }


async def main(args):
    cases = pick(load_cases(args.split), args.per_scenario)
    rows = []
    for i, c in enumerate(cases, 1):
        try:
            rows.append(await run_case(c))
        except Exception as e:  # 單筆失敗也要記錄，不中斷整輪
            rows.append({"id": c["id"], "error": f"{type(e).__name__}: {e}"})
        r = rows[-1]
        print(f"[{i}/{len(cases)}] {c['id']:22s} gold={c['gold']['risk_level']:7s} "
              f"pred={r.get('pred','ERR'):7s} tools={r.get('tools_run')} {r.get('seconds','')}s", flush=True)

    ok = [r for r in rows if "error" not in r]
    n = len(ok)
    res = {
        "split": args.split, "n": len(rows), "errors": len(rows) - n,
        "e2e_accuracy": round(sum(r["pred"] == r["gold_full"] for r in ok) / n, 4),
        "judge_accuracy": round(sum(r["pred"] == r["gold_seen"] for r in ok) / n, 4),
        "tool_recall": round(sum(r["tool_recall"] for r in ok) / n, 4),
        "invalid_call_rate": round(sum(r["invalid_calls"] for r in ok) / max(1, sum(len(r["planner_calls"]) for r in ok)), 4),
        "topup_rate": round(sum(r["topped_up"] for r in ok) / n, 4),
        "avg_seconds": round(sum(r["seconds"] for r in ok) / n, 1),
        "avg_iterations": round(sum(r["iterations"] for r in ok) / n, 2),
        "rows": rows,
    }
    print({k: v for k, v in res.items() if k != "rows"})
    if args.out:
        p = ROOT / args.out
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--per-scenario", type=int, default=2)
    ap.add_argument("--out")
    asyncio.run(main(ap.parse_args()))
