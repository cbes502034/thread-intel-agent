"""判定正確率評測。

對資料集的每個案例:組出與上線時一模一樣的判定提示(含 RAG 檢索),
讓指定模型產出報告,與 rubric 標準答案比對。

指標:
- risk_accuracy   風險等級正確率(主指標,目標 ≥ 90%)
- parse_rate      結構化輸出可解析率
- retrieval_hit   RAG 檢索是否取回該案例對應的準則段落(Hit@k)
- 另輸出混淆矩陣與每個情境的正確率,錯誤案例全數存檔供分析

用法(專案根目錄):
  python -m evaluation.run_eval --model qwen2.5:1.5b --split val
  python -m evaluation.run_eval --model threat-intel-judge --split test --out evaluation/results/judge_test.json
選項:--limit N 只跑前 N 筆;--no-rag 不帶參考準則(對照)
"""
import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import ollama

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import LLM_NUM_CTX, OLLAMA_HOST, RAG_TOP_K, REPORT_SCHEMA  # noqa: E402
from evidence import query_text  # noqa: E402
from judge import build_judge_messages, parse_report  # noqa: E402
from rag.retriever import Retriever  # noqa: E402

LEVELS = ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def load_cases(split, limit=None):
    path = ROOT / "dataset" / f"cases_{split}.jsonl"
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return cases[:limit] if limit else cases


def evaluate(model, split, limit=None, use_rag=True, out=None, progress_every=20):
    cases = load_cases(split, limit)
    client = ollama.Client(host=OLLAMA_HOST)
    retriever = Retriever() if use_rag else None

    n_ok = n_parse = n_hit = 0
    confusion = defaultdict(Counter)       # gold → predicted
    by_scenario = defaultdict(lambda: [0, 0])
    errors = []
    t0 = time.time()

    for i, case in enumerate(cases, 1):
        ev, gold = case["evidence"], case["gold"]["risk_level"]
        refs = retriever.search_sync(query_text(ev), ev["facts"]["type"], k=RAG_TOP_K) if retriever else []
        if refs and case["expected_chunk"] in [r["id"] for r in refs]:
            n_hit += 1
        resp = client.chat(model=model, messages=build_judge_messages(ev, refs),
                           format=REPORT_SCHEMA,
                           options={"temperature": 0, "num_ctx": LLM_NUM_CTX, "seed": 42, "num_predict": 900})
        report = parse_report(resp.message.content)
        pred = report["risk_level"] if report else "PARSE_FAIL"
        if report:
            n_parse += 1
        ok = pred == gold
        n_ok += ok
        confusion[gold][pred] += 1
        by_scenario[case["scenario"]][0] += ok
        by_scenario[case["scenario"]][1] += 1
        if not ok:
            errors.append({"id": case["id"], "target": ev["target"], "gold": gold, "pred": pred,
                           "rule": case["rule"],
                           "summary": (report or {}).get("summary", "")[:200],
                           "refs": [r["id"] for r in refs]})
        if i % progress_every == 0:
            print(f"  [{i}/{len(cases)}] 正確率 {n_ok/i:.1%}（{time.time()-t0:.0f}s）", flush=True)

    n = len(cases)
    result = {
        "model": model, "split": split, "n": n, "rag": use_rag,
        "risk_accuracy": round(n_ok / n, 4),
        "parse_rate": round(n_parse / n, 4),
        "retrieval_hit": round(n_hit / n, 4) if use_rag else None,
        "seconds": round(time.time() - t0, 1),
        "confusion": {g: dict(c) for g, c in sorted(confusion.items())},
        "by_scenario": {s: f"{a}/{b}" for s, (a, b) in sorted(by_scenario.items())},
        "errors": errors,
    }
    if out:
        out_path = ROOT / out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n模型 {model}｜{split} {n} 筆｜RAG={'開' if use_rag else '關'}")
    print(f"risk_accuracy = {result['risk_accuracy']:.1%}   parse_rate = {result['parse_rate']:.1%}"
          + (f"   retrieval_hit = {result['retrieval_hit']:.1%}" if use_rag else ""))
    print("混淆矩陣(列=標準答案 → 行=模型判定):")
    for g in LEVELS:
        if g in result["confusion"]:
            print(f"  {g:8s} → {result['confusion'][g]}")
    worst = sorted(by_scenario.items(), key=lambda kv: kv[1][0] / kv[1][1])[:5]
    print("最弱情境:", ", ".join(f"{s} {a}/{b}" for s, (a, b) in worst))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--split", default="val", choices=["train", "val", "test"])
    ap.add_argument("--limit", type=int)
    ap.add_argument("--no-rag", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    evaluate(args.model, args.split, args.limit, not args.no_rag, args.out)
