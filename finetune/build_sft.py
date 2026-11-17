"""把資料集組成 SFT 訓練樣本(chat 格式 JSONL)。

關鍵:訓練樣本的提示與上線時一字不差——同一個 build_judge_messages、
同一個 RAG 檢索(含訊號詞查詢句)。訓練/推論分佈一致,微調效果才會轉移。

輸出:finetune/sft_{train,val}.jsonl,每行 {"id","messages":[...]}
messages = [system, user, assistant(gold JSON)]
用法:python -m finetune.build_sft
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import RAG_TOP_K  # noqa: E402
from evidence import query_text  # noqa: E402
from judge import build_judge_messages  # noqa: E402
from rag.retriever import Retriever  # noqa: E402

OUT = Path(__file__).parent


def main():
    retriever = Retriever()
    for split in ("train", "val"):
        cases = [json.loads(line) for line in
                 (ROOT / "dataset" / f"cases_{split}.jsonl").read_text(encoding="utf-8").splitlines()]
        t0, rows, hit = time.time(), [], 0
        for c in cases:
            ev = c["evidence"]
            refs = retriever.search_sync(query_text(ev), ev["facts"]["type"], k=RAG_TOP_K)
            hit += c["expected_chunk"] in [r["id"] for r in refs]
            messages = build_judge_messages(ev, refs)
            gold = json.dumps(c["gold"], ensure_ascii=False, separators=(",", ":"))
            rows.append({"id": c["id"], "messages": messages + [{"role": "assistant", "content": gold}]})
        path = OUT / f"sft_{split}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{split}: {len(rows)} 筆,檢索命中 {hit/len(rows):.1%},{time.time()-t0:.0f}s → {path.name}")


if __name__ == "__main__":
    main()
