"""建立 RAG 知識庫索引：切塊 → Ollama 嵌入 → rag/index/kb_index.json。

用法（在專案根目錄）：python -m rag.build_index
知識庫內容改了就要重跑；索引檔記錄嵌入模型與內容雜湊，retriever 載入時會檢查。
"""
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import ollama

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import EMBED_MODEL, OLLAMA_HOST  # noqa: E402

KB_DIR = Path(__file__).parent / "knowledge"
INDEX_PATH = Path(__file__).parent / "index" / "kb_index.json"
_HEADING = re.compile(r"^##\s+(.+?)\s*\{#([\w-]+)\}\s*$")


def kb_hash():
    h = hashlib.sha256()
    for p in sorted(KB_DIR.glob("*.md")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def parse_doc(path):
    text = path.read_text(encoding="utf-8")
    meta, body = {}, text
    if text.startswith("---"):
        _, fm, body = text.split("---", 2)
        for line in fm.strip().splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    chunks, cur = [], None
    for line in body.splitlines():
        m = _HEADING.match(line)
        if m:
            cur = {"heading": m.group(1), "anchor": m.group(2), "lines": []}
            chunks.append(cur)
        elif cur is not None and line.strip():
            cur["lines"].append(line.strip())
    out = []
    for c in chunks:
        content = " ".join(c["lines"])
        out.append({
            "id": f"{path.stem}#{c['anchor']}",
            "title": meta.get("title", path.stem),
            "heading": c["heading"],
            "applies_to": meta.get("applies_to", "both"),
            "sources": [s.strip() for s in meta.get("sources", "").split(";") if s.strip()],
            "text": content,
        })
    return out


def main():
    chunks = [c for p in sorted(KB_DIR.glob("*.md")) for c in parse_doc(p)]
    client = ollama.Client(host=OLLAMA_HOST)
    inputs = [f"{c['title']}｜{c['heading']}\n{c['text']}" for c in chunks]
    vectors = client.embed(model=EMBED_MODEL, input=inputs)["embeddings"]
    for c, v in zip(chunks, vectors):
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        c["vector"] = [round(x / n, 6) for x in v]
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps({
        "embed_model": EMBED_MODEL,
        "kb_hash": kb_hash(),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "chunks": chunks,
    }, ensure_ascii=False), encoding="utf-8")
    print(f"已建立 {len(chunks)} 個段落 → {INDEX_PATH.relative_to(ROOT)}（嵌入模型 {EMBED_MODEL}，維度 {len(vectors[0])}）")


if __name__ == "__main__":
    main()
