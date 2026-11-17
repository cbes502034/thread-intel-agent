"""RAG 檢索：依目標型別過濾段落，再用餘弦相似度取前 k 名。

段落只有數十個，直接在記憶體算內積即可，不需要額外的向量資料庫。
"""
import json
import logging
import math
from pathlib import Path

import ollama

from config import EMBED_MODEL, OLLAMA_HOST

INDEX_PATH = Path(__file__).parent / "index" / "kb_index.json"
log = logging.getLogger(__name__)


class Retriever:
    def __init__(self, index_path=INDEX_PATH, host=OLLAMA_HOST, embed_model=EMBED_MODEL):
        data = json.loads(Path(index_path).read_text(encoding="utf-8"))
        if data.get("embed_model") != embed_model:
            raise ValueError(f"索引是用 {data.get('embed_model')} 建的，與設定的 {embed_model} 不同，請重跑 python -m rag.build_index")
        self.embed_model = embed_model
        self.chunks = data["chunks"]
        self.kb_hash = data.get("kb_hash")
        self.host = host
        self._async = None
        self._sync = None

    @staticmethod
    def _normalize(v):
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / n for x in v]

    def _rank(self, qvec, target_type, k):
        scored = []
        for c in self.chunks:
            if c["applies_to"] not in (target_type, "both"):
                continue
            score = sum(a * b for a, b in zip(qvec, c["vector"]))
            scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"id": c["id"], "title": c["title"], "heading": c["heading"], "text": c["text"],
                 "score": round(s, 4)} for s, c in scored[:k]]

    async def search(self, query, target_type, k=3):
        if self._async is None:
            self._async = ollama.AsyncClient(host=self.host)
        resp = await self._async.embed(model=self.embed_model, input=query)
        return self._rank(self._normalize(resp["embeddings"][0]), target_type, k)

    def search_sync(self, query, target_type, k=3):
        if self._sync is None:
            self._sync = ollama.Client(host=self.host)
        resp = self._sync.embed(model=self.embed_model, input=query)
        return self._rank(self._normalize(resp["embeddings"][0]), target_type, k)


_default = None


def get_retriever():
    """應用程式共用一個 Retriever；索引不存在時回傳 None（系統改走無 RAG 模式）。"""
    global _default
    if _default is None:
        try:
            _default = Retriever()
        except FileNotFoundError:
            log.warning("找不到 RAG 索引 %s，本次不使用 RAG", INDEX_PATH)
            return None
    return _default
