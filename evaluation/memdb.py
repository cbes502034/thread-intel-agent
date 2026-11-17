"""記憶體版的非同步 MongoDB collection（只實作本專案用到的方法）。

端到端評測與實測用：不連 MongoDB Atlas，避免測試資料寫進正式資料庫
（黑名單會出現在公開的 Demo 頁面上）。
"""
import copy
from types import SimpleNamespace


def _get(doc, dotted):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match(doc, flt):
    return all(_get(doc, k) == v for k, v in (flt or {}).items())


class _Cursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, key, direction=1):
        self.docs.sort(key=lambda d: _get(d, key), reverse=direction == -1)
        return self

    async def to_list(self, length=None):
        return [copy.deepcopy(d) for d in self.docs[:length]]


class MemCollection:
    def __init__(self):
        self.docs = []
        self._next = 1

    async def insert_one(self, doc):
        doc.setdefault("_id", self._next)
        self._next += 1
        self.docs.append(copy.deepcopy(doc))
        return SimpleNamespace(inserted_id=doc["_id"])

    async def find_one(self, flt=None):
        for d in self.docs:
            if _match(d, flt):
                return copy.deepcopy(d)
        return None

    def find(self, flt=None):
        return _Cursor([d for d in self.docs if _match(d, flt)])

    async def update_one(self, flt, update, upsert=False):
        for d in self.docs:
            if _match(d, flt):
                d.update(copy.deepcopy(update.get("$set", {})))
                return SimpleNamespace(matched_count=1, upserted_id=None)
        if upsert:
            new = dict(flt)
            new.update(copy.deepcopy(update.get("$set", {})))
            await self.insert_one(new)
        return SimpleNamespace(matched_count=0, upserted_id=None)

    async def delete_one(self, flt):
        for i, d in enumerate(self.docs):
            if _match(d, flt):
                del self.docs[i]
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)

    async def count_documents(self, flt=None):
        return sum(1 for d in self.docs if _match(d, flt))
