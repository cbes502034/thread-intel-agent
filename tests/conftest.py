"""測試用的假 MongoDB collection。

只實作這個專案實際會用到的操作,足以讓快取與 Agent 的邏輯在沒有資料庫、
沒有外部 API 的情況下被測到。
"""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _matches(doc: dict, query: dict) -> bool:
    for key, condition in query.items():
        value = doc.get(key)
        if isinstance(condition, dict):
            for op, operand in condition.items():
                if op == "$gt" and not (value is not None and value > operand):
                    return False
                if op == "$gte" and not (value is not None and value >= operand):
                    return False
                if op == "$lt" and not (value is not None and value < operand):
                    return False
        elif value != condition:
            return False
    return True


class FakeCursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        self._docs = sorted(
            self._docs,
            key=lambda d: (d.get(key) is None, d.get(key)),
            reverse=direction == -1,
        )
        return self

    def skip(self, n):
        self._docs = self._docs[n:]
        return self

    def limit(self, n):
        self._docs = self._docs[:n]
        return self

    async def to_list(self, length=None):
        return list(self._docs[:length] if length else self._docs)


class FakeCollection:
    def __init__(self, name="fake"):
        self.name = name
        self.docs: list[dict] = []

    async def find_one(self, query):
        return next((d for d in self.docs if _matches(d, query)), None)

    def find(self, query=None):
        query = query or {}
        return FakeCursor([d for d in self.docs if _matches(d, query)])

    async def insert_one(self, doc):
        self.docs.append(dict(doc))
        return type("Result", (), {"inserted_id": len(self.docs)})()

    async def update_one(self, query, update, upsert=False):
        existing = next((d for d in self.docs if _matches(d, query)), None)
        if existing is not None:
            existing.update(update.get("$set", {}))
            return type("Result", (), {"matched_count": 1, "upserted_id": None})()
        if upsert:
            new_doc = dict(query)
            new_doc.update(update.get("$set", {}))
            self.docs.append(new_doc)
            return type("Result", (), {"matched_count": 0, "upserted_id": 1})()
        return type("Result", (), {"matched_count": 0, "upserted_id": None})()

    async def delete_one(self, query):
        for i, doc in enumerate(self.docs):
            if _matches(doc, query):
                self.docs.pop(i)
                return type("Result", (), {"deleted_count": 1})()
        return type("Result", (), {"deleted_count": 0})()

    async def count_documents(self, query):
        return len([d for d in self.docs if _matches(d, query)])

    async def create_index(self, keys, **options):
        return "index"


@pytest.fixture
def collection():
    return FakeCollection("cache")


@pytest.fixture
def now():
    return datetime.now(timezone.utc)
