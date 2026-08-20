from datetime import datetime, timedelta, timezone

import pytest

from cache import get_cache, is_cacheable, make_cache_key, set_cache
from utils import iscache


async def test_miss_on_empty_collection(collection):
    hit, value = await get_cache(collection, "whois:example.com")
    assert (hit, value) == (False, None)


async def test_roundtrip(collection):
    await set_cache(collection, "whois:example.com", {"registrar": "Foo"})
    hit, value = await get_cache(collection, "whois:example.com")
    assert hit is True
    assert value == {"registrar": "Foo"}


async def test_empty_dict_still_counts_as_hit(collection):
    """舊版用 `if cache:` 判斷命中,空 dict 會被誤判成 miss 而重打外部 API。"""
    await set_cache(collection, "whois:example.com", {})
    hit, value = await get_cache(collection, "whois:example.com")
    assert hit is True
    assert value == {}


async def test_expired_entry_is_a_miss(collection):
    await collection.insert_one({
        "key": "whois:example.com",
        "value": {"registrar": "Foo"},
        "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
    })
    hit, _ = await get_cache(collection, "whois:example.com")
    assert hit is False


def test_error_results_are_not_cacheable():
    assert is_cacheable({"ok": True}) is True
    assert is_cacheable({"error": "rate limited"}) is False


def test_key_is_namespaced_by_tool():
    assert make_cache_key("whois", "example.com") == "whois:example.com"
    assert make_cache_key("virustotal_domain", "example.com") != make_cache_key(
        "whois", "example.com"
    )


async def test_iscache_does_not_persist_errors(collection):
    """一次暫時性的 429 不該把目標鎖住 24 小時。"""
    calls = []

    @iscache("abuseipdb")
    async def flaky(target, coll):
        calls.append(target)
        if len(calls) == 1:
            return {"error": "rate limited", "error_type": "rate_limited"}
        return {"abuseConfidenceScore": 0}

    first, (from_cache_1,) = await flaky("1.1.1.1", collection)
    assert from_cache_1 is False
    assert "error" in first

    second, (from_cache_2,) = await flaky("1.1.1.1", collection)
    assert from_cache_2 is False, "錯誤結果不該被快取"
    assert second == {"abuseConfidenceScore": 0}

    third, (from_cache_3,) = await flaky("1.1.1.1", collection)
    assert from_cache_3 is True, "成功結果才進快取"
    assert third == {"abuseConfidenceScore": 0}
    assert len(calls) == 2
