"""API 層的整合測試。

不連資料庫、不打外部 API、不呼叫 LLM —— app.state 上的 collection 換成
假物件,Agent 換成假實作,驗證的是路由層自己的行為。
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import routers.analyses as analyses_module
import utils
from conftest import FakeCollection
from main import app

ADMIN_KEY = "test-admin-key"


class FakeAI:
    """代替真的 Agent,回傳固定的報告。"""

    risk_level = "LOW"

    def __init__(self, target, cache_collection, tool_calls_collection):
        self.user = target
        self.analysis_id = "ana_20260820_test01"
        self.now = datetime.now(timezone.utc)
        self.duration_ms = 1234
        self.iterations = 2
        self.tool_calls_count = 3
        self.input_tokens = 2500
        self.output_tokens = 500
        self.cache_hits = 2
        self.stopped_reason = "submitted"

    async def run(self):
        return {
            "target_type": "ip",
            "risk_level": type(self).risk_level,
            "summary": "測試摘要",
            "evidence": [],
            "sources_checked": ["abuseipdb_lookup"],
            "recommendation": "無需處理",
        }


@pytest.fixture
def client(monkeypatch):
    app.state.analyses = FakeCollection("analyses")
    app.state.blocklist = FakeCollection("blocklist")
    app.state.cache = FakeCollection("cache")
    app.state.tool_calls = FakeCollection("tool_calls")
    app.state.rate_limits = FakeCollection("rate_limits")

    monkeypatch.setattr(utils, "ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setattr(analyses_module, "AI", FakeAI)
    FakeAI.risk_level = "LOW"

    # 刻意不使用 `with TestClient(...)`:那會觸發 lifespan,進而去連真的 MongoDB。
    # app.state 上面已經換成假的 collection 了。
    return TestClient(app)


# ------------------------------------------------------------------ 輸入驗證
@pytest.mark.parametrize(
    "bad_target", ["185", "185.", "123.456.123.456", "localhost:8000", "192.168.1.1"]
)
def test_invalid_target_is_rejected_before_the_agent_runs(client, bad_target):
    response = client.post("/api/v1/analyses", json={"target": bad_target})
    assert response.status_code == 422
    assert client.app.state.analyses.docs == [], "不該產生任何分析紀錄"


def test_unknown_body_field_is_rejected(client):
    response = client.post(
        "/api/v1/analyses", json={"target": "8.8.8.8", "sneaky": "x"}
    )
    assert response.status_code == 422


def test_valid_target_is_normalized(client):
    response = client.post(
        "/api/v1/analyses", json={"target": "  HTTPS://Example.COM/path  "}
    )
    assert response.status_code == 201
    assert response.json()["target"] == "example.com"


def test_metadata_reports_real_numbers(client):
    """舊版 cache_hits 寫死 0,token 也只算最後一輪。"""
    response = client.post("/api/v1/analyses", json={"target": "8.8.8.8"})
    metadata = response.json()["metadata"]
    assert metadata["cache_hits"] == 2
    assert metadata["input_tokens"] == 2500
    assert metadata["output_tokens"] == 500


# ------------------------------------------------------------------ 限流
def test_per_ip_rate_limit(client, monkeypatch):
    import ratelimit

    monkeypatch.setattr(ratelimit, "RATE_LIMIT_PER_IP", 2)

    assert client.post("/api/v1/analyses", json={"target": "8.8.8.8"}).status_code == 201
    assert client.post("/api/v1/analyses", json={"target": "8.8.4.4"}).status_code == 201

    blocked = client.post("/api/v1/analyses", json={"target": "1.1.1.1"})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_global_daily_budget(client, monkeypatch):
    import ratelimit

    monkeypatch.setattr(ratelimit, "DAILY_ANALYSIS_BUDGET", 1)

    assert client.post("/api/v1/analyses", json={"target": "8.8.8.8"}).status_code == 201
    blocked = client.post("/api/v1/analyses", json={"target": "8.8.4.4"})
    assert blocked.status_code == 429


# ------------------------------------------------------------------ 黑名單
def test_high_risk_adds_to_blocklist_and_downgrade_removes_it(client):
    FakeAI.risk_level = "HIGH"
    client.post("/api/v1/analyses", json={"target": "185.220.101.42"})
    assert client.get("/api/v1/blocklist/check/185.220.101.42").json()["blocked"] is True

    # 同一個目標後來被判為 MEDIUM,黑名單應該跟著放掉。
    # 線上資料就是卡在這裡:第一次 HIGH 之後三次 MEDIUM,紀錄卻一直留著。
    FakeAI.risk_level = "MEDIUM"
    client.post("/api/v1/analyses", json={"target": "185.220.101.42"})
    assert client.get("/api/v1/blocklist/check/185.220.101.42").json()["blocked"] is False


def test_expired_entries_are_not_blocked(client):
    """舊版查詢完全沒有比對 expires_at,寫進去的東西會永遠有效。"""
    now = datetime.now(timezone.utc)
    client.app.state.blocklist.docs.append({
        "target": "1.2.3.4",
        "target_type": "ip",
        "reason": "過期的紀錄",
        "risk_level": "HIGH",
        "added_by": "agent",
        "added_at": now - timedelta(days=60),
        "expires_at": now - timedelta(days=30),
    })

    assert client.get("/api/v1/blocklist/check/1.2.3.4").json()["blocked"] is False
    assert client.get("/api/v1/blocklist").json()["total"] == 0


def test_blocklist_check_rejects_garbage(client):
    assert client.get("/api/v1/blocklist/check/not-a-target").status_code == 400


def test_delete_requires_admin_key(client):
    FakeAI.risk_level = "HIGH"
    client.post("/api/v1/analyses", json={"target": "185.220.101.42"})

    assert client.delete("/api/v1/blocklist/185.220.101.42").status_code == 401
    assert client.delete(
        "/api/v1/blocklist/185.220.101.42", headers={"X-API-Key": "wrong"}
    ).status_code == 401
    assert client.delete(
        "/api/v1/blocklist/185.220.101.42", headers={"X-API-Key": ADMIN_KEY}
    ).status_code == 200


def test_manual_add_requires_admin_key(client):
    payload = {"target": "9.9.9.9", "reason": "人工封鎖", "risk_level": "HIGH"}
    assert client.post("/api/v1/blocklist", json=payload).status_code == 401

    created = client.post(
        "/api/v1/blocklist", json=payload, headers={"X-API-Key": ADMIN_KEY}
    )
    assert created.status_code == 201
    assert created.json()["added_by"] == "manual"


def test_admin_endpoints_fail_closed_without_server_key(client, monkeypatch):
    """伺服器沒設定金鑰時要拒絕,而不是把端點開著。"""
    monkeypatch.setattr(utils, "ADMIN_API_KEY", None)
    response = client.delete(
        "/api/v1/blocklist/1.2.3.4", headers={"X-API-Key": "anything"}
    )
    assert response.status_code == 503


# ------------------------------------------------------------------ 列表
def test_history_is_sorted_newest_first_and_paginated(client):
    now = datetime.now(timezone.utc)
    for i in range(5):
        client.app.state.analyses.docs.append({
            "analysis_id": f"ana_{i}",
            "target": f"8.8.8.{i}",
            "target_type": "ip",
            "created_at": now - timedelta(minutes=i),
            "result": {"risk_level": "LOW", "summary": f"第 {i} 筆"},
            "metadata": {},
        })

    body = client.get("/api/v1/analyses?limit=3").json()
    assert [item["analysis_id"] for item in body["items"]] == ["ana_0", "ana_1", "ana_2"]
    assert body["limit"] == 3
    assert body["total"] == 5


# ------------------------------------------------------------------ 靜態資源
def test_frontend_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Threat Intel Agent" in response.text


def test_internal_design_doc_is_no_longer_public(client):
    """backend_contract.md 原本放在 static/,等於 21KB 的內部文件對外開放。"""
    assert client.get("/backend_contract.md").status_code == 404


def test_frontend_ships_no_api_key(client):
    body = client.get("/").text
    assert "const API_KEY" not in body
    assert "X-API-Key" not in body or "getAdminKey" in body


def test_security_headers_are_set(client):
    headers = client.get("/").headers
    assert "Content-Security-Policy" in headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_openapi_documents_the_analyze_body(client):
    """舊版用 request.json() 手動取值,/docs 上最重要的端點沒有 request schema。"""
    schema = client.get("/openapi.json").json()
    post = schema["paths"]["/api/v1/analyses"]["post"]
    assert "requestBody" in post


def test_list_survives_legacy_documents_missing_fields(client):
    client.app.state.analyses.docs.append({
        "analysis_id": "ana_legacy",
        "target": "8.8.8.8",
        "created_at": datetime.now(timezone.utc),
        # 沒有 result 欄位
    })
    response = client.get("/api/v1/analyses")
    assert response.status_code == 200
    assert response.json()["items"][0]["risk_level"] == "UNKNOWN"
