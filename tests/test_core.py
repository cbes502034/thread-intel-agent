"""確定性元件的單元測試（不需要 Ollama、不連外部 API，幾秒內跑完）。

python -m pytest tests -q
"""
import asyncio
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dataset.rubric import gold_report, judge  # noqa: E402
from evaluation.memdb import MemCollection  # noqa: E402
from evaluation.replay import to_raw  # noqa: E402
from evidence import build_evidence, compact, target_facts, validate_target  # noqa: E402
from judge import parse_report  # noqa: E402

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


# ---------- 輸入驗證 ----------

def test_validate_target():
    assert validate_target("8.8.8.8") == ("ip", "8.8.8.8")
    assert validate_target("  Example.COM. ") == ("domain", "example.com")
    assert validate_target("2001:4860:4860::8888")[0] == "ip"
    for bad in ["", "   ", "1.2.3", "http://x.com", "not_a_target!!", "a" * 300 + ".com", "<script>"]:
        kind, msg = validate_target(bad)
        assert kind is None and msg


def test_target_facts_special_ranges():
    assert target_facts("8.8.8.8") == {"type": "ip", "version": 4, "is_public": True}
    f = target_facts("192.168.1.1")
    assert f["is_public"] is False and "RFC 1918" in f["range"]
    assert "迴路" in target_facts("127.0.0.1")["range"]
    assert target_facts("google.com") == {"type": "domain"}


# ---------- 證據精簡（以真實 API 回應的結構為準） ----------

def test_compact_real_shaped_payloads():
    vt = {"id": "8.8.8.8", "type": "ip_address", "attributes": {
        "last_analysis_stats": {"malicious": 1, "suspicious": 0, "undetected": 38, "harmless": 53, "timeout": 0},
        "last_analysis_results": {"Synthient": {"category": "malicious", "result": "malicious"},
                                  "ESET": {"category": "harmless", "result": "clean"}},
        "reputation": 566, "tags": ["suspicious-udp"], "as_owner": "Google LLC", "country": "US",
        "whois": "x" * 5000}}
    c = compact("virustotal_ip_lookup", vt, NOW)
    assert c["malicious"] == 1 and c["flagged_by"] == ["Synthient:malicious"] and "whois" not in c

    ab = {"ipAddress": "185.220.101.42", "isPublic": True, "isWhitelisted": False, "abuseConfidenceScore": 100,
          "isTor": True, "totalReports": 130, "numDistinctUsers": 48,
          "lastReportedAt": "2026-11-15T05:33:11+00:00", "usageType": "University/College/School"}
    c = compact("abuseipdb_lookup", ab, NOW)
    assert c["abuse_confidence_score"] == 100 and c["is_tor"] and c["last_reported_days_ago"] == 0

    wh = {"registrar": "MarkMonitor Inc.",
          "creation_date": [datetime(1997, 9, 15, 4), datetime(1997, 9, 15, 7)],
          "name": "REDACTED REGISTRANT", "org": "REDACTED FOR PRIVACY", "country": "US"}
    c = compact("whois_lookup", wh, NOW)
    assert c["creation_date"] == "1997-09-15" and c["domain_age_days"] > 10000 and c["privacy_redacted"]

    assert compact("abuseipdb_lookup", {"error": "API 回應失敗,status_code: 429"}) == {"error": "API 回應失敗,status_code: 429"}


# ---------- 判定準則 ----------

def ev(target, **sources):
    return {"target": target, "facts": target_facts(target), "sources": sources}


def abuse(score, **kw):
    d = {"abuse_confidence_score": score, "total_reports": 10, "distinct_reporters": 3,
         "is_whitelisted": False, "is_tor": False, "is_public": True}
    d.update(kw)
    return d


def vt(m, su=0, **kw):
    d = {"malicious": m, "suspicious": su, "harmless": 60, "undetected": 25}
    d.update(kw)
    return d


def test_rubric_ip_rules():
    assert judge(ev("8.8.8.8", abuseipdb_lookup=abuse(0, is_whitelisted=True), virustotal_ip_lookup=vt(1)))["risk_level"] == "LOW"
    assert judge(ev("185.220.101.42", abuseipdb_lookup=abuse(100, is_tor=True), virustotal_ip_lookup=vt(18)))["risk_level"] == "HIGH"
    assert judge(ev("192.168.1.1", abuseipdb_lookup=abuse(0, is_public=False), virustotal_ip_lookup=vt(3)))["risk_level"] == "UNKNOWN"
    assert judge(ev("5.6.7.8", abuseipdb_lookup={"error": "429"}, virustotal_ip_lookup={"error": "429"}))["risk_level"] == "UNKNOWN"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(60), virustotal_ip_lookup=vt(3)))["risk_level"] == "HIGH"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(30), virustotal_ip_lookup=vt(0)))["risk_level"] == "MEDIUM"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(0, is_tor=True), virustotal_ip_lookup=vt(0)))["rule"] == "IP_MEDIUM_TOR"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(10), virustotal_ip_lookup=vt(1)))["risk_level"] == "LOW"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(74), virustotal_ip_lookup=vt(1)))["risk_level"] == "MEDIUM"
    assert judge(ev("5.6.7.8", abuseipdb_lookup=abuse(75), virustotal_ip_lookup=vt(0)))["risk_level"] == "HIGH"


def test_rubric_domain_rules():
    assert judge(ev("google.com", virustotal_domain_lookup=vt(1, popularity_rank_best=1)))["risk_level"] == "LOW"
    assert judge(ev("new-shop.xyz", whois_lookup={"domain_age_days": 10}, virustotal_domain_lookup=vt(0)))["rule"] == "DOM_MEDIUM_NRD"
    assert judge(ev("new-shop.xyz", whois_lookup={"domain_age_days": 10}, virustotal_domain_lookup=vt(2)))["risk_level"] == "HIGH"
    assert judge(ev("x.com", virustotal_domain_lookup={"error": "API 回應失敗,status_code: 404"}))["risk_level"] == "UNKNOWN"
    assert judge(ev("x.com", virustotal_domain_lookup=vt(2, threat_categories=["phishing"])))["risk_level"] == "HIGH"
    assert judge(ev("x.com", virustotal_domain_lookup=vt(0, threat_categories=["spam"])))["risk_level"] == "MEDIUM"
    assert judge(ev("x.com", whois_lookup={"domain_age_days": 900}, virustotal_domain_lookup=vt(1)))["risk_level"] == "LOW"


def test_gold_report_shape():
    e = ev("185.220.101.42", abuseipdb_lookup=abuse(100, is_tor=True), virustotal_ip_lookup=vt(18))
    r = gold_report(e)
    assert r["risk_level"] == "HIGH" and r["sources_checked"] == ["abuseipdb_lookup", "virustotal_ip_lookup"]
    assert parse_report(json.dumps(r, ensure_ascii=False)) is not None


# ---------- 資料集還原 → 再精簡，要回到同一份證據 ----------

def test_replay_round_trip_preserves_labels():
    cases = [json.loads(line) for line in (ROOT / "dataset" / "cases_test.jsonl").read_text(encoding="utf-8").splitlines()]
    for c in random.Random(0).sample(cases, 60):
        e = c["evidence"]
        raw = {name: to_raw(name, s, NOW) for name, s in e["sources"].items()}
        rebuilt = build_evidence(e["target"], raw, NOW + timedelta(seconds=5))
        assert judge(rebuilt)["risk_level"] == c["gold"]["risk_level"], c["id"]


# ---------- 輸出解析 ----------

def test_parse_report_rejects_bad_output():
    assert parse_report("not json") is None
    assert parse_report(json.dumps({"risk_level": "DANGER", "target_type": "ip", "evidence": []})) is None
    ok = {"target_type": "ip", "risk_level": "LOW", "summary": "s", "evidence": [{"source": "a", "finding": "b", "confidence": "x"}],
          "sources_checked": ["a"], "recommendation": "r"}
    assert parse_report(json.dumps(ok))["evidence"][0]["confidence"] == "low"


# ---------- 快取：失敗結果不能被快取 ----------

def test_failed_lookup_is_not_cached():
    from utils import iscache

    calls = {"n": 0}

    @iscache("demo")
    async def lookup(arg, collection):
        calls["n"] += 1
        return {"error": "API 回應失敗,status_code: 429"} if calls["n"] == 1 else {"ok": True}

    col = MemCollection()

    async def run():
        r1, (hit1,) = await lookup("1.2.3.4", col)
        r2, (hit2,) = await lookup("1.2.3.4", col)
        r3, (hit3,) = await lookup("1.2.3.4", col)
        return r1, hit1, r2, hit2, r3, hit3

    r1, hit1, r2, hit2, r3, hit3 = asyncio.run(run())
    assert "error" in r1 and not hit1          # 第一次失敗
    assert r2 == {"ok": True} and not hit2     # 失敗沒被快取 → 第二次重新查詢
    assert r3 == {"ok": True} and hit3         # 成功結果才進快取
