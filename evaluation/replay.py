"""把資料集的精簡證據還原成「工具原始輸出」格式，供端到端評測重播。

資料集存的是精簡後的證據；端到端評測要讓 Agent 走完整流程
（工具迴圈 → evidence.compact → RAG → 判定），所以需要還原成與真實 API
相同結構的原始回應。還原後再精簡應得到原本的證據（tests 會驗證這個來回）。
"""
from datetime import datetime, timedelta, timezone

_VENDORS = ["Forcepoint ThreatSeeker", "Sophos", "BitDefender", "alphaMountain.ai", "Webroot"]


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _results(flagged):
    out = {}
    for item in flagged or []:
        engine, _, verdict = item.partition(":")
        cat = "suspicious" if verdict == "suspicious" else "malicious"
        out[engine] = {"category": cat, "result": verdict, "method": "blacklist", "engine_name": engine}
    out.setdefault("Google Safebrowsing", {"category": "harmless", "result": "clean", "method": "blacklist",
                                           "engine_name": "Google Safebrowsing"})
    return out


def to_raw(tool, s, now=None):
    now = now or datetime.now(timezone.utc)
    if "error" in s:
        return {"error": s["error"]}
    if tool == "abuseipdb_lookup":
        days = s.get("last_reported_days_ago")
        return {
            "ipAddress": None, "isPublic": s.get("is_public"), "ipVersion": 4,
            "isWhitelisted": s.get("is_whitelisted"), "abuseConfidenceScore": s.get("abuse_confidence_score"),
            "countryCode": s.get("country"), "usageType": s.get("usage_type"), "isp": s.get("isp"),
            "domain": None, "hostnames": [], "isTor": s.get("is_tor"),
            "totalReports": s.get("total_reports"), "numDistinctUsers": s.get("distinct_reporters"),
            "lastReportedAt": _iso(now - timedelta(days=days, hours=1)) if days is not None else None,
        }
    if tool in ("virustotal_ip_lookup", "virustotal_domain_lookup"):
        attrs = {
            "last_analysis_stats": {k: s.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
            | {"timeout": 0},
            "last_analysis_results": _results(s.get("flagged_by")),
            "reputation": s.get("reputation"),
            "tags": s.get("tags") or [],
            "total_votes": {"harmless": 0, "malicious": 0},
        }
        if tool == "virustotal_ip_lookup":
            attrs.update({"as_owner": s.get("as_owner"), "country": s.get("country")})
            return {"id": "replay", "type": "ip_address", "attributes": attrs}
        cats = s.get("categories") or []
        attrs["categories"] = {_VENDORS[i % len(_VENDORS)]: c for i, c in enumerate(cats)}
        if s.get("popularity_rank_best") is not None:
            attrs["popularity_ranks"] = {"Tranco": {"rank": s["popularity_rank_best"], "timestamp": int(now.timestamp())}}
        if s.get("domain_age_days") is not None:
            attrs["creation_date"] = int((now - timedelta(days=s["domain_age_days"], hours=1)).timestamp())
        attrs["registrar"] = s.get("registrar")
        return {"id": "replay", "type": "domain", "attributes": attrs}
    if tool == "whois_lookup":
        age = s.get("domain_age_days")
        created = now - timedelta(days=age, hours=1) if age is not None else None
        return {
            "registrar": s.get("registrar"),
            "creation_date": [_iso(created)] if created else None,
            "country": s.get("country"),
            "name": "REDACTED FOR PRIVACY" if s.get("privacy_redacted") else "Domain Admin",
            "org": "REDACTED FOR PRIVACY" if s.get("privacy_redacted") else None,
        }
    if tool == "ipwhois_lookup":
        return {
            "asn": s.get("asn"), "asn_description": s.get("asn_description"),
            "asn_country_code": s.get("asn_country"), "asn_cidr": s.get("cidr"),
            "network": {"name": s.get("network_name"), "cidr": s.get("cidr")},
        }
    raise ValueError(tool)


def replay_tools(evidence, now=None):
    """回傳可直接塞進 AI(tool_funcs=...) 的重播工具表：呼叫哪個工具就給該工具的錄製結果。"""
    from agent import TOOL_FUNCS

    def make(name):
        async def fn(target, collection):
            src = evidence["sources"].get(name)
            raw = to_raw(name, src, now) if src else {"error": "API 回應失敗,status_code: 503"}
            return raw, False, 5
        return fn

    return {name: (make(name), kind) for name, (_, kind) in TOOL_FUNCS.items()}
