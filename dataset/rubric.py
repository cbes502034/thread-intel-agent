"""標註準則（金標準）：把精簡證據對應到風險等級，並產生標準答案報告。

這份準則同時寫成自然語言放在 rag/knowledge/（給模型檢索），
這裡是同一套規則的程式版，用來：
1. 替模擬案例標註正確答案（訓練資料、測試資料）
2. 評測時判斷模型輸出對不對
評測準確率的意思是「模型判斷與本準則一致的比例」，不是真實世界的偵測率。
"""

LEVEL_ZH = {"HIGH": "高風險", "MEDIUM": "中風險", "LOW": "低風險", "UNKNOWN": "無法判定"}

# 每條規則對應知識庫中「應該被檢索到」的段落（評測檢索命中率用）
RULE_TO_CHUNK = {
    "IP_UNKNOWN_SPECIAL": "special_ranges#overview",
    "IP_UNKNOWN_NODATA": "ip_rules#unknown",
    "IP_LOW_WHITELIST": "ip_rules#whitelist",
    "IP_HIGH": "ip_rules#high",
    "IP_MEDIUM": "ip_rules#medium",
    "IP_MEDIUM_TOR": "tor_hosting#tor",
    "IP_LOW": "ip_rules#low",
    "DOM_UNKNOWN_NODATA": "domain_rules#unknown",
    "DOM_LOW_POPULAR": "domain_rules#popular",
    "DOM_HIGH": "domain_rules#high",
    "DOM_MEDIUM": "domain_rules#medium",
    "DOM_MEDIUM_NRD": "whois_domain_age#age",
    "DOM_LOW": "domain_rules#low",
}


def _ok(sources, name):
    s = sources.get(name)
    return s if (s and "error" not in s) else None


def judge(evidence):
    """回傳 {"risk_level", "rule", "reasons": [...], "roles": {tool: high/medium/low}}。"""
    facts, src = evidence["facts"], evidence["sources"]
    if facts["type"] == "ip":
        return _judge_ip(facts, src)
    return _judge_domain(src)


def _judge_ip(facts, src):
    ab, vt = _ok(src, "abuseipdb_lookup"), _ok(src, "virustotal_ip_lookup")
    roles = {name: "low" for name in src}

    if not facts.get("is_public", True) or (ab and ab.get("is_public") is False):
        rng = facts.get("range") or "非公網保留位址"
        return _v("UNKNOWN", "IP_UNKNOWN_SPECIAL", [f"目標屬於{rng}，不是公網位址，外部情資不適用"], roles)

    if not ab and not vt:
        return _v("UNKNOWN", "IP_UNKNOWN_NODATA", ["AbuseIPDB 與 VirusTotal 皆無法取得資料"], roles)

    s = ab.get("abuse_confidence_score") if ab else None
    s = s if isinstance(s, (int, float)) else None
    m = vt.get("malicious", 0) if vt else None
    su = vt.get("suspicious", 0) if vt else 0
    tor = bool(ab and ab.get("is_tor"))

    if ab and ab.get("is_whitelisted") and (m is None or m <= 2):
        roles["abuseipdb_lookup"] = "high"
        r = ["AbuseIPDB 將此 IP 列於白名單（知名基礎設施）"]
        if vt:
            r.append(f"VirusTotal 僅 {m} 家引擎判定惡意，屬零星誤判範圍" if m else "VirusTotal 無引擎判定惡意")
        return _v("LOW", "IP_LOW_WHITELIST", r, roles)

    high = []
    if s is not None and s >= 75:
        high.append(f"AbuseIPDB 信心分數 {s} 達高風險門檻（≥75）")
        roles["abuseipdb_lookup"] = "high"
    if m is not None and m >= 5:
        high.append(f"VirusTotal 有 {m} 家引擎判定惡意（≥5）")
        roles["virustotal_ip_lookup"] = "high"
    if not high and s is not None and s >= 50 and m is not None and m >= 2:
        high.append(f"AbuseIPDB 信心分數 {s}（≥50）且 VirusTotal {m} 家引擎判定惡意（≥2），兩個來源互相印證")
        roles["abuseipdb_lookup"] = roles["virustotal_ip_lookup"] = "high"
    if high:
        if tor:
            high.append("且為 Tor 出口節點")
        return _v("HIGH", "IP_HIGH", high, roles)

    med, rule = [], "IP_MEDIUM"
    if s is not None and 25 <= s < 75:
        med.append(f"AbuseIPDB 信心分數 {s} 落在中風險區間（25–74）")
        roles["abuseipdb_lookup"] = "medium"
    if m is not None and 2 <= m <= 4:
        med.append(f"VirusTotal 有 {m} 家引擎判定惡意（2–4）")
        roles["virustotal_ip_lookup"] = "medium"
    if su >= 3:
        med.append(f"VirusTotal 有 {su} 家引擎判定可疑（≥3）")
        roles["virustotal_ip_lookup"] = "medium"
    if tor:
        med.append("此 IP 為 Tor 出口節點（匿名網路出口）")
        roles["abuseipdb_lookup"] = "medium"
        if len(med) == 1:
            rule = "IP_MEDIUM_TOR"
    if med:
        return _v("MEDIUM", rule, med, roles)

    low = []
    if ab:
        low.append(f"AbuseIPDB 信心分數 {s}，未達可疑門檻")
        roles["abuseipdb_lookup"] = "medium"
    if vt:
        low.append(f"VirusTotal 僅 {m} 家引擎判定惡意，屬單一引擎誤判範圍" if m else "VirusTotal 無引擎判定惡意")
        roles["virustotal_ip_lookup"] = "medium"
    return _v("LOW", "IP_LOW", low, roles)


def _judge_domain(src):
    vt, wh = _ok(src, "virustotal_domain_lookup"), _ok(src, "whois_lookup")
    roles = {name: "low" for name in src}

    if not vt:
        return _v("UNKNOWN", "DOM_UNKNOWN_NODATA", ["VirusTotal 無此網域的情資資料，缺少信譽來源"], roles)

    m, su = vt.get("malicious", 0), vt.get("suspicious", 0)
    threat = vt.get("threat_categories") or []
    rank = vt.get("popularity_rank_best")
    age = wh.get("domain_age_days") if wh and wh.get("domain_age_days") is not None else vt.get("domain_age_days")
    age_src = "whois_lookup" if (wh and wh.get("domain_age_days") is not None) else "virustotal_domain_lookup"

    if rank is not None and rank <= 10000 and m <= 2 and not threat:
        roles["virustotal_domain_lookup"] = "high"
        r = [f"網域知名度排名 {rank}（前 1 萬名）"]
        r.append(f"VirusTotal 僅 {m} 家引擎判定惡意，屬零星誤判範圍" if m else "VirusTotal 無引擎判定惡意")
        return _v("LOW", "DOM_LOW_POPULAR", r, roles)

    high = []
    if m >= 5:
        high.append(f"VirusTotal 有 {m} 家引擎判定惡意（≥5）")
    elif m >= 2 and threat:
        high.append(f"VirusTotal {m} 家引擎判定惡意，且被歸類為 {'、'.join(threat)}")
    elif m >= 2 and age is not None and age < 30:
        high.append(f"VirusTotal {m} 家引擎判定惡意，且網域註冊僅 {age} 天")
        roles[age_src] = "high"
    if high:
        roles["virustotal_domain_lookup"] = "high"
        return _v("HIGH", "DOM_HIGH", high, roles)

    med, rule = [], "DOM_MEDIUM"
    if 2 <= m <= 4:
        med.append(f"VirusTotal 有 {m} 家引擎判定惡意（2–4）")
        roles["virustotal_domain_lookup"] = "medium"
    if threat:
        med.append(f"VirusTotal 分類含 {'、'.join(threat)}")
        roles["virustotal_domain_lookup"] = "medium"
    if su >= 3:
        med.append(f"VirusTotal 有 {su} 家引擎判定可疑（≥3）")
        roles["virustotal_domain_lookup"] = "medium"
    if age is not None and age < 30:
        med.append(f"新註冊網域（{age} 天，未滿 30 天）")
        roles[age_src] = "medium"
        if len(med) == 1:
            rule = "DOM_MEDIUM_NRD"
    if med:
        return _v("MEDIUM", rule, med, roles)

    roles["virustotal_domain_lookup"] = "medium"
    low = ["VirusTotal 僅 1 家引擎判定惡意，屬單一引擎誤判範圍" if m == 1 else "VirusTotal 無引擎判定惡意"]
    if age is not None:
        low.append(f"網域已註冊 {age} 天")
    return _v("LOW", "DOM_LOW", low, roles)


def _v(level, rule, reasons, roles):
    return {"risk_level": level, "rule": rule, "reasons": reasons, "roles": roles}


# ---------- 標準答案報告（訓練資料的 assistant 輸出） ----------

def _finding(name, s):
    if "error" in s:
        if name == "ipwhois_lookup" and "already defined" in s["error"]:
            return "此位址屬保留網段，RDAP 無公開註冊資料"
        if name == "whois_lookup" and ("No match" in s["error"] or "NotFound" in s["error"]):
            return "WHOIS 查無此網域的註冊資料"
        return f"查詢失敗（{s['error'][:60]}），無法取得資料"
    if name == "abuseipdb_lookup":
        t = (f"信心分數 {s.get('abuse_confidence_score')}，近 30 天 {s.get('total_reports')} 次檢舉"
             f"（{s.get('distinct_reporters')} 位回報者）")
        flags = []
        if s.get("is_whitelisted"):
            flags.append("列於白名單")
        if s.get("is_tor"):
            flags.append("Tor 出口節點")
        if s.get("is_public") is False:
            flags.append("非公網位址")
        if flags:
            t += "，" + "、".join(flags)
        if s.get("usage_type"):
            t += f"；用途：{s['usage_type']}"
        return t
    if name in ("virustotal_ip_lookup", "virustotal_domain_lookup"):
        total = sum(s.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
        t = f"{s.get('malicious')} 家引擎判定惡意、{s.get('suspicious')} 家可疑（共 {total} 家）"
        if s.get("reputation") is not None:
            t += f"，社群信譽 {s['reputation']}"
        if s.get("threat_categories"):
            t += f"；威脅分類：{'、'.join(s['threat_categories'])}"
        if s.get("popularity_rank_best"):
            t += f"；知名度排名 {s['popularity_rank_best']}"
        if "tor" in (s.get("tags") or []):
            t += "；標籤含 tor"
        return t
    if name == "whois_lookup":
        if s.get("creation_date"):
            t = f"註冊於 {s['creation_date']}（{s.get('domain_age_days')} 天前）"
        else:
            t = "WHOIS 未提供註冊日期"
        if s.get("registrar"):
            t += f"，註冊商 {s['registrar']}"
        if s.get("privacy_redacted"):
            t += "，註冊人資料經隱私保護"
        return t
    if name == "ipwhois_lookup":
        return f"ASN {s.get('asn')}（{s.get('asn_description')}），網段 {s.get('cidr')}"
    return "已查詢"


def _summary(level, reasons):
    body = "；".join(reasons)
    if level == "HIGH":
        return f"{body}，判定為高風險。"
    if level == "MEDIUM":
        return f"{body}，有可疑跡象但未達高風險門檻，判定為中風險。"
    if level == "LOW":
        return f"{body}，查無惡意跡象，判定為低風險。"
    return f"{body}，無法依外部情資判定風險。"


def _recommendation(level, rule, kind):
    noun = "IP" if kind == "ip" else "網域"
    if level == "HIGH":
        return f"已自動列入黑名單（30 天）；建議於防火牆或 DNS 封鎖此{noun}，並回查內部日誌是否有主機與其連線。"
    if rule == "IP_MEDIUM_TOR":
        return "此為 Tor 出口節點；若業務不需要匿名網路連入，可在防火牆限制 Tor 流量並持續監控。"
    if rule == "DOM_MEDIUM_NRD":
        return "新註冊網域，建議暫時限制存取，7 天後重新分析一次。"
    if level == "MEDIUM":
        return f"暫不封鎖；建議將此{noun}列入觀察、限制存取並持續監控相關連線，必要時人工複核。"
    if level == "LOW":
        return "查無異常，可正常放行，不需處置。"
    if rule == "IP_UNKNOWN_SPECIAL":
        return "此為內部或保留位址，外部情資不適用；請以內部資產清冊與防火牆、端點日誌調查來源主機。"
    return "外部情資不足以判定，請稍後重新分析或由人工查證。"


def gold_report(evidence, verdict=None):
    verdict = verdict or judge(evidence)
    kind = evidence["facts"]["type"]
    items = []
    for name, s in evidence["sources"].items():
        items.append({"source": name, "finding": _finding(name, s), "confidence": verdict["roles"].get(name, "low")})
    return {
        "target_type": kind,
        "evidence": items,
        "risk_level": verdict["risk_level"],
        "summary": _summary(verdict["risk_level"], verdict["reasons"]),
        "sources_checked": list(evidence["sources"].keys()),
        "recommendation": _recommendation(verdict["risk_level"], verdict["rule"], kind),
    }
