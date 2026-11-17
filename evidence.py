"""工具原始輸出 → 精簡證據（給本機 LLM 看的版本）。

外部情資 API 的原始回應很大（VirusTotal 單筆可達 2 萬字元以上），
本機小模型的上下文放不下，也容易被無關欄位干擾。這裡只抽出判斷需要的欄位，
並由程式先算好「事實型」數值（網域年齡、距上次檢舉天數、是否為公網位址），
模型只負責綜合判斷。資料庫 tool_calls 仍保存完整原始輸出，可回溯。
"""
import ipaddress
import json
import re
from datetime import datetime, timezone

IP_TOOLS = ("ipwhois_lookup", "abuseipdb_lookup", "virustotal_ip_lookup")
DOMAIN_TOOLS = ("whois_lookup", "virustotal_domain_lookup")

# VirusTotal 分類（categories）出現這些字眼即視為「威脅分類」
THREAT_KEYWORDS = (
    "phish", "malware", "malicious", "spam", "botnet", "bot network",
    "command and control", "c2", "ransomware", "scam", "fraud",
    "spyware", "compromised", "suspicious",
)

# 非公網位址對照表（依 IANA Special-Purpose Address Registry）
_SPECIAL_V4 = [
    ("10.0.0.0/8", "RFC 1918 私有位址"),
    ("172.16.0.0/12", "RFC 1918 私有位址"),
    ("192.168.0.0/16", "RFC 1918 私有位址"),
    ("127.0.0.0/8", "迴路位址（loopback）"),
    ("169.254.0.0/16", "鏈路本地位址（link-local）"),
    ("100.64.0.0/10", "電信級 NAT 共用位址（RFC 6598）"),
    ("192.0.2.0/24", "文件範例用位址（RFC 5737）"),
    ("198.51.100.0/24", "文件範例用位址（RFC 5737）"),
    ("203.0.113.0/24", "文件範例用位址（RFC 5737）"),
    ("198.18.0.0/15", "效能測試用位址（RFC 2544）"),
    ("224.0.0.0/4", "多播位址（multicast）"),
    ("0.0.0.0/8", "本網路位址（this network）"),
    ("240.0.0.0/4", "保留位址（reserved）"),
]
_SPECIAL_V6 = [
    ("::1/128", "迴路位址（loopback）"),
    ("fc00::/7", "IPv6 唯一本地位址（ULA）"),
    ("fe80::/10", "鏈路本地位址（link-local）"),
    ("2001:db8::/32", "文件範例用位址（RFC 3849）"),
    ("ff00::/8", "多播位址（multicast）"),
]


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$",
    re.IGNORECASE,
)


def validate_target(target: str):
    """輸入驗證：回傳 ("ip" | "domain", 正規化後的目標) 或 (None, 錯誤訊息)。

    在進入任何 LLM 流程之前執行,格式不對就直接拒絕,
    不浪費模型呼叫與外部 API 額度。
    """
    t = (target or "").strip().rstrip(".").lower()
    if not t:
        return None, "請輸入要分析的 IP 或網域"
    try:
        ipaddress.ip_address(t)
        return "ip", t
    except ValueError:
        pass
    if _DOMAIN_RE.match(t):
        return "domain", t
    return None, f"「{target.strip()[:60]}」不是合法的 IP 位址或網域名稱"


def target_facts(target: str) -> dict:
    """由程式判定的目標事實：型別、是否為公網位址。"""
    t = (target or "").strip()
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return {"type": "domain"}
    facts = {"type": "ip", "version": ip.version, "is_public": bool(ip.is_global)}
    if not ip.is_global:
        table = _SPECIAL_V4 if ip.version == 4 else _SPECIAL_V6
        name = next((n for net, n in table if ip in ipaddress.ip_network(net)), "非公網保留位址")
        facts["range"] = name
    return facts


def applicable_tools(target: str) -> tuple:
    return IP_TOOLS if target_facts(target)["type"] == "ip" else DOMAIN_TOOLS


# ---------- 小工具 ----------

def _to_dt(v):
    """str / datetime / epoch / list → aware datetime（list 取最早的一個）。"""
    if isinstance(v, (list, tuple)):
        dts = [d for d in (_to_dt(x) for x in v) if d]
        return min(dts) if dts else None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(v, str) and v.strip():
        s = v.strip().replace("Z", "+00:00")
        try:
            d = datetime.fromisoformat(s)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                return datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _days_between(dt, now):
    return None if dt is None else max(0, (now - dt).days)


def _short(s, n=160):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + "…"


def _attrs(raw):
    """VirusTotal 工具回傳的是 data 層（含 attributes），也容許直接給 attributes。"""
    if isinstance(raw, dict) and isinstance(raw.get("attributes"), dict):
        return raw["attributes"]
    return raw if isinstance(raw, dict) else {}


def _flagged(attrs, limit=6):
    results = attrs.get("last_analysis_results") or {}
    rows = []
    for engine, r in results.items():
        cat = (r or {}).get("category")
        if cat in ("malicious", "suspicious"):
            rows.append((0 if cat == "malicious" else 1, f"{engine}:{(r or {}).get('result') or cat}"))
    rows.sort()
    return [x for _, x in rows[:limit]]


def _vt_stats(attrs):
    st = attrs.get("last_analysis_stats") or {}
    return {k: int(st.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected")}


# ---------- 各工具精簡 ----------

def compact_abuseipdb(raw, now):
    d = raw or {}
    last = _to_dt(d.get("lastReportedAt"))
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported_days_ago": _days_between(last, now),
        "is_whitelisted": d.get("isWhitelisted"),
        "is_tor": d.get("isTor"),
        "is_public": d.get("isPublic"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "country": d.get("countryCode"),
    }


def compact_vt_ip(raw, now):
    a = _attrs(raw)
    out = _vt_stats(a)
    out.update({
        "reputation": a.get("reputation"),
        "flagged_by": _flagged(a),
        "tags": list(a.get("tags") or [])[:5],
        "as_owner": a.get("as_owner"),
        "country": a.get("country"),
    })
    return out


def compact_vt_domain(raw, now):
    a = _attrs(raw)
    cats = []
    for c in (a.get("categories") or {}).values():
        c = str(c).strip().lower()
        if c and c not in cats:
            cats.append(c)
    threat = [c for c in cats if any(k in c for k in THREAT_KEYWORDS)]
    ranks = [v.get("rank") for v in (a.get("popularity_ranks") or {}).values()
             if isinstance(v, dict) and isinstance(v.get("rank"), int)]
    created = _to_dt(a.get("creation_date"))
    out = _vt_stats(a)
    out.update({
        "reputation": a.get("reputation"),
        "categories": cats[:5],
        "threat_categories": threat[:3],
        "popularity_rank_best": min(ranks) if ranks else None,
        "creation_date": created.date().isoformat() if created else None,
        "domain_age_days": _days_between(created, now),
        "registrar": a.get("registrar"),
        "flagged_by": _flagged(a),
        "tags": list(a.get("tags") or [])[:5],
    })
    return out


def compact_whois(raw, now):
    d = raw or {}
    created = _to_dt(d.get("creation_date"))
    text = " ".join(str(d.get(k) or "") for k in ("name", "org", "address")).lower()
    return {
        "registrar": d.get("registrar"),
        "creation_date": created.date().isoformat() if created else None,
        "domain_age_days": _days_between(created, now),
        "country": d.get("country"),
        "privacy_redacted": ("redacted" in text) or ("privacy" in text),
    }


def compact_ipwhois(raw, now):
    d = raw or {}
    net = d.get("network") or {}
    return {
        "asn": d.get("asn"),
        "asn_description": d.get("asn_description"),
        "asn_country": d.get("asn_country_code"),
        "network_name": net.get("name"),
        "cidr": net.get("cidr") or d.get("asn_cidr"),
    }


_COMPACTORS = {
    "abuseipdb_lookup": compact_abuseipdb,
    "virustotal_ip_lookup": compact_vt_ip,
    "virustotal_domain_lookup": compact_vt_domain,
    "whois_lookup": compact_whois,
    "ipwhois_lookup": compact_ipwhois,
}


def compact(tool_name, raw, now=None):
    """單一工具輸出 → 精簡 dict；失敗（含例外訊息）一律轉成 {"error": ...}。"""
    now = now or datetime.now(timezone.utc)
    if isinstance(raw, dict) and "error" in raw and len(raw) <= 2:
        return {"error": _short(raw["error"])}
    if raw is None:
        return {"error": "沒有回傳資料"}
    fn = _COMPACTORS.get(tool_name)
    if fn is None:
        return {"error": f"未知工具 {tool_name}"}
    try:
        return fn(raw, now)
    except Exception as e:  # 防禦：格式異常也不要讓整次分析中斷
        return {"error": f"資料格式無法解析：{type(e).__name__}"}


def build_evidence(target, results, now=None):
    """results: {tool_name: 原始輸出}（依呼叫順序）。"""
    now = now or datetime.now(timezone.utc)
    return {
        "target": target,
        "facts": target_facts(target),
        "sources": {name: compact(name, raw, now) for name, raw in results.items()},
    }


def to_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def query_text(evidence):
    """把證據濃縮成檢索查詢句。

    除了關鍵數值,還會依證據型態補上「訊號詞」(與知識庫段落用語一致,
    例如「白名單」「Tor 出口節點」「新註冊網域」「高風險門檻」),
    讓嵌入檢索能命中對應的判定準則段落。第一版只放數值,
    與準則文字的語意距離太遠,實測命中率只有三成,加上訊號詞後才可用。
    """
    f = evidence["facts"]
    src = evidence["sources"]
    parts, signals = [], []

    def sig(*words):
        signals.extend(w for w in words if w not in signals)

    if f["type"] == "ip":
        if f.get("is_public") is False:
            parts.append(f"IP 位址（非公網：{f.get('range')}）")
            sig("非公網保留位址", "私有位址", "內部網路", "外部情資不適用")
        else:
            parts.append("公網 IP 位址")
    else:
        parts.append("網域")

    err_names = [n for n, s in src.items() if "error" in s]
    for name in err_names:
        parts.append(f"{name} 查詢失敗")
    if f["type"] == "ip" and {"abuseipdb_lookup", "virustotal_ip_lookup"} <= set(err_names):
        sig("兩個信譽來源都查詢失敗", "資料不足無法判定")
    if f["type"] == "domain" and "virustotal_domain_lookup" in err_names:
        sig("查無網域情資資料", "缺少信譽來源", "資料不足")

    ab = src.get("abuseipdb_lookup")
    if ab and "error" not in ab:
        score = ab.get("abuse_confidence_score")
        parts.append(f"AbuseIPDB 信心分數 {score}，近 30 天檢舉 {ab.get('total_reports')} 次")
        if ab.get("is_whitelisted"):
            sig("白名單", "知名服務基礎設施")
        if ab.get("is_tor"):
            sig("Tor 出口節點", "匿名網路")
        if isinstance(score, (int, float)):
            if score >= 75:
                sig("信心分數達高風險門檻")
            elif score >= 25:
                sig("信心分數落在中風險區間")
            else:
                sig("信心分數未達可疑門檻")

    for name in ("virustotal_ip_lookup", "virustotal_domain_lookup"):
        vt = src.get(name)
        if not vt or "error" in vt:
            continue
        m, su = vt.get("malicious") or 0, vt.get("suspicious") or 0
        parts.append(f"VirusTotal {m} 家引擎判定惡意、{su} 家可疑")
        if m >= 5:
            sig("多家引擎判定惡意", "高風險")
        elif m >= 2:
            sig("引擎判定惡意", "來源互相印證", "中風險")
        else:
            sig("單一引擎誤判", "查無惡意跡象")
        if su >= 3:
            sig("可疑引擎數")
        if vt.get("threat_categories"):
            parts.append("威脅分類 " + "、".join(vt["threat_categories"]))
            sig("威脅分類", "phishing", "malware")
        rank = vt.get("popularity_rank_best")
        if rank is not None and rank <= 10000:
            parts.append(f"知名度排名 {rank}")
            sig("知名網域", "排名前一萬")

    age = None
    wh = src.get("whois_lookup")
    if wh and "error" not in wh and wh.get("domain_age_days") is not None:
        age = wh["domain_age_days"]
    elif (v := src.get("virustotal_domain_lookup")) and "error" not in v and v.get("domain_age_days") is not None:
        age = v["domain_age_days"]
    if age is not None:
        parts.append(f"網域年齡 {age} 天")
        sig("新註冊網域" if age < 30 else "已註冊多時")
    if wh and "error" in wh and ("No match" in wh["error"] or "NotFound" in wh["error"]):
        sig("查無註冊資料", "網域不存在")

    return "；".join(parts) + ("。" + " ".join(signals) if signals else "")
