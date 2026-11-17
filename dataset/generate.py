"""產生模擬案例資料集(訓練/驗證/測試)。

為什麼用模擬資料:
- 真實查詢受外部 API 額度限制(VirusTotal 免費層 4 次/分),蒐不到足夠數量
- 模擬資料能覆蓋罕見但重要的情境(門檻邊界值、查詢失敗、私有位址),
  真實資料反而大多是乾淨目標,訓練會嚴重偏斜
- 欄位結構完全依照 evidence.py 從真實 API 回應精簡後的格式(以實際抓回的
  範例為準),模型上線後看到的輸入分佈與訓練一致

每個案例 = 精簡證據(evidence)+ 依 rubric 標註的標準答案(gold)。
用法:python -m dataset.generate   → dataset/cases_{train,val,test}.jsonl
"""
import ipaddress
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dataset.rubric import RULE_TO_CHUNK, gold_report, judge  # noqa: E402
from evidence import target_facts  # noqa: E402

OUT_DIR = Path(__file__).parent
rng = random.Random(20261117)

# ---------- 擬真素材 ----------
ISPS = ["Chunghwa Telecom", "Google LLC", "Amazon.com, Inc.", "DigitalOcean, LLC", "OVH SAS",
        "Hetzner Online GmbH", "Tencent Cloud", "Akamai Technologies", "M247 Europe",
        "Contabo GmbH", "Far EasTone Telecom", "Microsoft Corporation"]
USAGE = ["Fixed Line ISP", "Data Center/Web Hosting/Transit", "Content Delivery Network",
         "Commercial", "University/College/School", "Mobile ISP"]
COUNTRIES = ["TW", "US", "DE", "NL", "RU", "CN", "FR", "GB", "JP", "KR", "VN", "BR"]
ENGINES = ["Fortinet", "Kaspersky", "BitDefender", "ESET", "Sophos", "G-Data", "Webroot",
           "CyRadar", "Lionic", "Abusix", "GreyNoise", "Criminal IP", "alphaMountain.ai",
           "Dr.Web", "VIPRE", "SOCRadar", "Synthient", "Chong Lua Dao", "AlphaSOC", "Gridinsoft"]
VERDICTS = ["malicious", "phishing", "malware", "suspicious"]
THREAT_CATS = ["phishing", "malware", "spam", "botnet", "scam", "malicious"]
OK_CATS = ["search engines", "business", "information technology", "shopping", "news and media",
           "entertainment", "education", "finance", "web hosting"]
REGISTRARS = ["GoDaddy.com, LLC", "Namecheap, Inc.", "MarkMonitor Inc.", "Gandi SAS",
              "NameSilo, LLC", "PDR Ltd.", "Alibaba Cloud Computing", "Tucows Domains Inc."]
WORDS = ["secure", "login", "update", "cloud", "mail", "pay", "verify", "account", "portal",
         "tech", "data", "shop", "news", "bank", "support", "center", "global", "net",
         "fast", "safe", "prime", "zone", "hub", "link", "soft", "app", "sys", "info"]
TLDS = [".com", ".net", ".org", ".xyz", ".top", ".shop", ".online", ".site", ".io", ".cc"]
ERRORS = ["API 回應失敗,status_code: 429", "API 回應失敗,status_code: 401",
          "API 回應失敗,status_code: 503", "ConnectionError: 連線逾時"]


def rand_public_ip():
    while True:
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        if ipaddress.ip_address(ip).is_global:
            return ip


def rand_private_ip():
    return rng.choice([
        f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        f"192.168.{rng.randint(0,255)}.{rng.randint(1,254)}",
        f"172.{rng.randint(16,31)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "127.0.0.1", "169.254.10.20", "100.64.3.7", "192.0.2.15", "0.0.0.0",
    ])


def rand_domain():
    n = rng.randint(1, 3)
    name = "-".join(rng.sample(WORDS, n)) + (str(rng.randint(2, 99)) if rng.random() < 0.2 else "")
    return name + rng.choice(TLDS)


def flagged(n):
    n = min(n, 6)
    return [f"{e}:{rng.choice(VERDICTS)}" for e in rng.sample(ENGINES, max(0, n))]


def vt_stats(m, su):
    total = rng.randint(88, 95)
    harmless = rng.randint(40, 70)
    return {"malicious": m, "suspicious": su,
            "harmless": max(0, min(harmless, total - m - su)),
            "undetected": max(0, total - m - su - min(harmless, total - m - su))}


def abuse_src(score, *, tor=False, white=False, public=True, reports=None):
    return {
        "abuse_confidence_score": score,
        "total_reports": reports if reports is not None else (
            rng.randint(20, 300) if score >= 25 or white else rng.randint(0, 15)),
        "distinct_reporters": rng.randint(1, 60),
        "last_reported_days_ago": rng.randint(0, 29) if score > 0 or white else None,
        "is_whitelisted": white,
        "is_tor": tor,
        "is_public": public,
        "usage_type": "Reserved" if not public else rng.choice(USAGE),
        "isp": None if not public else rng.choice(ISPS),
        "country": None if not public else rng.choice(COUNTRIES),
    }


def vt_ip_src(m, su=0, *, tor=False, rep=None):
    s = vt_stats(m, su)
    s.update({
        "reputation": rep if rep is not None else (rng.randint(-40, 5) if m >= 5 else rng.randint(-5, 90)),
        "flagged_by": flagged(m + (1 if su else 0)),
        "tags": (["tor"] if tor else []) + (["suspicious-udp"] if rng.random() < 0.4 else []),
        "as_owner": rng.choice(ISPS),
        "country": rng.choice(COUNTRIES),
    })
    return s


def ipwhois_src():
    return {
        "asn": str(rng.randint(1000, 400000)),
        "asn_description": f"{rng.choice(ISPS).upper().split(',')[0]}, {rng.choice(COUNTRIES)}",
        "asn_country": rng.choice(COUNTRIES),
        "network_name": rng.choice(["NET-A", "CLOUDNET", "HOSTPOOL", "DCNET", "EDGE-01"]),
        "cidr": f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.0/24",
    }


def vt_dom_src(m, su=0, *, cats=None, rank=None, age=None):
    s = vt_stats(m, su)
    threat = [c for c in (cats or []) if any(k in c for k in THREAT_CATS)]
    s.update({
        "reputation": rng.randint(-20, 20) if m else rng.randint(0, 500),
        "categories": (cats or [])[:5],
        "threat_categories": threat[:3],
        "popularity_rank_best": rank,
        "creation_date": None,
        "domain_age_days": age,
        "registrar": rng.choice(REGISTRARS),
        "flagged_by": flagged(m + (1 if su else 0)),
        "tags": [],
    })
    return s


def whois_src(age):
    return {
        "registrar": rng.choice(REGISTRARS),
        "creation_date": None,
        "domain_age_days": age,
        "country": rng.choice(COUNTRIES),
        "privacy_redacted": rng.random() < 0.6,
    }


def err():
    return {"error": rng.choice(ERRORS)}


# ---------- 情境(涵蓋各規則與門檻邊界) ----------

def ip_case(scenario):
    tor = False
    if scenario == "ip_whitelist":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(0, white=True, reports=rng.randint(30, 300)),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 0, 1, 2]), rep=rng.randint(100, 600))}
    elif scenario == "ip_clean":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.choice([0, 0, 0, 3, 8, 15, 24])),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 0, 0, 1]))}
    elif scenario == "ip_high_abuse":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.choice([75, 76, 88, 95, 100]), tor=rng.random() < 0.3),
               "virustotal_ip_lookup": vt_ip_src(rng.randint(0, 20))}
    elif scenario == "ip_vt_swarm":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.randint(0, 49)),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([5, 6, 9, 14, 22]), rng.randint(0, 3))}
    elif scenario == "ip_corroborated":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.choice([50, 55, 63, 70, 74])),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([2, 3, 4]))}
    elif scenario == "ip_medium_score":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.choice([25, 26, 34, 49, 60, 74])),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 0, 1]))}
    elif scenario == "ip_medium_vt":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.randint(0, 24)),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([2, 3, 4]), rng.randint(0, 2))}
    elif scenario == "ip_suspicious":
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.randint(0, 24)),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 1]), rng.choice([3, 4, 6]))}
    elif scenario == "ip_tor":
        tor = True
        src = {"ipwhois_lookup": ipwhois_src(),
               "abuseipdb_lookup": abuse_src(rng.randint(0, 24), tor=True),
               "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 1]), tor=True)}
    elif scenario == "ip_private":
        ip = rand_private_ip()
        return ip, {"ipwhois_lookup": {"error": f"IPDefinedError: IPv4 address {ip} is already defined as Private-Use Networks via RFC 1918."},
                    "abuseipdb_lookup": abuse_src(0, public=False, reports=rng.randint(0, 150)),
                    "virustotal_ip_lookup": vt_ip_src(0, rng.choice([0, 1]))}
    elif scenario == "ip_all_error":
        src = {"ipwhois_lookup": ipwhois_src() if rng.random() < 0.5 else err(),
               "abuseipdb_lookup": err(), "virustotal_ip_lookup": err()}
    elif scenario == "ip_one_error":
        if rng.random() < 0.5:
            src = {"ipwhois_lookup": ipwhois_src(), "abuseipdb_lookup": err(),
                   "virustotal_ip_lookup": vt_ip_src(rng.choice([0, 1, 3, 5, 8]))}
        else:
            src = {"ipwhois_lookup": ipwhois_src(),
                   "abuseipdb_lookup": abuse_src(rng.choice([0, 10, 30, 60, 80, 100])),
                   "virustotal_ip_lookup": err()}
    else:
        raise ValueError(scenario)
    if tor or (src.get("abuseipdb_lookup", {}).get("is_tor")):
        src["abuseipdb_lookup"]["usage_type"] = "Data Center/Web Hosting/Transit"
    return rand_public_ip(), src


def domain_case(scenario):
    d = rand_domain()
    if scenario == "dom_popular":
        src = {"whois_lookup": whois_src(rng.randint(2000, 10000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 0, 1, 2]), cats=rng.sample(OK_CATS, 2),
                                                      rank=rng.choice([1, 37, 480, 2100, 9800, 10000]),
                                                      age=rng.randint(2000, 10000))}
    elif scenario == "dom_clean":
        src = {"whois_lookup": whois_src(rng.randint(31, 8000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 0, 0, 1]), cats=rng.sample(OK_CATS, 1),
                                                      rank=rng.choice([None, None, 250000, 800000]),
                                                      age=rng.randint(31, 8000))}
    elif scenario == "dom_nrd_clean":
        age = rng.choice([0, 1, 3, 7, 14, 21, 29])
        src = {"whois_lookup": whois_src(age),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 0, 1]), age=age)}
    elif scenario == "dom_nrd_bad":
        age = rng.choice([1, 5, 12, 25, 29])
        src = {"whois_lookup": whois_src(age),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([2, 3, 4]), age=age)}
    elif scenario == "dom_phish":
        src = {"whois_lookup": whois_src(rng.randint(5, 700)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([2, 3, 4]),
                                                      cats=[rng.choice(THREAT_CATS)] + rng.sample(OK_CATS, 1),
                                                      age=rng.randint(31, 700))}
    elif scenario == "dom_swarm":
        src = {"whois_lookup": whois_src(rng.randint(10, 3000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([5, 5, 7, 11, 19]), rng.randint(0, 4),
                                                      cats=[rng.choice(THREAT_CATS)] if rng.random() < 0.6 else None,
                                                      age=rng.randint(10, 3000))}
    elif scenario == "dom_medium":
        src = {"whois_lookup": whois_src(rng.randint(31, 4000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([2, 3, 4]), age=rng.randint(31, 4000))}
    elif scenario == "dom_cat_only":
        src = {"whois_lookup": whois_src(rng.randint(31, 4000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 1]),
                                                      cats=[rng.choice(THREAT_CATS)],
                                                      age=rng.randint(31, 4000))}
    elif scenario == "dom_suspicious":
        src = {"whois_lookup": whois_src(rng.randint(31, 4000)),
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 1]), rng.choice([3, 4, 7]),
                                                      age=rng.randint(31, 4000))}
    elif scenario == "dom_vt_404":
        src = {"whois_lookup": whois_src(rng.randint(10, 2000)) if rng.random() < 0.3 else
               {"error": f'WhoisDomainNotFoundError: No match for "{d.upper()}".'},
               "virustotal_domain_lookup": {"error": f'API 回應失敗,status_code: 404'}}
    elif scenario == "dom_whois_err":
        src = {"whois_lookup": {"error": rng.choice(ERRORS)},
               "virustotal_domain_lookup": vt_dom_src(rng.choice([0, 1, 2, 3, 6]),
                                                      age=rng.choice([None, 10, 100, 900]))}
    else:
        raise ValueError(scenario)
    return d, src


IP_SCENARIOS = {"ip_whitelist": 40, "ip_clean": 55, "ip_high_abuse": 45, "ip_vt_swarm": 40,
                "ip_corroborated": 35, "ip_medium_score": 45, "ip_medium_vt": 40,
                "ip_suspicious": 30, "ip_tor": 40, "ip_private": 40, "ip_all_error": 25,
                "ip_one_error": 35}
DOM_SCENARIOS = {"dom_popular": 40, "dom_clean": 50, "dom_nrd_clean": 40, "dom_nrd_bad": 35,
                 "dom_phish": 40, "dom_swarm": 40, "dom_medium": 35, "dom_cat_only": 30,
                 "dom_suspicious": 30, "dom_vt_404": 30, "dom_whois_err": 30}


def build_all():
    cases, seen = [], set()
    for scen, n in {**IP_SCENARIOS, **DOM_SCENARIOS}.items():
        maker = ip_case if scen.startswith("ip_") else domain_case
        for i in range(n):
            target, src = maker(scen)
            while target in seen:
                target, src = maker(scen)
            seen.add(target)
            ev = {"target": target, "facts": target_facts(target), "sources": src}
            verdict = judge(ev)
            cases.append({
                "id": f"{scen}_{i:03d}",
                "scenario": scen,
                "evidence": ev,
                "gold": gold_report(ev, verdict),
                "rule": verdict["rule"],
                "reasons": verdict["reasons"],
                "expected_chunk": RULE_TO_CHUNK[verdict["rule"]],
            })
    return cases


def split(cases):
    by_scen = {}
    for c in cases:
        by_scen.setdefault(c["scenario"], []).append(c)
    train, val, test = [], [], []
    for scen, group in sorted(by_scen.items()):
        rng.shuffle(group)
        n = len(group)
        n_test, n_val = max(3, int(n * 0.2)), max(2, int(n * 0.1))
        test += group[:n_test]
        val += group[n_test:n_test + n_val]
        train += group[n_test + n_val:]
    for part in (train, val, test):
        rng.shuffle(part)
    return train, val, test


def main():
    cases = build_all()
    train, val, test = split(cases)
    for name, part in [("train", train), ("val", val), ("test", test)]:
        path = OUT_DIR / f"cases_{name}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for c in part:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        dist = {}
        for c in part:
            dist[c["gold"]["risk_level"]] = dist.get(c["gold"]["risk_level"], 0) + 1
        print(f"{name}: {len(part)} 筆 {dict(sorted(dist.items()))} → {path.name}")


if __name__ == "__main__":
    main()
