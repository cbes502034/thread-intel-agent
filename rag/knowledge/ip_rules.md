---
title: IP 風險判定準則
applies_to: ip
sources: https://docs.abuseipdb.com/ ; https://www.usenix.org/conference/usenixsecurity20/presentation/zhu
---

## 判定順序 {#order}
IP 依下列順序判定，命中前面的規則就不再往下看：1. 非公網位址 → UNKNOWN；2. AbuseIPDB 與 VirusTotal 都沒有資料 → UNKNOWN；3. AbuseIPDB 白名單且 VirusTotal 惡意引擎數 ≤ 2 → LOW；4. 符合高風險條件 → HIGH；5. 符合中風險條件 → MEDIUM；6. 其餘 → LOW。

## 資料不足（UNKNOWN） {#unknown}
AbuseIPDB 與 VirusTotal 兩個信譽來源都查詢失敗（例如 401、429、逾時）或沒有被查詢時，風險等級為 UNKNOWN。IPWHOIS 只提供網段與 ASN 註冊資訊，不能單獨判斷好壞。只要其中一個信譽來源有資料，就依該來源的數值判定。

## AbuseIPDB 白名單（LOW） {#whitelist}
isWhitelisted = true 代表 AbuseIPDB 認定為知名服務（例如公共 DNS、大型 CDN），這類 IP 即使 totalReports 很多，信心分數仍是 0。白名單且 VirusTotal 惡意引擎數 ≤ 2 時判定 LOW，零星引擎標記視為誤判；若 VirusTotal 惡意引擎數 ≥ 3，改依高、中風險條件判定。

## 高風險條件（HIGH） {#high}
符合任一條即為 HIGH：AbuseIPDB 信心分數 ≥ 75；VirusTotal 惡意引擎數 ≥ 5；AbuseIPDB 信心分數 ≥ 50 且 VirusTotal 惡意引擎數 ≥ 2（兩個來源互相印證）。Tor 出口節點只要符合以上任一條，一樣是 HIGH。

## 中風險條件（MEDIUM） {#medium}
未達高風險，但符合任一條即為 MEDIUM：AbuseIPDB 信心分數 25–74；VirusTotal 惡意引擎數 2–4；VirusTotal 可疑引擎數 ≥ 3；AbuseIPDB 標記為 Tor 出口節點（isTor = true）。

## 低風險（LOW） {#low}
不符合以上任何條件即為 LOW，例如 AbuseIPDB 信心分數低於 25，且 VirusTotal 惡意引擎數為 0 或 1。只有一家引擎判定惡意屬常見誤判，不足以提高風險等級。
