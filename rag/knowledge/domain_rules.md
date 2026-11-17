---
title: 網域風險判定準則
applies_to: domain
sources: https://docs.virustotal.com/reference/domains-object ; https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/
---

## 判定順序 {#order}
網域依下列順序判定：1. VirusTotal 沒有資料 → UNKNOWN；2. 知名網域（排名前 1 萬）且惡意引擎數 ≤ 2、沒有威脅分類 → LOW；3. 符合高風險條件 → HIGH；4. 符合中風險條件 → MEDIUM；5. 其餘 → LOW。

## 資料不足（UNKNOWN） {#unknown}
VirusTotal 查詢失敗或回應 404（查無此網域）時為 UNKNOWN，因為缺少信譽來源。WHOIS 只提供註冊資訊，不能單獨判定好壞；WHOIS 查無註冊資料通常代表網域不存在或拼字錯誤。

## 高知名度網域（LOW） {#popular}
popularity_rank_best ≤ 10000（Tranco、Majestic、Cisco Umbrella 等排名前 1 萬），且 VirusTotal 惡意引擎數 ≤ 2、沒有威脅分類時判定 LOW。大型網站常出現 1 到 2 家引擎的零星誤判。

## 高風險條件（HIGH） {#high}
符合任一條即為 HIGH：VirusTotal 惡意引擎數 ≥ 5；惡意引擎數 ≥ 2 且 threat_categories 含威脅分類（phishing、malware、malicious、spam、botnet、scam、fraud 等）；惡意引擎數 ≥ 2 且網域年齡未滿 30 天。

## 中風險條件（MEDIUM） {#medium}
未達高風險，但符合任一條即為 MEDIUM：VirusTotal 惡意引擎數 2–4；threat_categories 不為空（有廠商把它歸類為威脅）；VirusTotal 可疑引擎數 ≥ 3；網域年齡未滿 30 天（新註冊網域）。

## 低風險（LOW） {#low}
不符合以上條件即為 LOW：VirusTotal 惡意引擎數 0 或 1、沒有威脅分類，而且網域已註冊 30 天以上。只有一家引擎判定惡意屬常見誤判。
