---
title: AbuseIPDB 欄位解讀
applies_to: ip
sources: https://docs.abuseipdb.com/
---

## 信心分數 abuseConfidenceScore {#score}
abuse_confidence_score 介於 0 到 100，是 AbuseIPDB 依照回報內容與回報者可信度算出的「這個 IP 有多可能在濫用」。本系統呼叫 check API 時使用預設的 maxAgeInDays = 30，所以分數與檢舉次數只反映最近 30 天。分數 ≥ 75 視為高風險，25–74 為中風險，低於 25 不構成可疑。

## 檢舉次數與回報者 {#reports}
total_reports 是近 30 天的檢舉筆數，distinct_reporters 是不同回報者的人數。回報者越多越可信；但白名單 IP（例如 8.8.8.8）也可能累積大量檢舉，因此要以信心分數與白名單旗標為準，不能只看檢舉數。

## 白名單、Tor 與用途 {#flags}
is_whitelisted = true 表示 AbuseIPDB 認定為知名服務；is_tor = true 表示 Tor 出口節點；is_public = false 表示非公網位址（usage_type 會顯示 Reserved）；usage_type 說明網段用途，例如 Data Center/Web Hosting/Transit、Fixed Line ISP、Content Delivery Network。
