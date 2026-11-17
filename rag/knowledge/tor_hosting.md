---
title: Tor 出口節點與主機代管網段
applies_to: ip
sources: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-183a
---

## Tor 出口節點 {#tor}
is_tor = true 代表此 IP 是 Tor 匿名網路的出口節點，流量來源無法追溯。美國 CISA 與 FBI 的公告（AA20-183A）指出攻擊者常利用 Tor 隱藏身分，但也有合法使用者，應依業務需要評估限制方式。本系統規則：Tor 出口節點至少為 MEDIUM；若 AbuseIPDB 信心分數 ≥ 75 或 VirusTotal 惡意引擎數 ≥ 5，則為 HIGH。

## 主機代管與雲端網段 {#hosting}
usage_type 為 Data Center/Web Hosting/Transit 或 ASN 屬於雲端業者（AWS、Google Cloud、Azure、DigitalOcean、OVH、Hetzner 等）時，代表伺服器而非一般用戶。掃描器與惡意伺服器常出現在這類網段，但雲端 IP 會重複分配，判定仍以信心分數與引擎數為準，不能只因為是雲端就提高風險。
