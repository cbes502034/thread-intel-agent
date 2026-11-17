---
title: WHOIS 與網域年齡
applies_to: domain
sources: https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/
---

## 新註冊網域 {#age}
domain_age_days 是程式依 WHOIS（或 VirusTotal）的註冊日期算出的天數。未滿 30 天稱為新註冊網域（NRD）。Palo Alto Networks Unit 42 的研究發現，新註冊網域中超過七成屬於惡意、可疑或不適合工作場所的內容，因此新網域即使沒有引擎判定惡意也列為 MEDIUM；若同時有 2 家以上引擎判定惡意則為 HIGH。

## 隱私保護與註冊商 {#privacy}
privacy_redacted = true 表示註冊人資料經隱私保護（REDACTED FOR PRIVACY），這在 GDPR 之後非常普遍，大型網站也一樣，本身不代表惡意。註冊商名稱只作為背景資訊。

## 查無註冊資料 {#notfound}
WHOIS 回應 No match 或 WhoisDomainNotFoundError，代表網域未註冊或已過期。此時通常 VirusTotal 也查無資料，風險等級為 UNKNOWN，建議確認拼字並人工查證。
