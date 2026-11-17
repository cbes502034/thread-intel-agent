---
title: 非公網與特殊用途位址
applies_to: ip
sources: https://www.rfc-editor.org/rfc/rfc1918 ; https://www.rfc-editor.org/rfc/rfc6890 ; https://www.rfc-editor.org/rfc/rfc6598 ; https://www.rfc-editor.org/rfc/rfc5737 ; https://www.iana.org/assignments/iana-ipv4-special-registry/
---

## 非公網位址一律為 UNKNOWN {#overview}
facts.is_public = false 的目標不是公網位址，包含 RFC 1918 私有位址（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）、迴路位址 127.0.0.0/8、鏈路本地 169.254.0.0/16、電信級 NAT 100.64.0.0/10、文件範例用 192.0.2.0/24 等。這些位址在每個內網都可能存在，外部情資的檢舉數與引擎標記不代表你的那台主機，因此風險等級一律 UNKNOWN，即使 AbuseIPDB 有檢舉紀錄也一樣。

## 非公網位址的查詢特徵 {#signals}
查詢非公網位址時，IPWHOIS 會出現「already defined as Private-Use Networks」之類的錯誤，AbuseIPDB 的 is_public 為 false、usage_type 為 Reserved，VirusTotal 的標籤可能含 private。建議改用內部資產清冊、DHCP 紀錄與防火牆日誌追查是哪一台主機。
