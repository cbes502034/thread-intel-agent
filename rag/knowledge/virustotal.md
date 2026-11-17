---
title: VirusTotal 欄位解讀
applies_to: both
sources: https://docs.virustotal.com/reference/ip-object ; https://docs.virustotal.com/reference/domains-object ; https://www.usenix.org/conference/usenixsecurity20/presentation/zhu
---

## 引擎統計 last_analysis_stats {#stats}
malicious、suspicious、harmless、undetected 分別是最近一次掃描中判定惡意、可疑、無害、未偵測的引擎數，總數約 90 家。判斷時主要看 malicious：5 家以上為高風險，2–4 家為中風險，0–1 家不構成風險；suspicious 達 3 家以上也算可疑跡象。

## 單一引擎誤判 {#false-positive}
學術研究（Zhu 等人，USENIX Security 2020）指出，「只要 1 家引擎判惡意就當惡意」是不好的門檻，引擎標記會隨時間翻轉、彼此也有相關性。因此只有 1 家引擎判定惡意時不提高風險等級，至少 2 家才算可疑。

## 分類與知名度 {#categories}
categories 是各家廠商對網域的分類（例如 search engines、phishing）；threat_categories 是其中含 phishing、malware、malicious、spam、botnet、scam、fraud 等威脅字眼的分類。popularity_rank_best 是各排名服務中最好的名次，數字越小越知名。

## 社群信譽 reputation {#reputation}
reputation 是 VirusTotal 社群投票累積的分數，正數偏向可信、負數偏向惡意。它容易受投票偏差影響，只作為輔助參考，不單獨決定風險等級。
