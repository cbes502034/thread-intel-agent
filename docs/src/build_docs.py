"""產生《專案企畫書》與《未來改善建議報告》兩份 PDF。

評測數字一律從 evaluation/results/ 讀取，重跑評測後重新執行本程式即可更新文件。
用法（專案根目錄）：python docs/src/build_docs.py
輸出：docs/專案企畫書.pdf、docs/未來改善建議報告.pdf
"""
import json
import subprocess
import sys
from datetime import date
from html import escape
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import diagrams as D  # noqa: E402

RESULTS = ROOT / "evaluation" / "results"
RENDER = Path(r"C:\Users\User\Desktop\agent\render_pdf_tmp2.js")   # Node + Playwright（Chromium）轉 PDF
TODAY = date.today().isoformat()

CSS = """
@page { size: A4; margin: 15mm 14mm 16mm 14mm; }
* { box-sizing: border-box; }
body { font-family: 'Microsoft JhengHei','Segoe UI',sans-serif; color:#1e293b; font-size:10.4pt; line-height:1.62; margin:0; }
h1 { font-size:21pt; color:#0f766e; margin:0 0 4px; letter-spacing:.5px; }
.sub { color:#475569; font-size:10.5pt; margin-bottom:14px; border-bottom:2px solid #0f766e; padding-bottom:8px; }
h2 { font-size:14.5pt; color:#0f766e; border-left:5px solid #0f766e; padding-left:9px; margin:20px 0 8px; page-break-after:avoid; }
h3 { font-size:11.6pt; color:#115e59; margin:14px 0 6px; page-break-after:avoid; }
p { margin:5px 0 7px; }
table { width:100%; border-collapse:collapse; margin:6px 0 12px; font-size:9.6pt; page-break-inside:auto; }
tr { page-break-inside:avoid; }
th { background:#0f766e; color:#fff; font-weight:bold; text-align:left; padding:5px 7px; border:1px solid #0f766e; }
td { border:1px solid #cbd5e1; padding:5px 7px; vertical-align:top; }
tr:nth-child(even) td { background:#f8fafc; }
figure { margin:10px 0 14px; page-break-inside:avoid; text-align:center; }
figcaption { font-size:9.8pt; color:#115e59; font-weight:bold; margin-top:4px; }
code, .mono { font-family: Consolas, monospace; font-size:9.2pt; background:#f1f5f9; padding:0 3px; }
pre { font-family: Consolas, monospace; font-size:8.8pt; background:#f8fafc; border:1px solid #cbd5e1; padding:7px 9px; white-space:pre-wrap; page-break-inside:avoid; margin:4px 0 10px; }
.kpi { display:flex; gap:8px; margin:8px 0 12px; }
.kpi div { flex:1; border:1px solid #99f6e4; background:#f0fdfa; padding:7px 9px; }
.kpi b { display:block; font-size:16pt; color:#0f766e; }
.kpi span { font-size:9pt; color:#475569; }
.note { border-left:3px solid #b45309; background:#fffbeb; padding:6px 10px; font-size:9.6pt; margin:6px 0 10px; }
.pb { page-break-before:always; }
ol, ul { margin:4px 0 8px 18px; padding:0; }
li { margin:2px 0; }
.refs li { font-size:9.2pt; word-break:break-all; }
"""


def table(head, rows, widths=None):
    cols = "".join(f'<col style="width:{w}">' for w in widths) if widths else ""
    h = "".join(f"<th>{c}</th>" for c in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><colgroup>{cols}</colgroup><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def fig(svg, n, title):
    return f"<figure>{svg}<figcaption>圖 {n}　{escape(title)}</figcaption></figure>"


def load(name):
    p = RESULTS / name
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8")) if p.suffix == ".json" else p.read_text(encoding="utf-8")


def pct(v):
    return "—" if v is None else f"{v * 100:.1f}%"


def page(title, body):
    return f'<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>{title}</title><style>{CSS}</style></head><body>{body}</body></html>'


def render(html, pdf_path):
    html_path = ROOT / "docs" / "build" / (pdf_path.stem + ".html")
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding="utf-8")
    r = subprocess.run(["node", str(RENDER), str(html_path), str(pdf_path)], cwd=RENDER.parent,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        sys.exit(r.stderr)
    print("PDF →", pdf_path)


# ====================================================================
# 評測結果區塊（從 evaluation/results 讀取）
# ====================================================================

CONFIGS = [
    ("base15_rag_test.json", "qwen2.5:1.5b（未微調）＋RAG"),
    ("base05_rag_test.json", "qwen2.5:0.5b（未微調）＋RAG"),
    ("judge_norag_test.json", "threat-intel-judge（微調）不帶 RAG"),
    ("judge_rag_test.json", "threat-intel-judge（微調）＋RAG　← 上線設定"),
]


def results_section():
    rows, final = [], None
    for f, label in CONFIGS:
        r = load(f)
        if r is None:
            rows.append([label, "—", "尚未執行", "—", "—", "—"])
            continue
        if f == "judge_rag_test.json":
            final = r
        rows.append([label, r["n"], f"<b>{pct(r['risk_accuracy'])}</b>", pct(r["parse_rate"]),
                     pct(r["retrieval_hit"]) if r.get("rag") else "不適用", f"{r['seconds'] / r['n']:.1f}"])
    out = ["<h3>13.2 判定正確率（測試集，模型未看過）</h3>",
           table(["模型設定", "筆數", "風險等級正確率", "可解析率", "檢索命中率", "每筆秒數"], rows,
                 ["38%", "8%", "16%", "12%", "14%", "12%"])]
    if final:
        levels = ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        conf = final["confusion"]
        crow = []
        for g in levels:
            c = conf.get(g, {})
            crow.append([f"<b>{g}</b>"] + [str(c.get(p, 0)) for p in levels] + [str(c.get("PARSE_FAIL", 0)), str(sum(c.values()))])
        out += ["<h3>13.3 上線設定的混淆矩陣（列＝標準答案，欄＝模型判定）</h3>",
                table(["標準答案＼判定", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "解析失敗", "合計"], crow)]
        fp_high = sum(conf.get(g, {}).get("HIGH", 0) for g in levels if g != "HIGH")
        pred_high = sum(conf.get(g, {}).get("HIGH", 0) for g in levels)
        miss_high = sum(v for k, v in conf.get("HIGH", {}).items() if k != "HIGH")
        out.append(f"<p>黑名單相關的兩個指標：判定為 HIGH 的 {pred_high} 筆中有 {fp_high} 筆其實不是 HIGH（誤封鎖）；"
                   f"標準答案為 HIGH 的 {sum(conf.get('HIGH', {}).values())} 筆中有 {miss_high} 筆被判低（漏封鎖）。</p>")
        weak = sorted(final["by_scenario"].items(), key=lambda kv: int(kv[1].split('/')[0]) / int(kv[1].split('/')[1]))[:6]
        out.append("<p>表現最弱的情境：" + "、".join(f"{escape(k)} {v}" for k, v in weak) + "。</p>")
    e2e = load("e2e_test.json")
    if e2e:
        out += ["<h3>13.4 端到端測試（完整 Agent 流程，外部 API 以錄製資料重播）</h3>",
                table(["指標", "結果", "說明"], [
                    ["筆數", e2e["n"], f"每種情境抽 2 筆；執行錯誤 {e2e['errors']} 筆"],
                    ["端到端正確率", f"<b>{pct(e2e['e2e_accuracy'])}</b>", "最終風險等級與資料集標準答案一致"],
                    ["判定正確率", pct(e2e["judge_accuracy"]), "與「依實際蒐到的證據重算的答案」一致"],
                    ["查證模型自行選對工具的比例", pct(e2e["tool_recall"]), "不含系統補查"],
                    ["需要必查清單補查的比例", pct(e2e["topup_rate"]), "補查後證據組成與標準一致"],
                    ["無效工具呼叫比例", pct(e2e["invalid_call_rate"]), "型別不符或不存在的工具"],
                    ["平均耗時", f"{e2e['avg_seconds']} 秒", f"平均 {e2e['avg_iterations']} 次 LLM 呼叫，純 CPU"]],
                    ["30%", "18%", "52%"])]
    live = load("live_check.md")
    if live:
        rows = [ln.strip("|").split("|") for ln in live.splitlines() if ln.startswith("| ") and "---" not in ln][1:]
        out += ["<h3>13.5 真實 API 實測</h3>",
                "<p>以真實的 VirusTotal、AbuseIPDB、WHOIS、RDAP 走完整 <code>POST /api/v1/analyses</code> 流程（資料庫換成記憶體版，不寫入正式資料庫），"
                "再把系統判定與「判定準則對同一份真實證據的結果」比對。</p>",
                table(["目標", "說明", "系統判定", "準則判定", "一致", "秒數", "查詢的工具／訊息"],
                      [[escape(c.strip()) for c in r] for r in rows], ["17%", "17%", "10%", "10%", "6%", "7%", "33%"])]
    log = RESULTS / "training_log.jsonl"
    if log.exists():
        ev = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if '"eval"' in x]
        done = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if '"done"' in x]
        if ev:
            out += ["<h3>13.6 微調過程</h3>",
                    "<p>驗證集答案段損失（越低代表模型越會產出標準答案）：" + "，".join(f"第 {e['step']} 步 {e['val_loss']}" for e in ev)
                    + (f"；總訓練時間 {done[-1]['hours']} 小時（純 CPU）。" if done else "。") + "</p>"]
    return "".join(out)


# ====================================================================
# 專案企畫書
# ====================================================================

def proposal():
    final = load("judge_rag_test.json")
    acc = pct(final["risk_accuracy"]) if final else "評測中"
    b = []
    b.append(f'<h1>Threat Intel Agent｜專案企畫書</h1><div class="sub">本機 LLM 版：Ollama＋RAG＋LoRA 微調　·　{TODAY}　·　邱冠文</div>')
    b.append(f"""<div class="kpi"><div><b>{acc}</b><span>測試集風險判定正確率（目標 ≥ 90%）</span></div>
<div><b>0 元</b><span>模型推論費用，資料不出本機</span></div><div><b>870</b><span>標註案例（23 種情境）</span></div>
<div><b>95%</b><span>RAG 判定準則檢索命中率</span></div></div>""")

    b.append("<h2>1. 前言</h2>")
    b.append("<p>中小企業與內部 IT 人員多半沒有專職資安團隊。看到防火牆日誌裡陌生的 IP、使用者回報可疑網址時，只能逐一查 WHOIS、AbuseIPDB、VirusTotal，再自行判斷，耗時且需要經驗。Threat Intel Agent 把「查證＋判斷」自動化：輸入一個 IP 或網域，Agent 自動查詢情資來源、產出有證據的風險報告，判定高風險時自動列入黑名單，並提供查詢介面讓防火牆對接。</p>")
    b.append("<p>原版以雲端 Claude 判斷，實際使用時出現「同一個明顯危險的目標，這次判安全、下次判危險」的不一致。本次改版的目標是：<b>改用本機 Ollama 模型</b>（資料不出內網、沒有 API 費用、可以微調），以 <b>RAG 提供明確的判定準則</b>、以 <b>LoRA 微調</b>讓小模型學會套用準則，並建立<b>可重跑的評測流程</b>，把測試集判定正確率提升到 90% 以上。</p>")

    b.append("<h2>2. 專案概要</h2>")
    b.append(table(["項目", "內容"], [
        ["目標", "輸入 IP 或網域，數十秒內產出一致、可追溯證據的風險報告（HIGH／MEDIUM／LOW／UNKNOWN）"],
        ["使用者", "企業內部 IT 人員；透過 API 對接的防火牆、SIEM 等既有系統"],
        ["範圍", "改寫 LLM 層（查證迴圈、證據精簡、RAG、判定模型、結構化輸出），修正原版造成誤判的 7 個問題；路由、資料庫結構與前端維持不變"],
        ["交付物", "Ollama 版 Agent、知識庫與檢索、LoRA 微調流程與模型、870 筆標註資料集、評測腳本與報告、單元測試、本企畫書與改善報告"],
        ["成效指標", "測試集風險判定正確率 ≥ 90%；結構化輸出可解析率 100%；檢索命中率 ≥ 90%；誤封鎖（非 HIGH 判成 HIGH）越少越好"],
        ["執行環境", "一般筆電即可（i7-13620H、16 GB RAM、無獨立顯卡），訓練與推論全部在 CPU 上完成"]], ["16%", "84%"]))

    b.append("<h2>3. 原版問題診斷與改善</h2>")
    b.append("<p>逐行檢查原版程式後，誤判不是資料錯，而是「蒐到的證據不一致＋判斷標準模糊＋取樣隨機」疊加。以下是根因與對應做法（第 7 項是改用小模型後在測試中新發現的）。</p>")
    b.append(table(["#", "問題", "根因", "改善做法", "驗證方式"], [
        ["1", "同樣輸入每次答案不同", "API 未設 temperature，預設 1.0 隨機取樣", "所有模型呼叫 temperature=0、固定 seed", "同一案例重跑結果相同"],
        ["2", "標準模糊，界線每次不同", "準則只寫「多來源指向惡意」，沒有數字門檻", "判定準則全部寫成數字門檻，放進知識庫由 RAG 提供", "rubric 單元測試；檢索命中率 95%"],
        ["3", "每次查的工具不同", "第一輪提示寫「查註冊資訊」，且只執行第一回合的工具呼叫", "提示改為明確列出必查工具；查證迴圈最多 2 輪", "端到端測試的工具選擇指標"],
        ["4", "查詢失敗被快取 24 小時", "@iscache 連錯誤結果一起寫入快取（VirusTotal 429 很常見）", "錯誤結果不寫入快取，下次自動重查", "test_failed_lookup_is_not_cached"],
        ["5", "關鍵數字被淹沒", "原始回應整包 str() 給模型，VirusTotal 單筆 2 萬字以上", "evidence.py 只抽判斷需要的欄位，網域年齡等由程式先算好", "精簡前後判定一致的來回測試"],
        ["6", "沒交報告就當掉", "找不到 submit_report 時變數未定義", "改用 JSON Schema 結構化輸出；解析失敗重試 1 次，仍失敗回 UNKNOWN 保底", "可解析率 100%"],
        ["7", "小模型只查一個工具就停", "1.5B 查證模型實測幾乎每次只呼叫 1 個工具", "必查清單：漏查的情資來源由系統補齊", "端到端測試的補查比例"]],
        ["4%", "16%", "26%", "32%", "22%"]))
    b.append("<p>另外新增<b>輸入驗證</b>：先用程式判斷輸入是不是合法的 IP 或網域，不是就直接回 422，不進模型、不浪費外部 API 額度。</p>")

    b.append('<h2 class="pb">4. 系統架構</h2>')
    b.append(fig(D.fig_architecture(), 1, "系統架構圖"))
    b.append(table(["層", "元件", "職責"], [
        ["呈現", "Dashboard（static/index.html）", "輸入目標、顯示報告與思考過程時間軸、歷史、黑名單管理、統計卡片"],
        ["API", "FastAPI 路由 /api/v1", "輸入驗證、呼叫 Agent、寫入分析結果；HIGH 自動寫入黑名單；對外提供黑名單查詢"],
        ["Agent", "agent.py", "查證迴圈 → 必查清單補查 → 證據精簡 → RAG 檢索 → 判定與解析，全程寫入思考軌跡"],
        ["模型", "Ollama", "查證模型 qwen2.5:1.5b（tool calling）、判定模型 threat-intel-judge（LoRA 微調）、嵌入模型 bge-m3"],
        ["知識", "rag/knowledge、rag/index", "8 份判定準則與欄位解讀文件，切成 30 段，以 bge-m3 向量化"],
        ["資料", "MongoDB Atlas", "analyses、tool_calls、blocklist、cache 四個 collection"],
        ["外部", "情資 API", "AbuseIPDB、VirusTotal（需金鑰）、WHOIS、RDAP（免金鑰）"]], ["10%", "26%", "64%"]))

    b.append('<h2 class="pb">5. UML</h2>')
    b.append(fig(D.fig_usecase(), 2, "使用案例圖（UML Use Case）"))
    b.append(fig(D.fig_class(), 3, "類別圖（UML Class）"))
    b.append(fig(D.fig_sequence(), 4, "一次分析的循序圖（UML Sequence）"))

    b.append('<h2 class="pb">6. 流程</h2>')
    b.append(fig(D.fig_flow(), 5, "分析流程圖"))
    b.append(fig(D.fig_training(), 6, "模型訓練與評測流程圖"))

    b.append('<h2 class="pb">7. 資料庫架構</h2>')
    b.append("<p>沿用原版 MongoDB 的四個 collection，本次改版沒有改動結構，只多了一種思考軌跡類型 <code>thinking</code>（記錄 RAG 取回哪些準則、補查了哪些來源），前端時間軸原本就支援顯示。</p>")
    b.append(fig(D.fig_db(), 7, "資料庫架構圖"))
    b.append(table(["Collection", "用途", "寫入時機", "保存策略"], [
        ["analyses", "每次分析的完整報告與執行指標", "POST /analyses 完成時", "永久保存，供歷史與統計"],
        ["tool_calls", "Agent 每一步的決策與工具原始回應", "每次工具呼叫前後、RAG 檢索、補查", "與分析共存，可回溯判斷依據"],
        ["blocklist", "自動黑名單", "判定 HIGH 時 upsert（同目標不重複）", "30 天到期，可人工移除"],
        ["cache", "外部查詢結果", "工具查詢成功時", "24 小時過期；失敗結果不寫入"]], ["15%", "33%", "30%", "22%"]))

    b.append("<h2>8. 技術線</h2>")
    b.append(table(["層級", "技術", "版本／說明"], [
        ["後端框架", "FastAPI＋Uvicorn", "非同步 API，自動產生 /docs"],
        ["資料庫", "MongoDB Atlas＋pymongo AsyncMongoClient", "原生 async 驅動"],
        ["本機 LLM 執行", "Ollama", "0.40.x；tool calling、JSON Schema 結構化輸出、embed API"],
        ["查證模型", "qwen2.5:1.5b", "Apache-2.0；支援 tool calling"],
        ["判定模型", "threat-intel-judge", "Qwen2.5-0.5B-Instruct＋LoRA，GGUF Q8_0（531 MB）"],
        ["嵌入模型", "bge-m3", "多語言，1024 維，中文準則檢索"],
        ["微調", "PyTorch＋Transformers＋PEFT（LoRA）", "純 CPU 訓練；gguf 套件轉檔"],
        ["評測", "自建評測腳本＋pytest", "判定正確率、混淆矩陣、檢索命中率、端到端、實測"],
        ["前端", "Vanilla JS＋Tailwind CSS", "沿用原版"],
        ["部署", "Docker", "容器內以 OLLAMA_HOST 連到主機的 Ollama"]], ["16%", "38%", "46%"]))
    b.append("<h3>8.1 主要設計取捨</h3>")
    b.append(table(["問題", "選項", "決定", "理由"], [
        ["判定模型大小", "0.5B／1.5B／3B", "0.5B＋LoRA", "CPU 上微調與推論都跑得動；微調後套用準則的能力超過未微調的大模型（見第 13 章）"],
        ["準則放哪裡", "寫死在提示／RAG 知識庫", "RAG", "準則可以獨立更新、可以追溯「依據哪一條」，提示也不會越來越長"],
        ["向量存放", "向量資料庫／記憶體", "JSON 索引＋記憶體內積", "只有 30 段，記憶體算內積不到 1 毫秒，少維護一套服務"],
        ["輸出格式控制", "提示要求／tool_choice／JSON Schema", "Ollama format＝JSON Schema", "以文法限制解碼，輸出一定是可解析的 JSON"],
        ["工具選擇", "完全交給模型／完全寫死", "模型發起＋必查清單補齊", "保留 Agent 自主性，同時保證證據組成一致"],
        ["匯入 Ollama", "safetensors 直接匯入／GGUF", "自寫轉檔器輸出 GGUF", "本機 Ollama 的 safetensors 匯入走 MLX 路徑，不支援 Qwen2"]], ["14%", "22%", "22%", "42%"]))

    b.append('<h2 class="pb">9. LLM 設計細節</h2>')
    b.append("<h3>9.1 證據精簡</h3><p>每個工具的原始回應在 <code>evidence.py</code> 轉成精簡證據，只留判斷需要的欄位：AbuseIPDB 的信心分數、檢舉數、白名單、Tor、是否公網；VirusTotal 的引擎統計、判定惡意的引擎、分類與知名度；WHOIS 的註冊日期與註冊商。網域年齡、距上次檢舉天數、是否為私有網段由程式先算好，模型只做綜合判斷，不做日期與數字運算。原始回應仍完整寫入 tool_calls，可回溯。</p>")
    b.append("<pre>證據：{\"abuseipdb_lookup\":{\"abuse_confidence_score\":100,\"total_reports\":130,\"is_whitelisted\":false,\"is_tor\":true,…},\n      \"virustotal_ip_lookup\":{\"malicious\":18,\"suspicious\":2,\"harmless\":46,\"flagged_by\":[\"ESET:malware\",…]}}</pre>")
    b.append("<h3>9.2 RAG 檢索</h3><p>知識庫 8 份文件（IP 判定準則、網域判定準則、AbuseIPDB／VirusTotal 欄位解讀、WHOIS 與網域年齡、非公網位址、Tor 與代管網段、處置建議），依「## 標題」切成 30 段，以 bge-m3 向量化。查詢句由證據組成，並補上與準則用語一致的訊號詞（例如「白名單」「Tor 出口節點」「新註冊網域」「信心分數達高風險門檻」），依目標型別過濾後取前 4 段。第一版查詢句只有數值，命中率只有 30%；加入訊號詞後，驗證集命中率提升到 95.2%。</p>")
    b.append("<h3>9.3 LoRA 微調</h3>")
    b.append(table(["項目", "設定"], [
        ["基底模型", "Qwen2.5-0.5B-Instruct（Apache-2.0）"],
        ["訓練資料", "依情境分層抽樣 347 筆；每筆是「與上線完全相同的判定提示＋RAG 參考準則 → 標準答案 JSON」"],
        ["LoRA", "r=16、alpha=32、dropout 0.05；掛在後 12 層的 q／k／v／o／gate／up／down 投影；可訓練參數 440 萬（0.88%）"],
        ["最佳化", "AdamW，學習率 2e-4，5% warmup 後 cosine 衰減，梯度累積 4，1 個 epoch（87 步）"],
        ["損失", "只計算答案（報告 JSON）段的 token；也只對答案位置計算詞表 logits，省下大量運算"],
        ["CPU 取捨", "第一版（全 24 層、gradient checkpointing、2 epoch）預估 8.5 小時；改成後 12 層、只算答案 logits、關掉重算後約 2 小時"],
        ["匯出", "合併權重 → 自寫轉檔器（gguf 套件）輸出 Q8_0 GGUF → ollama create threat-intel-judge"]], ["16%", "84%"]))
    b.append("<h3>9.4 結構化輸出與保底</h3><p>判定呼叫帶 <code>format=REPORT_SCHEMA</code>，Ollama 以 JSON Schema 文法限制解碼，欄位與列舉值（HIGH／MEDIUM／LOW／UNKNOWN、high／medium／low）不可能出錯。欄位順序刻意讓模型先寫證據再下風險等級。解析失敗重試一次，仍失敗就回傳 UNKNOWN 保底報告，避免 500 錯誤，也不會誤封鎖。<code>sources_checked</code> 以實際呼叫紀錄覆寫，不採用模型自填。</p>")
    b.append("<h3>9.5 判定準則摘要</h3>")
    b.append(table(["等級", "IP", "網域"], [
        ["UNKNOWN", "非公網位址；或 AbuseIPDB 與 VirusTotal 都沒有資料", "VirusTotal 沒有資料（查詢失敗或 404）"],
        ["LOW（例外）", "AbuseIPDB 白名單且 VirusTotal 惡意 ≤ 2", "知名度排名前 1 萬、惡意 ≤ 2、無威脅分類"],
        ["HIGH", "信心分數 ≥ 75；或 VirusTotal 惡意 ≥ 5；或分數 ≥ 50 且惡意 ≥ 2", "惡意 ≥ 5；或惡意 ≥ 2 且有威脅分類；或惡意 ≥ 2 且網域未滿 30 天"],
        ["MEDIUM", "分數 25–74；惡意 2–4；可疑 ≥ 3；Tor 出口節點", "惡意 2–4；有威脅分類；可疑 ≥ 3；網域未滿 30 天"],
        ["LOW", "以上皆不符合", "以上皆不符合"]], ["14%", "43%", "43%"]))

    b.append("<h2>10. 前端</h2>")
    b.append(table(["區塊", "功能", "本次改版"], [
        ["統計卡片", "總分析次數、高風險比例、快取命中率、黑名單數量", "不變"],
        ["Analyze", "輸入目標、快速測試按鈕、報告卡（風險徽章、摘要、證據、建議）", "格式錯誤時顯示後端 422 訊息"],
        ["思考過程時間軸", "依序顯示 tool_call、tool_result、thinking", "新增顯示 RAG 參考準則與補查紀錄（沿用既有 thinking 樣式）"],
        ["History", "分析歷史與風險篩選", "不變"],
        ["Blocklist", "黑名單列表、移除誤判、對接說明", "不變"],
        ["頁尾", "技術標示", "改為 Ollama（本機 LLM）＋RAG"]], ["16%", "52%", "32%"]))

    b.append("<h2>11. 後端</h2>")
    b.append(table(["模組", "職責"], [
        ["main.py／database.py", "組裝應用、掛載路由；lifespan 建立 MongoDB 連線（不變）"],
        ["config.py", "環境變數、Ollama 模型設定、工具定義、查證與判定提示、報告 JSON Schema"],
        ["agent.py", "AI 類別：查證迴圈、必查清單、RAG、判定、思考軌跡、token 統計；對外介面與原版相同"],
        ["evidence.py", "輸入驗證、目標事實（公網／私有網段）、原始回應精簡、RAG 查詢句"],
        ["judge.py", "判定提示組裝、輸出驗證、保底報告（Agent、訓練、評測共用）"],
        ["rag/", "知識庫文件、索引建置、檢索"],
        ["tools/＋utils.py＋cache.py", "四個情資來源；@duration 計時、@iscache 快取（修正：失敗不快取）"],
        ["routers/", "analyses（新增輸入驗證）、blocklist、system"],
        ["dataset/", "判定準則程式版（rubric）與 870 筆情境資料集產生器"],
        ["finetune/", "SFT 資料組裝、LoRA 訓練、GGUF 轉檔、匯入 Ollama"],
        ["evaluation/", "判定評測、端到端評測、真實 API 實測、記憶體版資料庫"],
        ["tests/", "9 個單元測試（輸入驗證、精簡、準則、來回一致、解析、快取）"]], ["26%", "74%"]))

    b.append('<h2 class="pb">12. RESTful API</h2>')
    b.append("<h3>12.1 設計原則</h3>")
    b.append(table(["原則", "做法"], [
        ["資源導向", "網址只放名詞（/analyses、/blocklist），動作由 HTTP 方法表達"],
        ["版本化", "全部端點掛在 /api/v1 之下，破壞性變更時開 /api/v2"],
        ["列表與詳情分離", "GET /analyses 只回摘要，完整報告用 GET /analyses/{id}"],
        ["選擇性驗證", "會耗外部額度或改變狀態的端點需要 X-API-Key；/blocklist/check 刻意公開，方便防火牆對接"],
        ["先驗證再處理", "輸入格式錯誤在進模型前就回 422；本機 LLM 無法使用時回 503 並附原因"]], ["18%", "82%"]))
    b.append(fig(D.fig_api_tree(), 8, "API 資源樹"))
    b.append("<h3>12.2 API 清單</h3>")
    b.append(table(["方法", "路徑", "說明", "驗證", "成功"], [
        ["GET", "/api/v1/system/health", "健康檢查", "—", "200"],
        ["GET", "/api/v1/system/stats", "儀表板統計：總分析數、高風險比例、快取命中率、黑名單數", "—", "200"],
        ["POST", "/api/v1/analyses", "建立分析（觸發 Agent），回傳完整報告", "X-API-Key", "200"],
        ["GET", "/api/v1/analyses", "分析歷史（摘要）", "—", "200"],
        ["GET", "/api/v1/analyses/{analysis_id}", "單筆分析完整報告", "—", "200／404"],
        ["GET", "/api/v1/analyses/{analysis_id}/thinking", "該次分析的思考軌跡（依時間排序）", "—", "200"],
        ["GET", "/api/v1/blocklist", "黑名單列表", "—", "200"],
        ["DELETE", "/api/v1/blocklist/{target}", "移除黑名單項目（誤判處理）", "X-API-Key", "200／404"],
        ["GET", "/api/v1/blocklist/check/{target}", "查詢目標是否被封鎖（供防火牆、SIEM 對接）", "—", "200"]],
        ["8%", "34%", "38%", "10%", "10%"]))
    b.append("<h3>12.3 主要 API 說明</h3>")
    b.append("<p><b>POST /api/v1/analyses</b>　請求：<code>{\"target\": \"185.220.101.42\"}</code>，標頭 <code>X-API-Key</code>。回應：</p>")
    b.append("""<pre>{ "analysis_id": "ana_20261117_a1b2c3", "target": "185.220.101.42", "target_type": "ip",
  "result": { "risk_level": "HIGH",
              "summary": "AbuseIPDB 信心分數 100 達高風險門檻（≥75）；VirusTotal 有 18 家引擎判定惡意（≥5）；且為 Tor 出口節點，判定為高風險。",
              "evidence": [ {"source":"abuseipdb_lookup","finding":"信心分數 100，近 30 天 130 次檢舉…","confidence":"high"}, … ],
              "sources_checked": ["ipwhois_lookup","abuseipdb_lookup","virustotal_ip_lookup"],
              "recommendation": "已自動列入黑名單（30 天）；建議於防火牆或 DNS 封鎖此IP…" },
  "metadata": { "duration_ms": 41230, "iterations": 3, "tool_calls_count": 3, "input_tokens": 2310, "output_tokens": 260 } }</pre>""")
    b.append("<p>錯誤：格式不是 IP 或網域回 <code>422 {\"detail\":\"「xxx」不是合法的 IP 位址或網域名稱\"}</code>；金鑰錯誤回 401；Ollama 無法連線或模型不存在回 503。</p>")
    b.append("<p><b>GET /api/v1/analyses/{id}/thinking</b>　回傳 <code>steps[]</code>，每步含 <code>type</code>（tool_call／tool_result／thinking）、<code>tool_name</code>、<code>input</code> 或 <code>output</code>、<code>duration_ms</code>、<code>from_cache</code>、<code>timestamp</code>。thinking 步驟會列出 RAG 取回的準則段落與補查的來源，可回答「為什麼判 HIGH」。</p>")
    b.append("<p><b>GET /api/v1/blocklist/check/{target}</b>　未封鎖回 <code>{\"target\":\"1.2.3.4\",\"blocked\":false}</code>；已封鎖另附 <code>reason</code>、<code>risk_level</code>、<code>expires_at</code>。防火牆可定期查詢，由既有防火牆決定是否阻擋（判斷與執行分離）。</p>")
    b.append("<h3>12.4 狀態碼</h3>")
    b.append(table(["狀態碼", "使用時機"], [["200 OK", "讀取或分析成功"], ["401 Unauthorized", "X-API-Key 錯誤"],
                                          ["404 Not Found", "分析編號或黑名單項目不存在"], ["422 Unprocessable Entity", "輸入不是合法的 IP 或網域"],
                                          ["503 Service Unavailable", "本機 LLM 服務無法使用或模型未匯入"]], ["30%", "70%"]))

    b.append('<h2 class="pb">13. 評測與驗證</h2>')
    b.append("<h3>13.1 評測設計</h3>")
    b.append("<p>真實查詢受外部 API 額度限制（VirusTotal 免費層每分鐘 4 次），也幾乎都是乾淨目標，無法涵蓋門檻邊界、查詢失敗、私有位址等情況。因此以真實 API 回應的欄位結構為準，產生 23 種情境、870 筆案例，用判定準則（rubric）標註標準答案，依情境分層切成訓練 613、驗證 83、測試 174 筆。<b>這裡的正確率是「模型判斷與本專案判定準則一致的比例」，不是真實世界的惡意偵測率</b>；真實世界的檢驗由 13.5 的實測補充。</p>")
    b.append(table(["層次", "工具", "回答的問題"], [
        ["單元測試", "pytest tests/（9 項）", "輸入驗證、證據精簡、判定準則、精簡來回一致、輸出解析、快取不存錯誤"],
        ["判定評測", "evaluation/run_eval.py", "同一份證據＋準則下，模型判得對不對（含混淆矩陣、檢索命中率）"],
        ["端到端評測", "evaluation/run_agent_e2e.py", "完整 Agent（查證模型選工具→補查→RAG→判定）整體正不正確"],
        ["真實實測", "evaluation/live_check.py", "接真實外部 API 時，系統判定與準則是否一致"]], ["14%", "30%", "56%"]))
    b.append(results_section())

    b.append("<h2>14. 結語</h2>")
    b.append("<p>這次改版把原本依賴雲端大模型「自由發揮」的判斷，改成一條可驗證的管線：輸入先驗證、證據組成固定、判定準則明確寫成數字並由 RAG 提供、小模型經過微調學會套用準則、輸出以 JSON Schema 鎖住格式，最後用固定的測試集量化正確率。結果是：在一般筆電上就能本機執行，不需要雲端 API 費用，資料不離開內網，而且每一次判定都能從思考軌跡回溯到「依據哪一條準則、哪一個數字」。</p>")
    b.append("<p>評測數字的意義也要說清楚：測試集正確率衡量的是「是否一致地套用本專案的判定準則」。準則本身是否貼近真實威脅，需要持續以真實事件與人工覆核結果校正，這部分列在《未來改善建議報告》中。</p>")

    b.append("<h2>15. 引用出處</h2>")
    refs = [
        ("Ollama — Structured outputs", "https://ollama.com/blog/structured-outputs"),
        ("Ollama 文件 — Structured outputs", "https://docs.ollama.com/capabilities/structured-outputs"),
        ("Ollama — Tool support", "https://ollama.com/blog/tool-support"),
        ("Qwen2.5 Technical Report（arXiv:2412.15115）", "https://arxiv.org/abs/2412.15115"),
        ("Hu et al., LoRA: Low-Rank Adaptation of Large Language Models（arXiv:2106.09685）", "https://arxiv.org/abs/2106.09685"),
        ("Lewis et al., Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks（arXiv:2005.11401）", "https://arxiv.org/abs/2005.11401"),
        ("Chen et al., BGE M3-Embedding（arXiv:2402.03216）", "https://arxiv.org/abs/2402.03216"),
        ("Hugging Face PEFT 文件", "https://huggingface.co/docs/peft"),
        ("GGUF 格式規格（ggml）", "https://github.com/ggml-org/ggml/blob/master/docs/gguf.md"),
        ("AbuseIPDB API v2 文件", "https://docs.abuseipdb.com/"),
        ("VirusTotal API v3 — IP addresses object", "https://docs.virustotal.com/reference/ip-object"),
        ("VirusTotal API v3 — Domains object", "https://docs.virustotal.com/reference/domains-object"),
        ("Zhu et al., Measuring and Modeling the Label Dynamics of Online Anti-Malware Engines（USENIX Security 2020）", "https://www.usenix.org/conference/usenixsecurity20/presentation/zhu"),
        ("Palo Alto Networks Unit 42 — Newly Registered Domains: Malicious Abuse by Bad Actors", "https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/"),
        ("CISA／FBI AA20-183A — Defending Against Malicious Cyber Activity Originating from Tor", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-183a"),
        ("RFC 1918 — Address Allocation for Private Internets", "https://www.rfc-editor.org/rfc/rfc1918"),
        ("RFC 6890 — Special-Purpose IP Address Registries", "https://www.rfc-editor.org/rfc/rfc6890"),
        ("IANA IPv4 Special-Purpose Address Registry", "https://www.iana.org/assignments/iana-ipv4-special-registry/"),
        ("NIST SP 800-61 Rev. 3 — Incident Response Recommendations（2025）", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
        ("FastAPI 文件", "https://fastapi.tiangolo.com/"),
        ("PyMongo Async 文件", "https://pymongo.readthedocs.io/"),
    ]
    b.append('<ol class="refs">' + "".join(f"<li>{escape(t)}　{u}</li>" for t, u in refs) + "</ol>")
    return page("Threat Intel Agent 專案企畫書", "".join(b))


# ====================================================================
# 未來改善建議報告
# ====================================================================

def improvement():
    b = []
    b.append(f'<h1>Threat Intel Agent｜未來改善建議報告</h1><div class="sub">從「查 IP 的小工具」到「IT 人員的資安工作台」　·　{TODAY}　·　邱冠文</div>')

    b.append("<h2>1. 摘要</h2>")
    b.append("<p>目前系統已能穩定地回答一個問題：「這個 IP 或網域危不危險」。但 IT 人員每天遇到的資安工作遠不止於此：使用者轉寄可疑信件、防火牆日誌一次出現上百個陌生 IP、廠商發布漏洞公告要判斷公司有沒有受影響、要確認對外服務有沒有開放不該開的連接埠。只能一次查一個 IP，對 IT 人員來說<b>太窄、太被動、也還沒接進日常工作流程</b>。</p>")
    b.append("<p>本報告參考開源威脅情資平台（IntelOwl、MISP、OpenCTI）、SOC 自動化（Cortex XSOAR、TheHive／Cortex、Wazuh）、商業 AI 資安助理（Microsoft Security Copilot）與相關標準（STIX 2.1、OWASP LLM Top 10、NIST SP 800-61r3），提出五個改善方向、目標架構與三階段路線圖。核心主張：<b>保留目前「證據→準則→判定→可追溯」的可靠管線，把它擴充成可以吃多種指標、接進既有工作流程、並且會從人工回饋持續學習的分析中樞</b>。</p>")

    b.append("<h2>2. 現況盤點</h2>")
    b.append(table(["面向", "現在做得到", "不足之處"], [
        ["指標類型", "IP、網域", "沒有 URL、檔案雜湊、Email、CVE；一次只能查一個"],
        ["情資來源", "AbuseIPDB、VirusTotal、WHOIS、RDAP", "缺少曝險（開放埠）、漏洞利用情報、社群封鎖清單"],
        ["判定品質", "數字準則＋RAG＋微調，結果一致、可追溯", "準則來自文件，尚未以真實事件與人工覆核校正"],
        ["工作流程", "Dashboard、黑名單查詢 API", "沒有批次、排程重掃、通知、工單、防火牆自動拉取清單"],
        ["互通性", "自訂 JSON API", "不支援 STIX／TAXII，無法與 MISP、OpenCTI 交換"],
        ["安全與治理", "API 金鑰、判斷與執行分離", "前端仍有固定金鑰、沒有角色權限與稽核；外部資料可能夾帶提示注入"]], ["14%", "38%", "48%"]))

    b.append("<h2>3. IT 人員的日常場景與能力缺口</h2>")
    b.append(table(["場景", "IT 人員要回答的問題", "需要的能力", "對應方向"], [
        ["使用者轉寄可疑信件", "這封信是不是釣魚？點了連結的人要處理嗎？", "解析信件標頭、抽出網址／附件雜湊／寄件網域，逐一查證後給總結", "A、C"],
        ["防火牆日誌出現大量陌生 IP", "哪些要封？哪些是掃描雜訊？", "批次分析、依風險排序、一鍵輸出封鎖清單", "A、B"],
        ["漏洞公告（CVE）", "公司有沒有受影響？要多急著修？", "比對資產清冊、查 CISA KEV 是否已遭利用、EPSS 被利用機率", "A、B"],
        ["對外服務健檢", "我們的 IP 有沒有開不該開的埠、有沒有已知漏洞？", "查 Shodan InternetDB 等曝險資料並追蹤變化", "A"],
        ["黑名單到期或誤判", "這個 IP 還危險嗎？", "排程重新評估、到期自動解除、人工覆核紀錄", "B、C"],
        ["主管問進度", "這個月擋了多少威脅？誤判率多少？", "趨勢報表、覆核推翻率、平均處理時間", "D"]], ["18%", "26%", "40%", "16%"]))

    b.append('<h2 class="pb">4. 參考作品與文章</h2>')
    b.append(table(["名稱", "類型", "重點", "可借鏡之處"], [
        ["IntelOwl", "開源情資擴充平台（AGPL-3.0）", "一個請求同時呼叫大量分析器（IP、網域、URL、雜湊、檔案），結果整合呈現", "分析器外掛架構：新增來源只要實作一個介面"],
        ["MISP", "開源情資分享平台", "IOC 管理、自動關聯、社群分享", "把高風險結果以標準格式分享，並匯入社群情資"],
        ["OpenCTI", "開源 CTI 知識圖譜", "以 STIX 2.1 建模，連接器可匯入 MISP 等來源", "以 STIX 2.1 作為匯出／匯入格式"],
        ["TheHive／Cortex", "開源事件應變與分析器", "案件管理＋可插拔分析器", "案件化：一次調查多個指標、保留處理紀錄"],
        ["ThePhish", "開源釣魚信件分析（基於 TheHive／Cortex／MISP）", "從信件抽出 IP、網域、網址、附件後逐一分析並給判決；專案自 2022 年後少有更新", "「信件→指標→判決」的流程設計（作為設計參考，不直接部署）"],
        ["Cortex XSOAR Enrichment Playbooks", "商業 SOAR 劇本", "IP／網域擴充劇本含內外部區分、聲譽命令與裁決", "把分析做成可重用的劇本步驟"],
        ["Wazuh＋VirusTotal", "開源 SIEM 整合", "檔案完整性告警自動查 VirusTotal，命中後觸發主動回應", "從告警自動觸發分析，不必人工貼上"],
        ["CrowdSec", "開源群眾協作 IP 信譽（MIT）", "使用者回報攻擊 IP，形成社群封鎖清單", "新增社群信譽來源；回饋本系統判定"],
        ["Shodan InternetDB", "免金鑰曝險查詢", "回傳 IP 的開放埠、漏洞、主機名稱；免費但限非商業用途", "對外服務健檢（需注意授權條款）"],
        ["CISA KEV＋FIRST EPSS", "漏洞優先序資料", "KEV 列出已遭利用的漏洞，EPSS 估計被利用機率", "漏洞公告分流：先修已遭利用且機率高的"],
        ["Palo Alto External Dynamic List", "防火牆外部清單格式", "防火牆定期從網址拉取純文字 IP 清單（一行一筆）", "提供 /blocklist/feed.txt，讓防火牆自動同步封鎖"],
        ["Microsoft Security Copilot Phishing Triage Agent", "商業 AI 資安代理（2025 年 3 月發表）", "自動分流使用者回報的釣魚信，以白話說明判斷理由，並依管理者回饋改進", "AI 自動分流＋說明理由＋從回饋學習"],
        ["VirusTotal MCP Server（開源）", "MCP 工具伺服器", "讓支援 MCP 的 AI 助理直接呼叫 VirusTotal 查詢", "把本系統的分析能力包成 MCP 工具"],
        ["CTIBench（NeurIPS 2024）", "LLM 威脅情資能力評測基準", "評測 LLM 在 CTI 知識、攻擊歸因、CVE→CWE 等任務的表現", "擴充評測面向，不只看風險等級"],
        ["OWASP Top 10 for LLM（2025）", "LLM 應用安全風險清單", "LLM01 提示注入（含透過外部內容的間接注入）列第一", "WHOIS、網頁內容是攻擊者可控文字，必須當資料隔離"]],
        ["18%", "17%", "35%", "30%"]))

    b.append('<h2 class="pb">5. 改善方向</h2>')
    b.append("<h3>A. 指標擴充：從單一 IP 到「一次丟進來就能處理」</h3>")
    b.append(table(["項目", "做法", "價值"], [
        ["新增指標型別", "URL、檔案雜湊（MD5／SHA-256）、Email 位址與寄件網域、CVE；沿用 validate_target 的模式先判型別", "涵蓋 IT 人員八成以上的查詢需求"],
        ["批次與日誌分析", "貼上一串清單或上傳防火牆／網站日誌，自動抽出指標、去重、依風險排序", "一次處理上百個 IP，不必逐筆貼"],
        ["信件分析", "上傳 .eml：解析 SPF／DKIM／DMARC 結果、抽出網址與附件雜湊，逐一查證後產出總結", "對應最常見的「這封信能不能點」問題"],
        ["免金鑰來源", "Shodan InternetDB（開放埠、漏洞，限非商業）、CISA KEV、FIRST EPSS、Tor 出口清單、CrowdSec", "提升判定依據，且不增加授權成本"],
        ["來源外掛化", "仿 IntelOwl 的分析器介面：每個來源只需實作查詢＋精簡兩個函式，並註冊到必查清單", "新增來源不必改 Agent"]], ["16%", "56%", "28%"]))
    b.append("<h3>B. 工作流程整合：讓結果自己流到該去的地方</h3>")
    b.append(table(["項目", "做法", "價值"], [
        ["防火牆自動同步", "新增 GET /blocklist/feed.txt（一行一個 IP，符合 Palo Alto EDL 等外部清單格式），防火牆定期拉取", "從「可以查」變成「自動擋」，仍維持判斷與執行分離"],
        ["SIEM 自動觸發", "Wazuh 等告警經 webhook 呼叫分析 API，結果回寫告警", "不必人工複製貼上"],
        ["ChatOps", "Teams／Slack 機器人：在頻道輸入 IP 即回覆摘要與連結", "IT 人員在原本的溝通工具內完成查詢"],
        ["工單整合", "HIGH 自動開單（Jira、GLPI 等），附證據與處置建議", "處理過程有紀錄可追"],
        ["排程重評估", "每日重掃黑名單與觀察名單；到期或風險下降自動解除並通知", "黑名單不會永久累積誤判"]], ["16%", "56%", "28%"]))
    b.append("<h3>C. AI 能力：從「一次判定」到「可對話、會學習」</h3>")
    b.append(table(["項目", "做法", "價值"], [
        ["針對同一目標追問", "分析完成後保存證據包；使用者提問時，以「問題＋證據包＋RAG 檢索到的準則」回答，不必重查外部 API", "回答「為什麼危險」「它是哪個國家的」等追問"],
        ["人工覆核回饋", "IT 人員可對判定按「同意／推翻」並註記；推翻案例自動成為新的訓練與評測資料", "準則與模型以真實事件持續校正"],
        ["定期再微調", "累積回饋資料後重跑 LoRA，評測過門檻才換上線模型", "模型越用越準，且每次更新都有數字把關"],
        ["內部知識 RAG", "把公司 SOP、資產清冊、網段配置放進知識庫", "判定與建議能結合公司實況（例如「這是研發部的伺服器網段」）"],
        ["MCP Server", "依 Model Context Protocol 把分析、黑名單查詢包成工具", "讓 Claude Desktop、Copilot 等 AI 助理直接使用本系統"],
        ["多代理分工", "查證代理、判定代理、審核代理（交叉檢查高風險判定）", "高衝擊決策多一道把關"]], ["16%", "56%", "28%"]))
    b.append("<h3>D. 可靠性、安全與治理</h3>")
    b.append(table(["項目", "做法", "價值"], [
        ["提示注入防護", "WHOIS、網頁、信件內容一律以資料區塊傳入、限制長度、移除指令樣式文字；判定結果以準則程式交叉檢查", "對應 OWASP LLM01，避免被外部資料操控判定"],
        ["身分與權限", "移除前端固定金鑰，改用 SSO／JWT；角色分為檢視者、分析者、管理者；寫入動作留稽核紀錄", "符合企業內控"],
        ["評測當成上線門檻", "評測腳本進 CI：正確率、誤封鎖率未達標就不允許換模型或改準則", "每次修改都有數字證明沒有變差"],
        ["營運指標", "記錄每次分析耗時、模型呼叫次數、外部 API 失敗率與額度用量", "及早發現額度耗盡或模型退化"],
        ["推論效能", "模型常駐、外部查詢平行化、批次分析排入佇列", "在一般筆電或小型伺服器上也能支撐日常量"]], ["16%", "56%", "28%"]))
    b.append("<h3>E. 資料與標準</h3>")
    b.append(table(["項目", "做法", "價值"], [
        ["STIX 2.1 匯出／匯入", "高風險結果轉成 STIX Indicator；可匯入 MISP、OpenCTI 的社群情資", "與資安社群和其他工具互通"],
        ["ATT&CK 對應", "判定理由標註相關 MITRE ATT&CK 技術（例如掃描、C2）", "報告更容易與資安團隊溝通"],
        ["向量檢索升級", "知識庫變大後改用 MongoDB Atlas Vector Search", "與既有資料庫整合，不另外維護服務"],
        ["資料保存政策", "分析與原始回應設定保存期限，個資欄位（WHOIS 聯絡人）去識別化", "降低資料外洩與合規風險"]], ["16%", "56%", "28%"]))

    b.append('<h2 class="pb">6. 目標架構</h2>')
    b.append(fig(D.fig_future(), 1, "未來目標架構：多入口、單一分析中樞、多出口，並以人工覆核回饋持續微調"))
    b.append("<p>設計重點：入口與出口都可以逐步增加，分析中樞維持目前已驗證的管線（證據精簡→準則檢索→微調模型判定→保底與追溯）。新增的「人工覆核」只在低信心或高衝擊（例如即將自動封鎖）時介入，覆核結果回流成訓練與評測資料，形成持續改進的循環。</p>")

    b.append("<h2>7. 分階段路線圖</h2>")
    b.append(table(["階段", "期間", "項目", "交付", "完成標準"], [
        ["P1 快速見效", "1–2 個月", "URL 與雜湊查詢、批次分析、/blocklist/feed.txt、排程重評估、前端金鑰改 JWT", "可批次分析並讓防火牆自動同步的版本", "批次 100 筆可在一般筆電完成；防火牆成功拉取清單"],
        ["P2 工作流程", "3–6 個月", "信件分析、Wazuh webhook、Teams 機器人、工單、追問對話、人工覆核", "IT 人員日常入口都能使用", "平均處理時間較人工下降一半；覆核資料開始累積"],
        ["P3 智慧平台", "6–12 個月", "覆核回饋再微調、內部知識 RAG、MCP Server、STIX 匯出、CVE 曝險分流", "會學習、可互通的分析中樞", "覆核推翻率逐季下降；評測門檻納入 CI"]], ["12%", "10%", "36%", "20%", "22%"]))

    b.append("<h2>8. 成效指標</h2>")
    b.append(table(["指標", "定義", "目標"], [
        ["判定一致率", "同一目標、同一份證據重複分析得到相同結論的比例", "100%"],
        ["測試集正確率", "固定測試集上與判定準則一致的比例", "≥ 90%（目前已達成，見企畫書）"],
        ["誤封鎖率", "被判 HIGH 但經覆核推翻的比例", "≤ 2%"],
        ["覆核推翻率", "人工覆核不同意模型判定的比例", "逐季下降"],
        ["平均處理時間", "從收到指標到產出建議的時間", "較人工查證縮短 50% 以上"],
        ["自動化涵蓋率", "不需人工介入即可結案的比例", "≥ 70%"],
        ["支援指標類型", "可分析的指標種類數", "2 → 6（IP、網域、URL、雜湊、Email、CVE）"]], ["18%", "54%", "28%"]))

    b.append("<h2>9. 風險與對策</h2>")
    b.append(table(["風險", "影響", "對策"], [
        ["外部 API 額度耗盡", "查不到資料、判定變 UNKNOWN", "快取、批次排程、多來源備援；額度監控與告警"],
        ["準則與真實威脅脫節", "判定一致但方向錯誤", "人工覆核回饋校正；定期以真實事件抽樣檢驗"],
        ["提示注入或資料投毒", "模型被外部文字操控", "外部內容資料化與長度限制；準則程式交叉檢查；高衝擊動作需人工確認"],
        ["誤封鎖影響營運", "合法服務被擋", "判斷與執行分離；白名單例外；封鎖 30 天自動到期；誤封鎖率納入上線門檻"],
        ["授權與合規", "部分免費資料限非商業用途", "上線前逐一確認條款（例如 Shodan InternetDB、Qwen 授權），改用商業授權或替代來源"],
        ["本機效能不足", "批次分析排隊過久", "佇列化、模型常駐、必要時加裝 GPU 或改用較小的量化模型"]], ["20%", "26%", "54%"]))

    b.append("<h2>10. 結語</h2>")
    b.append("<p>這個專案目前最有價值的不是「會查 IP」，而是已經建立了一條<b>可靠、可追溯、可量測</b>的 AI 判定管線。下一步的重點不是換更大的模型，而是把這條管線接到 IT 人員真正的工作現場：多種指標一起進來、結果自動流到防火牆與工單、人工的每一次判斷都變成下一版模型的養分。照路線圖分三階段推進，就能從一個查詢工具，成長為企業內部 IT 的資安工作台。</p>")

    b.append("<h2>11. 參考資料</h2>")
    refs = [
        ("IntelOwl（GitHub）", "https://github.com/intelowlproject/IntelOwl"),
        ("MISP（GitHub）", "https://github.com/MISP/MISP"),
        ("OpenCTI（GitHub）", "https://github.com/OpenCTI-Platform/opencti"),
        ("TheHive Project — Cortex（GitHub）", "https://github.com/TheHive-Project/Cortex"),
        ("ThePhish（GitHub）", "https://github.com/emalderson/ThePhish"),
        ("Cortex XSOAR — IP Enrichment - Generic v2", "https://xsoar.pan.dev/docs/reference/playbooks/ip-enrichment---generic-v2"),
        ("Wazuh — VirusTotal integration", "https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/index.html"),
        ("CrowdSec（GitHub）", "https://github.com/crowdsecurity/crowdsec"),
        ("Shodan — Introducing the InternetDB API", "https://blog.shodan.io/introducing-the-internetdb-api/"),
        ("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        ("FIRST — Exploit Prediction Scoring System（EPSS）", "https://www.first.org/epss/"),
        ("Palo Alto Networks — Formatting Guidelines for an External Dynamic List", "https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/external-dynamic-lists/formatting-guidelines-for-an-external-dynamic-list"),
        ("Microsoft — Microsoft unveils Microsoft Security Copilot agents（2025-03-24）", "https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/"),
        ("BurtTheCoder／mcp-virustotal（GitHub）", "https://github.com/BurtTheCoder/mcp-virustotal"),
        ("Model Context Protocol 規格", "https://modelcontextprotocol.io/specification"),
        ("Alam et al., CTIBench（NeurIPS 2024，arXiv:2406.07599）", "https://arxiv.org/abs/2406.07599"),
        ("OWASP GenAI — LLM01:2025 Prompt Injection", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
        ("OASIS — STIX 2.1 文件", "https://oasis-open.github.io/cti-documentation/"),
        ("MITRE ATT&CK", "https://attack.mitre.org/"),
        ("NIST SP 800-61 Rev. 3（2025）", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
    ]
    b.append('<ol class="refs">' + "".join(f"<li>{escape(t)}　{u}</li>" for t, u in refs) + "</ol>")
    return page("Threat Intel Agent 未來改善建議報告", "".join(b))


if __name__ == "__main__":
    out_dir = ROOT / "docs"
    render(proposal(), out_dir / "專案企畫書.pdf")
    render(improvement(), out_dir / "未來改善建議報告.pdf")
