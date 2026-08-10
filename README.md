# Threat Intel Agent

AI-powered IP / Domain 威脅情資分析工具。輸入一個 IP 或網域，Agent 會自主判斷該查詢哪些情資來源，交叉比對後產出結構化的風險報告，並在判定為高風險時自動加入黑名單。

**Live Demo：** https://thread-intel-agent.onrender.com/
**API 文件：** https://thread-intel-agent.onrender.com/docs

> 部署於 Render 免費方案，閒置後會進入休眠，首次連線可能需要 20-30 秒喚醒。

---

## 目錄

- [專案背景](#專案背景)
- [核心功能](#核心功能)
- [技術棧](#技術棧)
- [系統流程](#系統流程)
- [Agent 核心機制](#agent-核心機制)
- [Cache 架構](#cache-架構)
- [資料模型](#資料模型)
- [黑名單機制](#黑名單機制)
- [思考過程可追溯性](#思考過程可追溯性)
- [API 一覽](#api-一覽)
- [API 設計原則](#api-設計原則)
- [模組結構](#模組結構)
- [本機開發](#本機開發)
- [部署](#部署)
- [已知限制與後續規劃](#已知限制與後續規劃)

---

## 專案背景

中小企業與獨立開發者通常沒有專職資安團隊。遇到可疑的 IP 或網域時，只能逐一手動查詢 WHOIS、VirusTotal、AbuseIPDB，再自行綜合判斷——這個過程耗時，且需要一定的專業知識才能正確解讀各來源的資料。

本專案將「查證 + 判斷」這個最耗時的環節自動化。原本需要 10-20 分鐘的多來源比對，壓縮到數秒內完成，並且保留完整的判斷依據供人工複核。

封鎖的執行權刻意保留給企業既有的防火牆系統——讓 AI 直接執行封鎖的風險過高，這是負責任的半自動化設計。

---

## 核心功能

| 功能 | 說明 |
| :--- | :--- |
| 多來源交叉分析 | 整合 WHOIS、IPWHOIS、AbuseIPDB、VirusTotal，由 Agent 依情境自主決定查詢範圍 |
| 思考過程可視化 | 完整記錄每一步決策與查詢結果，可回溯「為何判定為高風險」 |
| 自動黑名單 | 判定 HIGH 風險時自動記錄，並提供公開查詢 API 供外部系統對接 |
| 快取機制 | 24 小時內重複查詢直接命中快取，避免耗盡外部 API 額度 |
| 統計儀表板 | 總分析次數、高風險比例、快取命中率、黑名單數量 |

---

## 技術棧

| 層級 | 技術 |
| :--- | :--- |
| 後端框架 | FastAPI |
| 資料庫驅動 | pymongo `AsyncMongoClient`（原生 async） |
| LLM | Anthropic Claude（`claude-haiku-4-5`），SDK 直接呼叫 |
| 資料庫 | MongoDB Atlas |
| 前端 | Vanilla JS + Tailwind CSS |
| 容器化 | Docker |
| 部署平台 | Render（Web Service） |
| 執行環境 | Python 3.12 |

---

## 系統流程

1. 使用者透過前端或 API 提交分析目標（IP 或 domain）
2. `POST /api/v1/analyses` 觸發 Agent
3. Agent 第一輪：自主判斷需查詢哪些情資來源，逐一執行查詢（過程中經過快取層）
4. Agent 第二輪：綜合所有證據，以強制的結構化格式提交分析報告
5. 分析結果寫入 `analyses`；若判定為 HIGH 風險，同步寫入 `blocklist`
6. 每一步決策軌跡寫入 `tool_calls`，供後續回溯查詢
7. 回傳結構化 JSON，前端渲染報告與思考時間軸

---

## Agent 核心機制

系統未使用 LangChain 等框架，直接呼叫 Anthropic SDK 實作 Tool Use 迴圈，讓每一步決策保持透明可控，也便於除錯。

### 第一輪：自由選擇工具

Claude 收到分析目標後，自主判斷該使用哪些工具、需要查詢幾次。這個判斷是動態的：分析知名公開服務時可能僅查詢單一來源即產出結論；面對來源不明確的目標時，則會主動交叉比對多個情資來源後才提交報告。

### 第二輪：強制結構化輸出

第二輪呼叫使用 `tool_choice` 強制 Claude 必須呼叫 `submit_report` 工具，並依預先定義的 `input_schema` 填寫內容：

```python
tool_choice={"type": "tool", "name": "submit_report"}
```

`submit_report` 的必填欄位：

| 欄位 | 型別 | 說明 |
| :--- | :--- | :--- |
| `target_type` | enum | `ip` 或 `domain` |
| `risk_level` | enum | `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN` |
| `summary` | string | 分析摘要 |
| `evidence` | array | 證據列表（來源、發現、信心度） |
| `sources_checked` | array | 實際使用的工具清單 |
| `recommendation` | string | 建議動作 |

**設計理由：** 僅依賴 prompt 要求輸出格式不夠可靠，模型仍有機率輸出自由格式文字（例如 Markdown 表格）。透過工具呼叫機制強制輸出，保證回傳永遠是可解析的結構化資料，不需額外撰寫容錯解析邏輯。

`target_type` 一併整合進此工具的輸出，而非另外用程式碼做字串判斷——Claude 在第一輪選擇查詢工具時本來就已做過這個判斷，讓它一併回報比重複判斷更一致。

### 建立與執行分離

`AI` 類別的建構子僅負責初始化狀態（分析目標、資料庫 collection 參照），實際的分析流程置於獨立的 `async def run()` 方法：

```python
ai = AI(target, cache_collection, tool_calls_collection)
await ai.run()
```

這樣的拆分是必要的——Python 的 `__init__` 不能宣告為 `async`，但分析流程中需要多次等待非同步操作（資料庫讀寫、快取查詢）。這也讓「建立物件」與「執行任務」兩個階段的職責更清楚。

### 風險等級判定

由 Claude 綜合多來源證據自主判斷，非寫死規則（例如非單純的 `if abuse_score > 80: risk = "HIGH"`）。系統提供的是多方查證的原始資料，判斷邏輯完全交由模型基於證據推理——這是 Agent 架構相對於傳統規則引擎的核心差異。

---

## Cache 架構

### 動機

VirusTotal 免費層級速率限制為每分鐘 4 次請求，AbuseIPDB 為每日 1000 次。若無快取機制，重複查詢會迅速耗盡額度，也無謂增加回應時間。

### 裝飾器封裝

以裝飾器封裝計時與快取判斷兩個橫切關注點，讓 5 個外部查詢工具共用同一套邏輯：

```python
@duration
@iscache("whois")
async def whois_lookup(domain, collection):
    return whois.whois(domain)
```

| 裝飾器 | 職責 |
| :--- | :--- |
| `@iscache(name)` | 查詢快取、判斷是否命中，未命中時執行實際查詢並寫回快取 |
| `@duration` | 計算整體執行耗時（含快取判斷） |

工具函式本身只需專注在查詢邏輯，新增查詢來源時不需重複實作快取與計時。

### 裝飾器疊加的資料傳遞

兩層裝飾器透過固定的回傳格式協作：內層 `@iscache` 回傳 `(結果, (是否命中快取,))`，外層 `@duration` 接住後以展開語法附加執行時間：

```python
def duration(fun):
    @wraps(fun)
    async def wrap(*args, **kwargs):
        start = time()
        back, middle_tuple = await fun(*args, **kwargs)
        exec_time = int((time() - start) * 1000)
        return back, *middle_tuple, exec_time
    return wrap
```

呼叫端取得攤平的三個值：

```python
result, from_cache, exec_time = await whois_lookup(domain, collection)
```

`@duration` 置於最外層，因此計時涵蓋整個流程（含快取判斷）。這個設計的另一個特性是可擴充性：若未來需在中間層加入其他裝飾器（例如重試機制），只要遵循「接住上層 tuple 後附加自身資訊」的約定，`@duration` 完全不需修改——它接收到的永遠是「一個結果 + 一個 tuple」，不需知道中間累積了幾層資訊。

### 抽象化邊界的判斷

計時與快取適合封裝為裝飾器，是因為這兩者的行為完全獨立於查詢內容——任何工具套用都是相同邏輯。相對地，「發送 HTTP 請求」雖然在多個工具中重複出現，但各自需要不同的 headers 與 URL 組成方式，屬於查詢邏輯本身的一部分，因此保留在各工具函式內，未強行抽象化。

### 快取策略

| 項目 | 設計 |
| :--- | :--- |
| Key 格式 | `{工具名稱}:{查詢目標}`，例如 `abuseipdb:185.220.101.42` |
| TTL | 24 小時，過期後視為未命中並重新查詢 |
| 命中率 | 即時反映於 `GET /api/v1/system/stats` 的 `cache_hit_rate` |

Key 加上工具名稱前綴，是為了避免不同工具對同一目標的查詢結果互相覆蓋。

---

## 資料模型

MongoDB Atlas，四個 collection：

| Collection | 用途 | 關鍵欄位 |
| :--- | :--- | :--- |
| `analyses` | 每次分析的完整結果 | `analysis_id`, `target`, `target_type`, `result`, `metadata` |
| `blocklist` | 自動生成的黑名單 | `target`, `target_type`, `risk_level`, `added_by`, `expires_at` |
| `cache` | 外部查詢結果暫存 | `key`, `value`, `expires_at` |
| `tool_calls` | Agent 決策軌跡 | `analysis_id`, `iteration`, `type`, `tool_name`, `timestamp` |

### 為何選擇 MongoDB

分析結果（`evidence`、`sources_checked` 等）為巢狀、非固定結構的資料，不同查詢來源回傳的欄位組成也各不相同。文件導向的資料模型能自然容納這種結構，不需為了固定 schema 而拆分成多張關聯表。

### 為何 blocklist 使用 target / target_type

黑名單需同時容納 IP 與 domain 兩種類型的高風險目標。統一的欄位設計讓 `GET /blocklist/check/{target}` 這個對外查詢端點能以一致的介面處理兩種輸入，避免維護兩套平行邏輯。

### 外部 API 回應格式的正規化

AbuseIPDB 與 VirusTotal 的回應皆以 `{"data": {...}}` 形式包裝實際內容，而 WHOIS / IPWHOIS 則直接回傳扁平結構。為讓存入快取的資料格式一致，前兩者在工具函式層即取出 `["data"]` 後再回傳，避免每個讀取端各自處理「這個來源要不要多剝一層」的差異。

### Collection 存取方式

MongoDB 連線於應用程式啟動時（`lifespan`）建立一次，各 collection 的操作介面掛載於 `app.state`，供各 router 透過 `request.app.state.{collection}` 取用，避免每次請求重複建立連線：

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGODB_URL)
    db = client["threat_intel"]
    app.state.analyses = db["analyses"]
    app.state.blocklist = db["blocklist"]
    app.state.cache = db["cache"]
    app.state.tool_calls = db["tool_calls"]
    yield
    client.close()
```

---

## 黑名單機制

### 自動化流程

`POST /analyses` 完成分析後，若 `risk_level == "HIGH"`，自動以 `upsert` 方式寫入 `blocklist`：

```python
if ai.final_report["risk_level"] == "HIGH":
    await blocklist_collection.update_one(
        {"target": target},
        {"$set": blocklist_doc},
        upsert=True
    )
```

使用 `upsert` 而非 `insert`，避免同一目標重複分析為 HIGH 時產生多筆重複紀錄。

### 職責邊界：判斷與執行分離

系統僅負責判斷是否高風險並記錄，不直接修改防火牆規則或執行封鎖動作。`GET /blocklist/check/{target}` 提供標準化查詢介面，供外部系統自行決定是否採取行動：

```bash
if curl -s $API/api/v1/blocklist/check/1.2.3.4 | jq -r .blocked | grep -q true; then
    iptables -A INPUT -s 1.2.3.4 -j DROP
fi
```

這個設計將「AI 判斷」與「實際執行」的權責分開——誤判造成的風險不會直接轉化為服務中斷，執行端仍由既有系統把關。

---

## 思考過程可追溯性

`tool_calls` collection 記錄 Agent 執行過程中的每一個決策步驟，分為兩種類型：

**`tool_call`**（決策時刻）

```json
{
  "type": "tool_call",
  "tool_name": "abuseipdb_lookup",
  "input": {"ip": "185.220.101.42"},
  "timestamp": "2026-08-10T06:58:57Z"
}
```

**`tool_result`**（執行結果）

```json
{
  "type": "tool_result",
  "tool_name": "abuseipdb_lookup",
  "output": {},
  "duration_ms": 420,
  "from_cache": false,
  "timestamp": "2026-08-10T06:59:00Z"
}
```

`GET /analyses/{id}/thinking` 依 `analysis_id` 查詢並按時間排序回傳，前端據此還原完整的決策時間軸——包含查詢了哪些來源、各花費多少時間、是否命中快取。

這讓每一次的風險判斷都具備可回溯的完整脈絡，而非僅呈現最終結論。

---

## API 一覽

| Method | Path | 說明 | 驗證 |
| :--- | :--- | :--- | :---: |
| GET | `/api/v1/system/health` | 健康檢查 | — |
| GET | `/api/v1/system/stats` | 儀表板統計數據 | — |
| POST | `/api/v1/analyses` | 建立分析（觸發 Agent） | 需要 |
| GET | `/api/v1/analyses` | 分析歷史列表 | — |
| GET | `/api/v1/analyses/{id}` | 單筆分析詳情 | — |
| GET | `/api/v1/analyses/{id}/thinking` | 該筆分析的完整思考過程 | — |
| GET | `/api/v1/blocklist` | 黑名單列表 | — |
| DELETE | `/api/v1/blocklist/{target}` | 移除黑名單項目 | 需要 |
| GET | `/api/v1/blocklist/check/{target}` | 查詢是否在黑名單（供外部系統對接） | — |

驗證機制為 `X-API-Key` header。完整規格請見 [`/docs`](https://thread-intel-agent.onrender.com/docs)。

---

## API 設計原則

| 原則 | 說明 |
| :--- | :--- |
| RESTful 慣例 | URL 僅描述資源，操作語意由 HTTP 方法表達，路徑中不出現動詞 |
| 列表與詳情分離 | `GET /analyses` 僅回傳摘要欄位，完整內容另行呼叫 `GET /analyses/{id}`，避免列表查詢傳輸過量資料 |
| 版本化路徑 | 所有端點統一置於 `/api/v1/` 前綴，為未來的破壞性變更保留相容空間 |
| 選擇性驗證 | 對會消耗外部 API 額度或改變系統狀態的端點加上驗證；`/blocklist/check/{target}` 刻意維持公開，供外部防火牆系統無障礙對接 |

---

## 模組結構

```
thread-intel-agent/
├── main.py              # 應用程式入口、生命週期管理、路由掛載
├── config.py            # 環境變數、Agent 設定(system prompt、tools schema)
├── agent.py             # AI class:Tool Use 迴圈核心邏輯
├── utils.py             # 快取裝飾器、計時裝飾器、ID 產生、API Key 驗證
├── cache.py             # 快取讀寫邏輯
├── routers/
│   ├── system.py        # 健康檢查、儀表板統計
│   ├── analyses.py      # 分析建立、查詢、思考過程
│   └── blocklist.py     # 黑名單查詢、移除、對外驗證端點
├── tools/
│   ├── whois_.py
│   ├── ipwhois_.py
│   ├── abuseipdb_.py
│   └── virustotal_.py
├── static/              # 前端
├── Dockerfile
└── requirements.txt
```

路由依職責拆分為獨立模組。`main.py` 以巢狀 `APIRouter` 統一管理版本前綴，各功能模組的 router 掛載於其下：

```python
main_router = APIRouter(prefix="/api/v1")
main_router.include_router(analyses.router)   # router 內部 prefix="/analyses"
main_router.include_router(blocklist.router)  # router 內部 prefix="/blocklist"
main_router.include_router(system.router)     # router 內部 prefix="/system"

app.include_router(main_router)
```

這讓「版本前綴」與「資源路徑」的管理職責分離——版本變更只需修改 `main.py` 一處，各功能模組不需感知自己的完整 URL 路徑。

---

## 本機開發

環境需求：Python 3.12

```bash
# 安裝套件
pip install -r requirements.txt

# 設定環境變數(.env)
MONGODB_URL=...
ANTHROPIC_API_KEY=...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
API_KEY=...

# 啟動
uvicorn main:app --reload
```

使用 Docker：

```bash
docker build -t threat-intel-agent .
docker run -p 8000:8000 --env-file .env threat-intel-agent
```

---

## 部署

應用程式以 Docker 容器化後部署至 Render，資料庫使用 MongoDB Atlas 托管服務。

| 項目 | 說明 |
| :--- | :--- |
| 容器化 | 確保開發、測試、正式環境的一致性 |
| 資料庫 | MongoDB Atlas 托管，免自行維運基礎設施 |
| 環境變數 | 於 Render 平台設定，不隨程式碼進入版本控制 |
| 網路設定 | MongoDB Atlas Network Access 需允許 Render 的連線來源 |

---

## 已知限制與後續規劃

### 前端 API Key 管理（優先度高）

目前前端的 `X-API-Key` 為硬編碼於前端程式碼中的固定值，與後端 `.env` 中的 `API_KEY` 手動保持一致。這代表 `Depends(verify_api_key)` 這層驗證機制，在 Key 已公開於前端原始碼的前提下，實質防護力有限——任何能檢視前端原始碼的人都能取得這組 Key。

這是時間限制下的權宜設計。正式環境應改為：

- 使用者登入後由後端動態核發短期憑證（例如 JWT），前端不持有長期有效的固定密鑰
- 或於伺服器端注入環境變數至前端，至少讓 Key 不隨版本控制外流

### 輸入邊界處理

系統目前假設輸入為合法、可查詢的 IP 或 domain，尚未對特殊保留位址（如 `0.0.0.0`、私有網段位址如 `192.168.x.x`）或格式錯誤的輸入做防禦性處理。查詢此類位址時，部分工具（如 IPWHOIS）可能因查無對應網段資料而拋出例外，導致該次分析中斷。

改善方向：

- 於工具函式層級加入例外捕捉，查詢失敗時回傳結構化的錯誤資訊，讓 Agent 仍能依其餘可用來源完成分析
- 於 API 層加入基本格式驗證，對明顯不合法的輸入提前回應，避免消耗不必要的外部 API 額度

### 白名單機制

黑名單目前僅記錄經 Agent 判定為 HIGH 風險的目標，尚無對稱的白名單資料結構。

這並非設計疏漏——`analyses` collection 中 `risk_level` 為 `LOW` 的紀錄本身即隱含「已驗證安全」的資訊。值得注意的是，「不在黑名單」與「已驗證安全」並不等價：前者包含了「從未被查詢過」這個不確定狀態。未來若需提供白名單查詢介面，可直接基於既有的 `analyses` 資料建立新的查詢端點，區分「已驗證安全」與「未知」，無需新增、維護第二份平行資料。

### 自動化偵測

目前為被動分析架構，需由使用者或外部系統主動呼叫 API 觸發。若要達成持續監控、自動發現可疑流量，需額外建置感測器層（例如接收伺服器 log 或網路流量），列為後續版本規劃方向。

### 黑名單的封鎖情境涵蓋範圍

`GET /blocklist/check/{target}` 設計初衷為供防火牆等 IP 導向的系統對接查詢。若目標為 domain 且判定為 HIGH 風險，一樣會被記錄進黑名單，但實務上 domain 的封鎖通常需要 DNS 層級的機制（如 DNS sinkhole），與 IP 層級的防火牆規則屬於不同的執行手段。本系統目前僅提供判斷與記錄，未涵蓋這類封鎖機制的整合。

---

## 開發者

邱冠文，2026 年 8 月
