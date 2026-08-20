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
| 多來源交叉分析 | 整合 WHOIS、IPWHOIS、AbuseIPDB、VirusTotal，由 Agent 依前一輪結果決定下一步查什麼 |
| 思考過程可視化 | 完整記錄每一步決策、查詢結果與最終判斷，可回溯「為何判定為高風險」 |
| 自動黑名單 | 判定 HIGH 時自動記錄、判定降級時自動移除，並提供公開查詢 API 供外部系統對接 |
| 快取機制 | 24 小時內重複查詢直接命中快取，避免耗盡外部 API 額度 |
| 用量控管 | per-IP 滑動視窗 + 全站每日總量，公開 demo 也不會被刷爆額度 |
| 統計儀表板 | 總分析次數、高風險比例、快取命中率、黑名單數量 |

---

## 技術棧

| 層級 | 技術 |
| :--- | :--- |
| 後端框架 | FastAPI + Pydantic |
| 資料庫驅動 | pymongo `AsyncMongoClient`（原生 async） |
| LLM | Anthropic Claude（`claude-haiku-4-5`），`AsyncAnthropic` SDK 直接呼叫 |
| 外部查詢 | httpx `AsyncClient`；同步的 whois / ipwhois 以 `asyncio.to_thread` 隔離 |
| 資料庫 | MongoDB Atlas |
| 前端 | Vanilla JS + Tailwind CSS |
| 測試 | pytest + pytest-asyncio |
| 容器化 | Docker |
| 部署平台 | Render（Web Service） |
| 執行環境 | Python 3.12 |

全鏈路非同步：Agent 一次分析要 10-30 秒，過程中若有任何一個同步的 blocking 呼叫（`requests.get`、同步版 Anthropic client、socket 型的 whois 查詢），整個 event loop 會被鎖住——單 worker 部署下，那段時間連 `/health` 都回不了。

---

## 系統流程

1. 使用者透過前端或 API 提交分析目標（IP 或 domain）
2. `POST /api/v1/analyses` 先做輸入驗證與用量檢查，通過後才觸發 Agent
3. Agent 迴圈：判斷該查哪些來源 → 併發執行查詢（經過快取層）→ 結果回饋 → 依結果決定是否再查
4. 模型呼叫 `submit_report` 提交結構化報告，或在觸及輪數上限時被強制提交
5. 分析結果寫入 `analyses`；判定 HIGH 時寫入 `blocklist`，判定降級時將既有紀錄移除
6. 每一步決策軌跡（含最終判斷）寫入 `tool_calls`，供後續回溯查詢
7. 回傳結構化 JSON，前端渲染報告與思考時間軸

---

## Agent 核心機制

系統未使用 LangChain 等框架，直接呼叫 Anthropic SDK 實作 Tool Use 迴圈，讓每一步決策保持透明可控，也便於除錯。

### 迴圈:結果回饋驅動下一步

每一輪的工具結果都會回饋進對話，模型據此決定下一步要查什麼，直到它呼叫 `submit_report` 或觸及輪數上限：

```python
for iteration in range(1, self.MAX_ITERATIONS + 1):
    message = await self._call_model(messages, force_report=iteration == self.MAX_ITERATIONS)
    messages.append({"role": "assistant", "content": message.content})

    if report_block := find_submit_report(message.content):
        break

    results = await asyncio.gather(*(self._execute_tool(iteration, b) for b in tool_uses))
    messages.append({"role": "user", "content": list(results)})
```

**為什麼這件事重要：** 早期版本是寫死的兩次呼叫（第一輪選工具、第二輪交報告），工具結果永遠不會回饋。那個結構下的「Agent」其實可以被一個固定 pipeline 完全取代——查完所有來源、丟給 LLM 總結，一次呼叫就能做完，而且更快、更便宜、結果更穩定。付出了 Agent 的成本（不確定性、雙倍 token 與延遲）卻沒拿到 Agent 的好處（多跳推理），是不划算的交換。

改成真迴圈之後，模型才能做到「查了 A 發現異常 → 因此再去查 B」這種依賴前一步結果的推理。同一輪內的多個查詢則用 `asyncio.gather` 併發執行，三個來源約可省下三分之二的等待時間。

### 收斂保證：最後一輪強制交報告

迴圈必須有終點。最後一輪改用 `tool_choice` 強制 Claude 呼叫 `submit_report`，並依預先定義的 `input_schema` 填寫內容：

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

### 風險等級判定：明確門檻，而非自由心證

由 Claude 綜合多來源證據判斷，但判定門檻寫死在 system prompt 裡：

```
- HIGH:AbuseIPDB abuseConfidenceScore >= 75
       或 VirusTotal last_analysis_stats.malicious >= 5
       或 兩個以上獨立來源明確指出涉及惡意活動
- MEDIUM:abuseConfidenceScore 介於 25-74,或 malicious 介於 1-4,
         或具備高風險特徵(Tor 出口節點、匿名代理、新註冊網域)但無明確惡意證據
```

**為什麼加門檻：** 早期版本只給模型四個等級的文字描述，讓它自由心證。實際跑出來的結果是同一個目標（185.220.101.42）在同一份快取資料上，跑出過 HIGH 與 MEDIUM 兩種結論——證據沒變，結論卻變了。對一個會自動觸發封鎖的系統來說，這種不一致是不能接受的。

現在的作法是：**判斷標準由人訂，證據的蒐集與解讀交給模型。** 搭配 `temperature=0`，同樣的證據應該收斂到同樣的結論。這是規則引擎與 Agent 之間的折衷——模型的價值在於它能理解各來源格式迥異的原始資料並產出人類可讀的推理，而不在於它能自己發明風險門檻。

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
| TTL | 24 小時，過期後視為未命中並重新查詢；MongoDB TTL 索引負責實際清除 |
| 命中判斷 | 回傳 `(是否命中, 值)`，而非靠值本身的真假 |
| 錯誤處理 | 工具回報 error 時**不寫入快取** |
| 命中率 | 即時反映於 `GET /api/v1/system/stats` 的 `cache_hit_rate` |

Key 加上工具名稱前綴，是為了避免不同工具對同一目標的查詢結果互相覆蓋。

**兩個容易忽略的坑：**

*命中判斷不能靠真假值。* 早期用 `if cache:` 判斷是否命中，但快取值是空 dict 或空 list 時會被當成未命中，每次都重打外部 API——對一個以節省額度為目的的機制來說，這正好在最該生效的邊界失效。

*錯誤不該進快取。* VirusTotal 免費層每分鐘只有 4 次請求。若把一次 429 的回應也寫進快取，那個目標接下來 24 小時都只會拿到同一個錯誤——一次暫時性失敗被醃成一整天的失效，跟快取的目的完全相反。現在 `is_cacheable()` 會擋掉所有含 `error` 欄位的結果。

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

資料庫的連線與釋放邏輯集中於 `database.py`，以 FastAPI 的 `lifespan` 機制管理生命週期。連線於應用程式啟動時建立一次，各 collection 的操作介面掛載於 `app.state`，供各 router 透過 `request.app.state.{collection}` 取用，避免每次請求重複建立連線：

```python
# database.py
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

`main.py` 只需引入並掛載，本身不涉及任何資料庫細節：

```python
# main.py
from database import lifespan

app = FastAPI(lifespan=lifespan)
```

這讓 `main.py` 的職責單純化為「組裝應用程式」——連線設定、資料庫名稱、collection 命名等細節都封裝在 `database.py`，未來若要更換資料庫或調整連線策略，修改範圍不會擴散到入口檔案。

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

### 判定降級時自動移除

黑名單跟著最新一次的判定走。若同一目標後續被判定為非 HIGH，Agent 加入的紀錄會被移除：

```python
removed = await collection.delete_one({"target": target, "added_by": "agent"})
```

早期版本只有「判到 HIGH 就加入」這一個方向，導致黑名單是單向棘輪——一旦進去就出不來。實際資料中 `185.220.101.42` 第一次判 HIGH 後，後續三次都判 MEDIUM，紀錄卻一直留著。

只移除 `added_by == "agent"` 的項目：人工加入的封鎖代表管理者的明確決定，不該被自動推翻。

### 過期時效

`expires_at` 在**查詢時實際生效**，而非只是一個存起來好看的欄位：

```python
def _active_filter():
    return {"expires_at": {"$gt": datetime.now(timezone.utc)}}
```

`GET /blocklist`、`GET /blocklist/check/{target}` 與 `/system/stats` 的 `blocklist_size` 都套用同一個條件，三邊的數字才會一致。早期版本的查詢完全沒有比對 `expires_at`，所以「30 天過期」在程式裡其實不存在。

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

**`report`**（最終判斷）

```json
{
  "type": "report",
  "tool_name": "submit_report",
  "output": {"risk_level": "HIGH", "summary": "..."},
  "timestamp": "2026-08-10T06:59:05Z"
}
```

`GET /analyses/{id}/thinking` 依 `analysis_id` 查詢並按時間排序回傳，前端據此還原完整的決策時間軸——包含查詢了哪些來源、各花費多少時間、是否命中快取、哪些來源查詢失敗。

早期版本只記錄第一輪的查詢，最關鍵的「依據這些證據做出什麼判斷」那一步反而沒有留下紀錄——可追溯性缺了結論本身。現在 `submit_report` 也會寫進軌跡。

這讓每一次的風險判斷都具備可回溯的完整脈絡，而非僅呈現最終結論。

---

## API 一覽

| Method | Path | 說明 | 保護方式 |
| :--- | :--- | :--- | :--- |
| GET | `/api/v1/system/health` | 健康檢查（含資料庫連線） | — |
| GET | `/api/v1/system/stats` | 儀表板統計數據 | — |
| POST | `/api/v1/analyses` | 建立分析（觸發 Agent） | 用量限制 |
| GET | `/api/v1/analyses` | 分析歷史列表（`limit` / `skip`） | — |
| GET | `/api/v1/analyses/{id}` | 單筆分析詳情 | — |
| GET | `/api/v1/analyses/{id}/thinking` | 該筆分析的完整思考過程 | — |
| GET | `/api/v1/blocklist` | 黑名單列表（僅未過期項目） | — |
| POST | `/api/v1/blocklist` | 人工加入黑名單 | Admin Key |
| DELETE | `/api/v1/blocklist/{target}` | 移除黑名單項目 | Admin Key |
| GET | `/api/v1/blocklist/check/{target}` | 查詢是否在黑名單（供外部系統對接） | — |

Admin Key 透過 `X-API-Key` header 傳送。完整規格請見 [`/docs`](https://thread-intel-agent.onrender.com/docs)。

---

## API 設計原則

| 原則 | 說明 |
| :--- | :--- |
| RESTful 慣例 | URL 僅描述資源，操作語意由 HTTP 方法表達，路徑中不出現動詞 |
| 列表與詳情分離 | `GET /analyses` 僅回傳摘要欄位，完整內容另行呼叫 `GET /analyses/{id}`，避免列表查詢傳輸過量資料 |
| 版本化路徑 | 所有端點統一置於 `/api/v1/` 前綴，為未來的破壞性變更保留相容空間 |
| 輸入在邊界驗證 | 請求以 Pydantic 模型定義，不合法的目標在進入 Agent 之前就被擋下並回 422 |
| 保護方式對應風險 | 花錢的端點用用量限制、改變狀態的端點用金鑰，兩者的威脅模型不同 |

### 為什麼分析端點不用 API Key 保護

`POST /analyses` 是唯一會直接產生費用的端點（LLM token + 外部 API 額度）。它需要被「公開 demo 可以試用」與「不能被人刷爆」同時滿足——而 API Key 解不了這個問題：前端要能呼叫，Key 就得下發到瀏覽器；下發到瀏覽器，Key 就是公開的。

早期版本正是這個狀況：Key 以字面值寫死在 `index.html` 裡，任何人檢視原始碼就能取得，那層 `Depends(verify_api_key)` 實質上沒有防護力。

現在改成用**伺服器端的用量限制**保護，分兩層：

| 層級 | 預設值 | 擋什麼 |
| :--- | :--- | :--- |
| per-IP 滑動視窗 | 每 60 分鐘 5 次 | 單一使用者的連點與腳本重跑 |
| 全站每日總量 | 每日 200 次 | per-IP 可以換 IP 繞過，這層才是真正的預算天花板 |

限流紀錄計算的是**嘗試次數**而非成功次數——失敗的分析一樣燒掉了 token，不該不算數。

Admin Key 則只保護 `POST` / `DELETE /blocklist` 這類改變系統狀態的操作，並且**永遠不下發到前端**：需要用時由使用者自行在介面貼上，只存在該瀏覽分頁的 `sessionStorage`。伺服器端若未設定 `ADMIN_API_KEY`，這些端點一律回 503（fail closed），而不是在沒有金鑰的狀態下開著。

### 前端輸出跳脫

所有插入 DOM 的值都先經過跳脫。這在這個專案裡有兩條不可信路徑：使用者輸入的 `target`（會存進資料庫並重播給所有訪客），以及 **LLM 產生的 `summary` / `evidence`**——後者意味著針對工具回傳內容的 prompt injection 可以一路打成 stored XSS。system prompt 中也加了一段，明確要求把工具回傳的內容當作資料而非指令。

---

## 模組結構

```
thread-intel-agent/
├── main.py              # 應用程式入口、路由掛載、安全標頭
├── database.py          # MongoDB 連線、生命週期管理、索引建立
├── config.py            # 環境變數、Agent 設定(system prompt、tools schema)
├── agent.py             # AI class:Tool Use 迴圈核心邏輯
├── schemas.py           # Pydantic 請求 / 回應模型
├── validation.py        # 目標(IP / domain)正規化與驗證
├── ratelimit.py         # 分析端點的用量控管
├── utils.py             # 快取裝飾器、計時裝飾器、ID 產生、金鑰驗證
├── cache.py             # 快取讀寫邏輯
├── routers/
│   ├── system.py        # 健康檢查、儀表板統計
│   ├── analyses.py      # 分析建立、查詢、思考過程
│   └── blocklist.py     # 黑名單查詢、新增、移除、對外驗證端點
├── tools/
│   ├── http_client.py   # 共用的 async HTTP client
│   ├── normalize.py     # 外部回應的序列化與瘦身
│   ├── whois_.py
│   ├── ipwhois_.py
│   ├── abuseipdb_.py
│   └── virustotal_.py
├── tests/               # pytest:驗證、快取、Agent 迴圈、API 層
├── docs/
│   └── backend_contract.md
├── static/              # 前端(僅前端資產)
├── Dockerfile
├── pytest.ini
├── requirements.txt
└── requirements-dev.txt
```

`static/` 掛載在 `/` 之下，等於整個目錄對外公開，所以裡面只放前端資產——內部的設計文件放在 `docs/`，不隨網站對外提供。

路由依職責拆分為獨立模組。`main.py` 以巢狀 `APIRouter` 統一管理版本前綴，各功能模組的 router 掛載於其下：

```python
from database import lifespan
from routers import analyses, blocklist, system

main_router = APIRouter(prefix="/api/v1")
main_router.include_router(analyses.router)   # router 內部 prefix="/analyses"
main_router.include_router(blocklist.router)  # router 內部 prefix="/blocklist"
main_router.include_router(system.router)     # router 內部 prefix="/system"

app = FastAPI(lifespan=lifespan)
app.include_router(main_router)
```

這讓「版本前綴」與「資源路徑」的管理職責分離——版本變更只需修改 `main.py` 一處，各功能模組不需感知自己的完整 URL 路徑。

---

## 本機開發

環境需求：Python 3.12

```bash
# 安裝套件
pip install -r requirements.txt

# 設定環境變數
cp .env.example .env    # 再填入實際值

# 啟動
uvicorn main:app --reload
```

必要的環境變數見 [`.env.example`](.env.example)。`ADMIN_API_KEY` 請自行產生一組亂數：

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 測試

```bash
pip install -r requirements-dev.txt
pytest
```

測試不連資料庫、不打外部 API、不呼叫 LLM——`app.state` 上的 collection 換成記憶體中的假物件，Anthropic client 與工具也都以假實作替換。涵蓋範圍：

| 檔案 | 測什麼 |
| :--- | :--- |
| `test_validation.py` | 目標正規化、無效輸入、保留網段的拒絕 |
| `test_cache.py` | 命中 / 未命中 / 過期、錯誤不進快取 |
| `test_agent.py` | 迴圈是否真的把結果回饋、token 累計、工具例外的收斂、強制收斂 |
| `test_api.py` | 輸入驗證、限流、金鑰保護、黑名單過期與降級、排序分頁 |

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
| 埠號 | 容器以 `${PORT:-8000}` 啟動，交由平台指定；寫死埠號在換平台時會失效 |
| 執行身分 | 容器內以非 root 的 `appuser` 執行 |

部署前請確認 Render 上已設定 `ADMIN_API_KEY`（舊的 `API_KEY` 仍可作為後備讀取）。未設定時，`POST` / `DELETE /blocklist` 會一律回 503。

---

## 已知限制與後續規劃

### 判定一致性尚未量化

判定門檻已寫進 prompt、`temperature` 也設為 0，但目前**沒有一組標註好的測試集能證明準確率與一致性實際改善了多少**。這是下一步最該補的東西：建立 30-50 個 ground truth（Tor 出口節點、已知 C2、公開 DNS、大型 CDN、新註冊的釣魚站），量測準確率、同一目標重跑數次的結論一致性，以及每次分析的 token 成本。

沒有這把尺，任何 prompt 或架構調整都只能憑感覺說「應該有變好」。

### 多跳關聯調查

迴圈架構已經就緒，但目前的五個工具彼此獨立——查 IP 的三個來源之間沒有依賴關係，所以模型實際上很少需要用到第二輪以後的推理。要讓迴圈真正發揮價值，需要能互相牽引的工具：

- Reverse DNS / Passive DNS（IP ↔ domain 互查）
- 同 ASN / 同網段的其他已知惡意目標
- domain 的歷史解析 IP、憑證關聯

有了這些，才會出現「查 domain → 解析到 IP X → X 同網段有多個已知釣魚站 → 因此判定 HIGH」這種單靠固定 pipeline 做不到的調查鏈。

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
