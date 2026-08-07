# 後端 API 契約書 — 給後端開發用

> 前端已經寫死,只要後端照這份契約實作,前端不用改一行就能跑。
> 這是「合約」,任何欄位名稱、型別、path、method 都不能改。

---

## 目錄

1. [基本規範](#1-基本規範)
2. [API Endpoints 契約](#2-api-endpoints-契約)
3. [Schema 定義](#3-schema-定義)
4. [錯誤格式](#4-錯誤格式)
5. [API Key 注入方式](#5-api-key-注入方式)
6. [部署設定](#6-部署設定)
7. [驗收清單](#7-驗收清單)

---

## 1. 基本規範

### 1.1 Base URL

**同源部署** — 前端跟後端在同一個服務,前端會用相對路徑 `/api/v1/*`。

**FastAPI 必須這樣設定:**

```python
from fastapi.staticfiles import StaticFiles

# API 路由要先掛
app.include_router(analyses_router, prefix="/api/v1")
app.include_router(system_router, prefix="/api/v1")
app.include_router(blocklist_router, prefix="/api/v1")

# static 一定要最後掛(不然會蓋過 API)
app.mount("/", StaticFiles(directory="static", html=True), name="static")
```

### 1.2 Content-Type

- Request:`application/json`
- Response:`application/json`

### 1.3 認證

- Header 名稱:`X-API-Key`
- Value:後端 `.env` 裡的 `API_KEY`
- **哪些要驗證見 §2 每個 endpoint 的表格**

### 1.4 CORS

**不需要設定**(同源部署)。

---

## 2. API Endpoints 契約

### 總表

| # | Method | Path | 需要驗證 | 用途 |
|---|---|---|---|---|
| 1 | GET | `/api/v1/health` | ❌ | 健康檢查 |
| 2 | GET | `/api/v1/system/stats` | ❌ | 指標卡數據 |
| 3 | POST | `/api/v1/analyses` | ✅ | 建立分析 |
| 4 | GET | `/api/v1/analyses` | ✅ | 分析列表 |
| 5 | GET | `/api/v1/analyses/{id}` | ✅ | 單筆詳情 |
| 6 | GET | `/api/v1/analyses/{id}/thinking` | ✅ | 思考過程 |
| 7 | GET | `/api/v1/blocklist` | ✅ | 黑名單列表 |
| 8 | POST | `/api/v1/blocklist` | ✅ | 手動加入 |
| 9 | DELETE | `/api/v1/blocklist/{ip}` | ✅ | 移除 |
| 10 | GET | `/api/v1/blocklist/check/{ip}` | ❌ | 快速查詢(給防火牆對接) |

---

### 2.1 GET /api/v1/health

**驗證:** 不需要

**Response 200:**
```json
{
  "status": "ok"
}
```

**前端用途:** 頁面載入時 ping 一下,更新右上角「API Connected」狀態。

---

### 2.2 GET /api/v1/system/stats

**驗證:** 不需要

**Response 200:**
```json
{
  "total_analyses": 47,
  "high_risk_ratio": 0.32,
  "cache_hit_rate": 0.65,
  "blocklist_size": 12
}
```

**欄位說明:**

| 欄位 | 型別 | 範圍 | 說明 |
|---|---|---|---|
| `total_analyses` | int | ≥ 0 | 累計分析次數 |
| `high_risk_ratio` | float | 0.0 ~ 1.0 | HIGH 佔比(不是百分比) |
| `cache_hit_rate` | float | 0.0 ~ 1.0 | 快取命中率 |
| `blocklist_size` | int | ≥ 0 | 目前黑名單數量 |

**前端用途:** 首頁 4 個指標卡。

**⚠️ 注意:** `high_risk_ratio` 和 `cache_hit_rate` 是 **0.0 到 1.0 的小數**,不是 0-100。前端會自己 * 100 顯示。

---

### 2.3 POST /api/v1/analyses

**驗證:** ✅ 需要

**Request Body:**
```json
{
  "target": "8.8.8.8"
}
```

**欄位說明:**

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `target` | string | ✅ | IP 或 domain |

**Response 201:**
```json
{
  "analysis_id": "ana_20260806_a3f2c1",
  "target": "8.8.8.8",
  "target_type": "ip",
  "created_at": "2026-08-06T14:23:00Z",
  "result": {
    "risk_level": "HIGH",
    "summary": "此 IP 被多個情資來源標記為惡意...",
    "evidence": [
      {
        "source": "AbuseIPDB",
        "finding": "被檢舉 5,247 次,信心分數 100%",
        "confidence": "high"
      }
    ],
    "sources_checked": ["abuseipdb", "virustotal", "whois"],
    "recommendation": "建議立即在防火牆封鎖此 IP"
  },
  "metadata": {
    "duration_ms": 3200,
    "iterations": 3,
    "tool_calls_count": 3,
    "input_tokens": 1250,
    "output_tokens": 480,
    "cache_hits": 1
  }
}
```

**欄位說明:**

| 欄位 | 型別 | 說明 |
|---|---|---|
| `analysis_id` | string | 業務 ID,格式 `ana_YYYYMMDD_XXXXXX` |
| `target` | string | 原始輸入 |
| `target_type` | string | `"ip"` 或 `"domain"` |
| `created_at` | string | ISO 8601 時間 |
| `result.risk_level` | string | **必須是** `"HIGH"`、`"MEDIUM"`、`"LOW"`、`"UNKNOWN"` 之一 |
| `result.summary` | string | 摘要文字 |
| `result.evidence` | array | 證據列表(見下方) |
| `result.sources_checked` | array of string | 用過的 tool 名稱 |
| `result.recommendation` | string | 建議動作 |
| `metadata.*` | 各種 int | 執行元資訊,前端會直接顯示 |

**Evidence 物件:**

| 欄位 | 型別 | 說明 |
|---|---|---|
| `source` | string | 來源名(顯示用,如 `"AbuseIPDB"`) |
| `finding` | string | 發現內容 |
| `confidence` | string | **必須是** `"high"`、`"medium"`、`"low"` 之一 |

**⚠️ 關鍵:** 
- 如果 `risk_level === "HIGH"`,**後端要自動加入黑名單**(前端不會呼叫,是後端 side effect)
- 前端會用 `risk_level` 來決定顏色,值必須完全對上(大寫)

---

### 2.4 GET /api/v1/analyses

**驗證:** ✅ 需要

**Query Parameters:**

| 參數 | 型別 | 預設 | 說明 |
|---|---|---|---|
| `limit` | int | 50 | 每頁筆數 |
| `skip` | int | 0 | 偏移量 |
| `risk_level` | string | (無) | 篩選:`HIGH` / `MEDIUM` / `LOW` |

**Response 200(兩種格式都接受):**

**格式 A(有 envelope,推薦):**
```json
{
  "items": [
    {
      "analysis_id": "ana_20260806_001",
      "target": "185.220.101.42",
      "risk_level": "HIGH",
      "summary": "已知 Tor exit node...",
      "created_at": "2026-08-06T14:23:00Z"
    }
  ],
  "total": 47,
  "limit": 50,
  "skip": 0
}
```

**格式 B(直接陣列,也接受):**
```json
[
  {
    "analysis_id": "ana_20260806_001",
    "target": "185.220.101.42",
    "risk_level": "HIGH",
    "summary": "已知 Tor exit node...",
    "created_at": "2026-08-06T14:23:00Z"
  }
]
```

**⚠️ 注意:** 前端會用 `resp.items || resp` 兩種都適配,你選一種就好。**推薦格式 A**(更 RESTful)。

**單筆的欄位(精簡版):**

| 欄位 | 說明 |
|---|---|
| `analysis_id` | 業務 ID |
| `target` | 分析對象 |
| `risk_level` | 大寫 |
| `summary` | 摘要 |
| `created_at` | ISO 時間 |

**這是精簡版,不需要 result 完整內容(evidence 之類)。點進去看詳細時前端會另外呼叫 §2.5。**

---

### 2.5 GET /api/v1/analyses/{analysis_id}

**驗證:** ✅ 需要

**Path Parameter:**
- `analysis_id`:業務 ID

**Response 200:** 完整版,結構跟 §2.3 的 response 完全一樣。

**Response 404:**
```json
{
  "error": "not_found",
  "detail": "Analysis not found"
}
```

---

### 2.6 GET /api/v1/analyses/{analysis_id}/thinking

**驗證:** ✅ 需要

**Response 200:**
```json
{
  "analysis_id": "ana_20260806_a3f2c1",
  "steps": [
    {
      "iteration": 1,
      "type": "thinking",
      "content": "這是一個 IP 位址,先查 AbuseIPDB",
      "timestamp": "2026-08-06T14:23:00.100Z"
    },
    {
      "iteration": 1,
      "type": "tool_call",
      "tool_name": "abuseipdb_lookup",
      "input": { "ip": "185.220.101.42" },
      "timestamp": "2026-08-06T14:23:00.200Z"
    },
    {
      "iteration": 1,
      "type": "tool_result",
      "tool_name": "abuseipdb_lookup",
      "output": { "reports": 5247, "confidence": 100 },
      "duration_ms": 420,
      "from_cache": false,
      "timestamp": "2026-08-06T14:23:00.620Z"
    }
  ]
}
```

**Step 物件三種類型:**

**Type = "thinking":**
```json
{
  "iteration": 1,
  "type": "thinking",
  "content": "...",
  "timestamp": "ISO time"
}
```

**Type = "tool_call":**
```json
{
  "iteration": 1,
  "type": "tool_call",
  "tool_name": "abuseipdb_lookup",
  "input": { ... },
  "timestamp": "ISO time"
}
```

**Type = "tool_result":**
```json
{
  "iteration": 1,
  "type": "tool_result",
  "tool_name": "abuseipdb_lookup",
  "output": { ... },
  "duration_ms": 420,
  "from_cache": false,
  "timestamp": "ISO time"
}
```

**⚠️ 關鍵:**
- `type` 必須是 `"thinking"` / `"tool_call"` / `"tool_result"` 之一(小寫、底線)
- `input` 和 `output` 是任意 JSON 物件,前端會 `JSON.stringify` 顯示
- steps 陣列要**按時間順序**排好

---

### 2.7 GET /api/v1/blocklist

**驗證:** ✅ 需要

**Response 200(兩種格式都接受):**

**格式 A:**
```json
{
  "items": [
    {
      "ip": "185.220.101.42",
      "reason": "已知 Tor exit node",
      "risk_level": "HIGH",
      "added_by": "agent",
      "added_at": "2026-08-06T14:23:00Z",
      "expires_at": "2026-09-05T14:23:00Z",
      "analysis_id": "ana_20260806_001"
    }
  ],
  "total": 12
}
```

**格式 B:** 直接陣列。

**單筆欄位:**

| 欄位 | 型別 | 說明 |
|---|---|---|
| `ip` | string | IP 位址 |
| `reason` | string | 加入理由 |
| `risk_level` | string | `"HIGH"` 或 `"MEDIUM"` |
| `added_by` | string | **必須是** `"agent"` 或 `"manual"` |
| `added_at` | string | ISO 時間 |
| `expires_at` | string | ISO 時間 |
| `analysis_id` | string 或 null | 關聯的分析 ID(手動加入可為 null) |

---

### 2.8 POST /api/v1/blocklist

**驗證:** ✅ 需要

**Request Body:**
```json
{
  "ip": "1.2.3.4",
  "reason": "手動加入 - 內部政策",
  "risk_level": "HIGH"
}
```

**欄位說明:**

| 欄位 | 必填 | 說明 |
|---|---|---|
| `ip` | ✅ | IP 位址 |
| `reason` | ✅ | 理由 |
| `risk_level` | ✅ | `"HIGH"` 或 `"MEDIUM"` |

**Response 201:** 回傳新建的 blocklist 物件(結構同 §2.7 單筆)。

**注意:** 手動加入時 `added_by` 自動設 `"manual"`,`analysis_id` 為 null,`expires_at` 後端決定(建議 30 天)。

---

### 2.9 DELETE /api/v1/blocklist/{ip}

**驗證:** ✅ 需要

**Path Parameter:**
- `ip`:要移除的 IP

**Response 200 或 204:**
```json
{
  "success": true,
  "ip": "185.220.101.42"
}
```

或直接 204 No Content 也可以。

**Response 404:** 該 IP 不在黑名單。

---

### 2.10 GET /api/v1/blocklist/check/{ip}

**驗證:** ❌ 不需要(這是給機器對接的公開查詢 endpoint)

**Path Parameter:**
- `ip`:要檢查的 IP

**Response 200:**
```json
{
  "ip": "185.220.101.42",
  "blocked": true,
  "reason": "已知 Tor exit node",
  "risk_level": "HIGH",
  "expires_at": "2026-09-05T14:23:00Z"
}
```

**如果不在名單:**
```json
{
  "ip": "8.8.8.8",
  "blocked": false
}
```

**這個 endpoint 前端不會呼叫**,是設計給防火牆對接時用的:

```bash
# 防火牆自動化範例
if curl -s http://api/api/v1/blocklist/check/1.2.3.4 | jq -r .blocked | grep -q true; then
    iptables -A INPUT -s 1.2.3.4 -j DROP
fi
```

---

## 3. Schema 定義(Pydantic 版本)

**直接抄下面的定義到 `app/schemas/`,前端保證能對上:**

### 3.1 `schemas/analysis.py`

```python
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime

class AnalysisCreateRequest(BaseModel):
    target: str

class Evidence(BaseModel):
    source: str
    finding: str
    confidence: Literal["high", "medium", "low"]

class AnalysisResult(BaseModel):
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    summary: str
    evidence: list[Evidence]
    sources_checked: list[str]
    recommendation: str

class AnalysisMetadata(BaseModel):
    duration_ms: int
    iterations: int
    tool_calls_count: int
    input_tokens: int
    output_tokens: int
    cache_hits: int

class AnalysisResponse(BaseModel):
    analysis_id: str
    target: str
    target_type: Literal["ip", "domain"]
    created_at: datetime
    result: AnalysisResult
    metadata: AnalysisMetadata

class AnalysisListItem(BaseModel):
    """列表用的精簡版"""
    analysis_id: str
    target: str
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    summary: str
    created_at: datetime

class AnalysisListResponse(BaseModel):
    items: list[AnalysisListItem]
    total: int
    limit: int
    skip: int
```

### 3.2 `schemas/thinking.py`

```python
from pydantic import BaseModel
from typing import Literal, Any, Optional
from datetime import datetime

class ThinkingStep(BaseModel):
    iteration: int
    type: Literal["thinking", "tool_call", "tool_result"]
    timestamp: datetime
    # thinking 用
    content: Optional[str] = None
    # tool_call / tool_result 用
    tool_name: Optional[str] = None
    input: Optional[dict] = None
    output: Optional[dict] = None
    # tool_result 用
    duration_ms: Optional[int] = None
    from_cache: Optional[bool] = None

class ThinkingResponse(BaseModel):
    analysis_id: str
    steps: list[ThinkingStep]
```

### 3.3 `schemas/blocklist.py`

```python
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime

class BlocklistCreateRequest(BaseModel):
    ip: str
    reason: str
    risk_level: Literal["HIGH", "MEDIUM"]

class BlocklistItem(BaseModel):
    ip: str
    reason: str
    risk_level: Literal["HIGH", "MEDIUM"]
    added_by: Literal["agent", "manual"]
    added_at: datetime
    expires_at: datetime
    analysis_id: Optional[str] = None

class BlocklistListResponse(BaseModel):
    items: list[BlocklistItem]
    total: int

class BlocklistCheckResponse(BaseModel):
    ip: str
    blocked: bool
    reason: Optional[str] = None
    risk_level: Optional[str] = None
    expires_at: Optional[datetime] = None
```

### 3.4 `schemas/system.py`

```python
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str = "ok"

class StatsResponse(BaseModel):
    total_analyses: int
    high_risk_ratio: float  # 0.0 ~ 1.0
    cache_hit_rate: float   # 0.0 ~ 1.0
    blocklist_size: int
```

---

## 4. 錯誤格式

**所有錯誤 response 統一格式:**

```json
{
  "error": "error_code",
  "detail": "Human readable message"
}
```

**Status Code 表:**

| Status | error_code | 情境 |
|---|---|---|
| 400 | `invalid_input` | target 格式錯 |
| 401 | `unauthorized` | API Key 錯或缺 |
| 404 | `not_found` | 資源不存在 |
| 422 | `validation_error` | Pydantic 驗證失敗 |
| 429 | `upstream_rate_limited` | 外部 API 超額 |
| 500 | `internal_error` | 系統錯 |
| 502 | `upstream_error` | 外部 API 失敗 |

**前端會抓 `detail` 顯示給使用者。** 所以 detail 要寫得清楚。

**FastAPI 統一錯誤處理範例:**

```python
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": _status_to_code(exc.status_code),
            "detail": exc.detail,
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "detail": str(exc.errors()[0]) if exc.errors() else "Validation failed",
        }
    )

def _status_to_code(status: int) -> str:
    return {
        400: "invalid_input",
        401: "unauthorized",
        404: "not_found",
        422: "validation_error",
        429: "upstream_rate_limited",
        500: "internal_error",
        502: "upstream_error",
    }.get(status, "error")
```

---

## 5. API Key 注入方式

前端 fetch 會自動帶 `X-API-Key: ${window.API_KEY}`,所以你要**在 index.html 送出前**把 `window.API_KEY` 注入進去。

### 方法:FastAPI 動態注入 index.html

**不用 template 引擎,直接讀檔改字串:**

**`app/api/frontend.py`(新增):**

```python
from fastapi import APIRouter, Response
from pathlib import Path
from app.config import settings

router = APIRouter()

# 讀一次快取
_INDEX_HTML = None

def _load_index() -> str:
    global _INDEX_HTML
    if _INDEX_HTML is None:
        path = Path("static/index.html")
        html = path.read_text(encoding="utf-8")
        # 在 </head> 前注入 API_KEY
        inject = f'<script>window.API_KEY = "{settings.api_key}";</script>\n</head>'
        html = html.replace("</head>", inject)
        _INDEX_HTML = html
    return _INDEX_HTML

@router.get("/", include_in_schema=False)
async def serve_index():
    return Response(content=_load_index(), media_type="text/html")
```

**`app/main.py` 修改:**

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.api import analyses, system, blocklist, frontend

app = FastAPI(title="Threat Intel Agent")

# API 路由
app.include_router(analyses.router, prefix="/api/v1")
app.include_router(system.router, prefix="/api/v1")
app.include_router(blocklist.router, prefix="/api/v1")

# 前端 index.html(動態注入 API_KEY)
app.include_router(frontend.router)

# static 資源(CSS/JS 等,如果有)
app.mount("/static", StaticFiles(directory="static"), name="static")
```

**⚠️ 注意:** 因為 `frontend` router 的 `/` 是 GET,會處理根路徑。static 掛在 `/static/` 底下,避免衝突。

### 為什麼這樣做?

- 前端 `.html` 檔本身**不含** API Key,可以放 GitHub
- 部署時後端從 `.env` 讀 `API_KEY`,注入到 HTML
- 前端 JS 用 `window.API_KEY` 拿到
- 使用者 F12 看 HTML source 會看到,**但這個 key 本來就是給前端用的**,這是「demo/內部工具」的正常設計

---

## 6. 部署設定

### 6.1 目錄結構

```
threat-intel-agent/
├── app/
│   └── ...
├── static/
│   └── index.html      ← 我給的前端檔案放這裡
├── .env
└── docker-compose.yml
```

### 6.2 `.env` 必要變數

```bash
API_KEY=your-secret-key-here
ANTHROPIC_API_KEY=sk-ant-...
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
MONGODB_URI=mongodb://mongo:27017
MONGODB_DB=threat_intel
```

### 6.3 `config.py`

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str
    anthropic_api_key: str
    vt_api_key: str
    abuseipdb_api_key: str
    mongodb_uri: str
    mongodb_db: str = "threat_intel"

    class Config:
        env_file = ".env"

settings = Settings()
```

---

## 7. 驗收清單

**後端做完後,逐一測試:**

### 基本連線

- [ ] 打開 `http://localhost:8000/`,能看到 dashboard
- [ ] 右上角顯示綠燈「API Connected」
- [ ] 4 個指標卡有數字(可能是 0,不影響)

### 分析流程

- [ ] 貼一個 domain(如 `example.com`),按 Analyze
- [ ] 看到 loading spinner 大約 3-5 秒
- [ ] 分析完成後左邊出現 Report Card、右邊出現時間軸
- [ ] Report Card 有:target、risk_level badge、summary、evidence、recommendation
- [ ] 時間軸有:iteration 標籤、type icons(🧠🔧📊)、時間戳
- [ ] 指標卡的「總分析次數」+1

### 高風險自動加黑名單

- [ ] 貼一個已知惡意 IP(如 `185.220.101.42`)
- [ ] 分析完成後 Report Card 顯示「已自動加入黑名單」的紫色提示
- [ ] 右上角跳出 toast「已自動加入黑名單」
- [ ] 切到 Blocklist tab,可以看到剛剛的 IP
- [ ] 該筆 `added_by` 是「🤖 AGENT」(紫色)

### 歷史

- [ ] 切到 History tab,能看到過去分析
- [ ] 點某筆 → 切回 Analyze tab,顯示那筆的完整內容
- [ ] 按 High / Medium / Low 篩選,列表會過濾

### 黑名單

- [ ] Blocklist tab 能看到列表
- [ ] 按「+ 手動加入」跳出 modal
- [ ] 填 IP 送出後,列表出現該筆,`added_by` 是「👤 MANUAL」
- [ ] 按某筆的 ✕ 移除,列表刷新

### 錯誤處理

- [ ] 空字串送出 → 前端不會送(input 空的按鈕沒反應)
- [ ] 無效 target(如亂碼)→ 後端回 400,前端顯示紅色錯誤訊息
- [ ] 沒帶 API Key → 401,前端顯示錯誤

### 對接測試

- [ ] `curl http://localhost:8000/api/v1/blocklist/check/185.220.101.42` 
     不用帶任何 header,回 `{"blocked": true, ...}`

---

## 8. 常見雷點

### 雷 1:欄位名稱大小寫不對
前端寫死了 `HIGH`、`MEDIUM`、`LOW`、`UNKNOWN`。如果後端回 `high` 或 `High`,badge 顏色會壞掉。

### 雷 2:`from_cache` 型別是 boolean
不是 `"true"` 字串,是 `true` boolean。

### 雷 3:時間格式
必須是 ISO 8601(帶 Z 或 timezone offset)。前端會用 `new Date(iso)` 解析。

### 雷 4:steps 陣列要排序
按 timestamp 由小到大排,不然時間軸會亂。

### 雷 5:靜態檔 mount 位置
`app.mount("/static", ...)` 要在 API router **之後**,不然可能蓋過 API。

### 雷 6:忘記寫 Agent 自動加黑名單邏輯
在 `core/agent.py` 分析完後要:
```python
if result.risk_level == "HIGH":
    await blocklist_service.add(
        ip=target,
        reason=result.summary,
        risk_level="HIGH",
        added_by="agent",
        analysis_id=analysis.analysis_id,
    )
```
這是後端的 side effect,**前端不會呼叫**,是後端主動做。

---

## 一句話總結

**這份契約寫死了。後端照這個實作,前端不用改。**

**開發時打開瀏覽器 → 打開 `http://localhost:8000/docs`(Swagger)→ 對照這份契約 → 逐個 endpoint 驗證。**

有任何跟契約不同的地方,就是 bug。修後端,不改前端。
