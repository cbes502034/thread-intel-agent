"""API 的請求 / 回應模型。

原本的版本用 `await request.json()` 加手動 `.get()` 取值,等於放棄了 FastAPI
最主要的優勢:`/docs` 上最重要的端點沒有 request schema,不合法的輸入也要等到
下游才炸。這裡把 `backend_contract.md` §3 已經定義好的 schema 補上。

回應模型的欄位刻意大多給預設值 —— 資料庫裡已經有舊格式的文件,不希望單一筆
缺欄位的舊資料就讓整個列表端點 500。
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from validation import InvalidTarget, normalize_target

RiskLevel = Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
TargetType = Literal["ip", "domain"]
Confidence = Literal["high", "medium", "low"]


# ---------------------------------------------------------------- 請求
class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="要分析的 IP 位址或 domain 名稱",
        examples=["8.8.8.8", "example.com"],
    )

    @field_validator("target")
    @classmethod
    def _normalize(cls, value: str) -> str:
        try:
            _, normalized = normalize_target(value)
        except InvalidTarget as exc:
            raise ValueError(str(exc)) from None
        return normalized


class BlocklistCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., min_length=1, max_length=253)
    reason: str = Field(..., min_length=1, max_length=1000)
    risk_level: RiskLevel = "HIGH"
    expire_days: int | None = Field(
        default=None, ge=1, le=3650, description="不填則套用系統預設天數"
    )

    @field_validator("target")
    @classmethod
    def _normalize(cls, value: str) -> str:
        try:
            _, normalized = normalize_target(value)
        except InvalidTarget as exc:
            raise ValueError(str(exc)) from None
        return normalized


# ---------------------------------------------------------------- 分析
class Evidence(BaseModel):
    source: str = ""
    finding: str = ""
    confidence: Confidence | str = "low"


class AnalysisResult(BaseModel):
    risk_level: RiskLevel | str = "UNKNOWN"
    summary: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    sources_checked: list[str] = Field(default_factory=list)
    recommendation: str = ""


class AnalysisMetadata(BaseModel):
    duration_ms: int = 0
    iterations: int = 0
    tool_calls_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_hits: int = 0
    stopped_reason: str | None = None


class AnalysisResponse(BaseModel):
    analysis_id: str
    target: str
    target_type: TargetType | str = "ip"
    created_at: str
    result: AnalysisResult = Field(default_factory=AnalysisResult)
    metadata: AnalysisMetadata = Field(default_factory=AnalysisMetadata)


class AnalysisListItem(BaseModel):
    analysis_id: str
    target: str
    risk_level: RiskLevel | str = "UNKNOWN"
    summary: str = ""
    created_at: str


class AnalysisListResponse(BaseModel):
    items: list[AnalysisListItem]
    total: int
    limit: int
    skip: int


class ThinkingStep(BaseModel):
    analysis_id: str
    iteration: int = 0
    type: str = ""
    tool_name: str | None = None
    input: dict[str, Any] | None = None
    output: Any | None = None
    duration_ms: int | None = None
    from_cache: bool | None = None
    error: str | None = None
    timestamp: str


class ThinkingResponse(BaseModel):
    analysis_id: str
    steps: list[ThinkingStep]


# ---------------------------------------------------------------- 黑名單
class BlocklistItem(BaseModel):
    target: str
    target_type: TargetType | str = "ip"
    reason: str = ""
    risk_level: RiskLevel | str = "UNKNOWN"
    added_by: str = "agent"
    added_at: str
    expires_at: str
    analysis_id: str | None = None


class BlocklistResponse(BaseModel):
    items: list[BlocklistItem]
    total: int


class BlocklistCheckResponse(BaseModel):
    target: str
    blocked: bool
    reason: str | None = None
    risk_level: RiskLevel | str | None = None
    expires_at: str | None = None


class DeleteResponse(BaseModel):
    success: bool
    target: str


# ---------------------------------------------------------------- 系統
class HealthResponse(BaseModel):
    status: str
    database: str


class StatsResponse(BaseModel):
    total_analyses: int
    high_risk_ratio: float
    cache_hit_rate: float
    blocklist_size: int
