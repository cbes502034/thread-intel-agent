"""Tool Use 迴圈。

原本的實作是寫死的兩次呼叫:第一輪讓模型自由選工具,第二輪強制交報告。
工具的結果永遠不會回饋給模型再做決策 —— 也就是說它等同於「把來源查一遍
再叫 LLM 總結」,用一次固定的 pipeline 就能做完,而且更快更便宜更穩定。

這一版改成真正的迴圈:每一輪的工具結果都回饋進對話,模型可以依據前一輪
查到的東西決定下一步要查什麼,直到它呼叫 submit_report 或觸及輪數上限。
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from time import perf_counter

import anthropic

from config import ANTHROPIC_API_KEY, AgentConfig
from tools.abuseipdb_ import abuseipdb_lookup
from tools.ipwhois_ import ipwhois_lookup
from tools.virustotal_ import virustotal_domain_lookup, virustotal_ip_lookup
from tools.whois_ import whois_lookup
from utils import get_analysis_id

logger = logging.getLogger(__name__)

_client: anthropic.AsyncAnthropic | None = None


def get_anthropic_client() -> anthropic.AsyncAnthropic:
    """共用同一個 client,省去每次請求重建連線池的成本。

    用 Async 版本:同步的 client 在 async 端點裡會鎖住 event loop。
    """
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    return _client


class AgentError(RuntimeError):
    """Agent 無法產出可用的報告。"""


# 工具名稱 -> (實作, 該工具的參數名)
TOOL_DISPATCH = {
    "whois_lookup": (whois_lookup, "domain"),
    "ipwhois_lookup": (ipwhois_lookup, "ip"),
    "abuseipdb_lookup": (abuseipdb_lookup, "ip"),
    "virustotal_ip_lookup": (virustotal_ip_lookup, "ip"),
    "virustotal_domain_lookup": (virustotal_domain_lookup, "domain"),
}

_REPORT_DEFAULTS = {
    "target_type": "ip",
    "risk_level": "UNKNOWN",
    "summary": "",
    "evidence": [],
    "sources_checked": [],
    "recommendation": "",
}


class AI(AgentConfig):
    def __init__(self, user, cache_collection, tool_calls_collection):
        super().__init__()
        self.user = user
        self.cache_collection = cache_collection
        self.tool_calls_collection = tool_calls_collection

        # 先給定預設值,呼叫端就不會因為 run() 中途出狀況而撞上 AttributeError。
        self.analysis_id, self.now = get_analysis_id(return_now=True)
        self.final_report = None
        self.iterations = 0
        self.tool_calls_count = 0
        self.cache_hits = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.duration_ms = 0
        self.stopped_reason = None

    async def run(self):
        start = perf_counter()
        messages = [{
            "role": "user",
            "content": f"請分析這個目標並提交風險報告:{self.user}",
        }]

        try:
            for iteration in range(1, self.MAX_ITERATIONS + 1):
                self.iterations = iteration

                # 最後一輪強制交報告,確保迴圈一定收斂成結構化輸出。
                force_report = iteration == self.MAX_ITERATIONS
                message = await self._call_model(messages, force_report)
                self._accumulate_usage(message)

                messages.append({"role": "assistant", "content": message.content})
                tool_uses = [b for b in message.content if b.type == "tool_use"]

                report_block = next(
                    (b for b in tool_uses if b.name == "submit_report"), None
                )
                if report_block is not None:
                    self.final_report = self._coerce_report(report_block.input)
                    self.stopped_reason = (
                        "max_iterations" if force_report else "submitted"
                    )
                    await self._log_report(iteration, self.final_report)
                    break

                if not tool_uses:
                    # 模型既沒查也沒交報告,直接把它推回正軌。
                    messages.append({
                        "role": "user",
                        "content": "請呼叫 submit_report 工具提交最終的結構化報告。",
                    })
                    continue

                # 同一輪的多個查詢彼此獨立,併發執行可以省下大半等待時間。
                results = await asyncio.gather(
                    *(self._execute_tool(iteration, block) for block in tool_uses)
                )
                messages.append({"role": "user", "content": list(results)})
        finally:
            self.duration_ms = int((perf_counter() - start) * 1000)

        if self.final_report is None:
            raise AgentError("Agent 未能產出結構化報告")

        return self.final_report

    # ------------------------------------------------------------ 模型呼叫
    async def _call_model(self, messages, force_report: bool):
        kwargs = {
            "model": self.MODEL,
            "max_tokens": self.MAX_TOKEN,
            "temperature": self.TEMPERATURE,
            "system": self.AI_SYSTEM_PROMPT,
            "messages": messages,
            "tools": self.ALL_TOOLS,
        }
        if force_report:
            kwargs["tools"] = self.SUBMIT_REPORT_TOOL
            kwargs["tool_choice"] = {"type": "tool", "name": "submit_report"}

        return await get_anthropic_client().messages.create(**kwargs)

    def _accumulate_usage(self, message) -> None:
        """累計每一輪的 token。

        原本只記錄最後一次呼叫的 usage,等於漏掉前面所有輪次 —— 通常還是
        比較大的那幾輪。
        """
        usage = getattr(message, "usage", None)
        if usage is None:
            return
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0

    # ------------------------------------------------------------ 工具執行
    async def _execute_tool(self, iteration: int, block):
        """執行單一工具呼叫,並保證一定回傳一個 tool_result block。

        少回傳任何一個 tool_use 對應的 tool_result,下一次 API 呼叫就會被拒絕,
        所以這裡的每條路徑(含未知工具、參數缺漏、執行失敗)都要有回傳值。
        """
        await self._log_tool_call(iteration, block)
        self.tool_calls_count += 1

        entry = TOOL_DISPATCH.get(block.name)
        if entry is None:
            return await self._tool_result(
                iteration, block,
                {"error": f"未知的工具:{block.name}", "error_type": "unknown_tool"},
                from_cache=False, duration_ms=0, is_error=True,
            )

        func, arg_name = entry
        raw_input = block.input if isinstance(block.input, dict) else {}
        target = raw_input.get(arg_name)
        if not target:
            # 模型偶爾會把參數名寫錯,退而求其次拿第一個字串值。
            target = next(
                (v for v in raw_input.values() if isinstance(v, str) and v), None
            )
        if not target:
            return await self._tool_result(
                iteration, block,
                {
                    "error": f"缺少必要參數 '{arg_name}'",
                    "error_type": "missing_argument",
                },
                from_cache=False, duration_ms=0, is_error=True,
            )

        try:
            result, from_cache, exec_ms = await func(target, self.cache_collection)
        except Exception as exc:
            logger.exception("tool %s failed for %s", block.name, target)
            return await self._tool_result(
                iteration, block,
                {"error": f"工具執行失敗:{exc}", "error_type": "tool_crashed"},
                from_cache=False, duration_ms=0, is_error=True,
            )

        if from_cache:
            self.cache_hits += 1

        is_error = isinstance(result, dict) and "error" in result
        return await self._tool_result(
            iteration, block, result,
            from_cache=from_cache, duration_ms=exec_ms, is_error=is_error,
        )

    async def _tool_result(
        self, iteration, block, result, *, from_cache, duration_ms, is_error
    ):
        await self._log_tool_result(
            iteration, block, result,
            from_cache=from_cache, duration_ms=duration_ms, is_error=is_error,
        )
        return {
            "type": "tool_result",
            "tool_use_id": block.id,
            "is_error": is_error,
            # 原本傳的是 str(result),也就是 Python 的 repr
            # (單引號、datetime(...)、None)。改成 JSON,省 token 也好解析。
            "content": json.dumps(result, ensure_ascii=False, default=str),
        }

    def _coerce_report(self, report):
        """補齊缺漏欄位,讓下游永遠拿得到完整結構。

        強制工具呼叫時若剛好撞到 max_tokens,回傳的 input 可能是殘缺的。
        """
        if not isinstance(report, dict):
            raise AgentError("submit_report 回傳的內容不是物件")

        coerced = dict(_REPORT_DEFAULTS)
        coerced.update({k: v for k, v in report.items() if v is not None})

        if coerced["risk_level"] not in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            coerced["risk_level"] = "UNKNOWN"
        if coerced["target_type"] not in ("ip", "domain"):
            coerced["target_type"] = "ip"
        if not isinstance(coerced["evidence"], list):
            coerced["evidence"] = []
        if not isinstance(coerced["sources_checked"], list):
            coerced["sources_checked"] = []

        return coerced

    # ------------------------------------------------------------ 軌跡紀錄
    async def _log(self, doc) -> None:
        """軌跡是輔助資訊,寫失敗不該讓整次分析失敗。"""
        try:
            await self.tool_calls_collection.insert_one(doc)
        except Exception:
            logger.warning("failed to write trace record", exc_info=True)

    async def _log_tool_call(self, iteration, block) -> None:
        await self._log({
            "analysis_id": self.analysis_id,
            "iteration": iteration,
            "type": "tool_call",
            "tool_name": block.name,
            "input": block.input if isinstance(block.input, dict) else {},
            "timestamp": datetime.now(timezone.utc),
        })

    async def _log_tool_result(
        self, iteration, block, result, *, from_cache, duration_ms, is_error
    ) -> None:
        await self._log({
            "analysis_id": self.analysis_id,
            "iteration": iteration,
            "type": "tool_result",
            "tool_name": block.name,
            "output": result,
            "duration_ms": duration_ms,
            "from_cache": bool(from_cache),
            "error": result.get("error") if is_error and isinstance(result, dict) else None,
            "timestamp": datetime.now(timezone.utc),
        })

    async def _log_report(self, iteration, report) -> None:
        """把最終決策也寫進軌跡。

        原本的版本只記錄第一輪的查詢,最關鍵的「依據這些證據做出什麼判斷」
        那一步反而沒有留下紀錄,可追溯性等於缺了結論。
        """
        await self._log({
            "analysis_id": self.analysis_id,
            "iteration": iteration,
            "type": "report",
            "tool_name": "submit_report",
            "output": report,
            "timestamp": datetime.now(timezone.utc),
        })
