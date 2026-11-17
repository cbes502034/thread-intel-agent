"""Threat Intel Agent（本機 Ollama 版）。

流程：
1. 查證：AGENT_MODEL 以 tool calling 決定呼叫哪些情資工具（最多 MAX_TOOL_ROUNDS 輪），
   模型漏查的來源由「必查清單」補齊，確保同型別目標每次的證據組成一致
2. 精簡：工具原始輸出 → 精簡證據（evidence.py），原始輸出照舊寫入 tool_calls 供回溯
3. 檢索：以證據組成查詢句，從知識庫取回最相關的判定準則（RAG）
4. 判定：JUDGE_MODEL（LoRA 微調）以 JSON Schema 結構化輸出產生報告

對外介面與原版相同：AI(target, cache_collection, tool_calls_collection)、await run()，
執行後提供 final_report、analysis_id、now、iterations、tool_calls_count、duration_ms、result.usage。
"""
from datetime import datetime, timezone
from time import time
from types import SimpleNamespace

import ollama
from fastapi import HTTPException

from config import AgentConfig, OLLAMA_HOST, RAG_ENABLED, RAG_TOP_K, MAX_TOOL_ROUNDS, LLM_NUM_CTX
from evidence import applicable_tools, build_evidence, compact, query_text, target_facts, to_json
from judge import build_judge_messages, fallback_report, parse_report
from rag.retriever import get_retriever
from tools.whois_ import whois_lookup
from tools.ipwhois_ import ipwhois_lookup
from tools.abuseipdb_ import abuseipdb_lookup
from tools.virustotal_ import virustotal_domain_lookup, virustotal_ip_lookup
from utils import get_analysis_id

# 工具名稱 → (函式, 接受的目標型別)
TOOL_FUNCS = {
    "whois_lookup": (whois_lookup, "domain"),
    "ipwhois_lookup": (ipwhois_lookup, "ip"),
    "abuseipdb_lookup": (abuseipdb_lookup, "ip"),
    "virustotal_ip_lookup": (virustotal_ip_lookup, "ip"),
    "virustotal_domain_lookup": (virustotal_domain_lookup, "domain"),
}
_KIND_ZH = {"ip": "IP", "domain": "網域"}


class AI(AgentConfig):
    def __init__(self, user, cache_collection, tool_calls_collection, client=None, tool_funcs=None, retriever=None):
        super().__init__()
        self.user = user
        self.cache_collection = cache_collection
        self.tool_calls_collection = tool_calls_collection
        self.client = client or ollama.AsyncClient(host=OLLAMA_HOST)
        self.tool_funcs = tool_funcs or TOOL_FUNCS      # 評測時可換成錄製資料
        self.retriever = retriever

    async def run(self):
        start = time()
        self.analysis_id, self.now = get_analysis_id(return_now=True)
        self.target = (self.user or "").strip()
        self.facts = target_facts(self.target)
        self.iterations = 0
        self.tool_calls_count = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.raw_results = {}       # 工具名稱 → 原始輸出（依呼叫順序）
        self.planner_calls = []     # 模型實際提出的工具呼叫（評測工具選擇用）

        await self._collect()
        # 必查清單：同一型別的目標每次都要有同一組證據，判定才會一致。
        # 小模型常查一個工具就停（實測 1.5B 幾乎每次只叫一個），漏掉的情資來源由系統補查。
        self.topped_up = [n for n in applicable_tools(self.target) if n not in self.raw_results]
        if self.topped_up:
            await self._log_thinking("依必查清單補查：" + "、".join(self.topped_up))
            for name in self.topped_up:
                await self._run_tool(name)

        self.evidence = build_evidence(self.target, self.raw_results, self.now)
        self.refs = await self._retrieve()
        self.final_report = await self._judge()
        self.result = SimpleNamespace(usage=SimpleNamespace(input_tokens=self.input_tokens, output_tokens=self.output_tokens))
        self.duration_ms = int((time() - start) * 1000)

    # ---------- 第一輪：查證（tool calling 迴圈） ----------

    async def _collect(self):
        messages = [
            {"role": "system", "content": self.PLANNER_SYSTEM_PROMPT},
            {"role": "user", "content": f"請分析這個目標的風險：{self.target}"},
        ]
        wanted = set(applicable_tools(self.target))
        for _ in range(MAX_TOOL_ROUNDS):
            resp = await self._chat(self.AGENT_MODEL, messages, tools=self.TOOLS)
            calls = resp.message.tool_calls or []
            if not calls:
                break
            messages.append(resp.message)
            for call in calls:
                name = call.function.name
                self.planner_calls.append(name)
                content = await self._handle_call(name)
                messages.append({"role": "tool", "content": content, "tool_name": name})
            if wanted <= set(self.raw_results):   # 適用的工具都查過了，不必再問一輪
                break

    async def _handle_call(self, name):
        if name not in self.tool_funcs:
            return to_json({"error": f"沒有 {name} 這個工具"})
        _, kind = self.tool_funcs[name]
        if kind != self.facts["type"]:
            return to_json({"error": f"{name} 只接受{_KIND_ZH[kind]}，本次目標是{_KIND_ZH[self.facts['type']]}"})
        if name in self.raw_results:
            return to_json({"note": "此工具已查詢過，結果同上"})
        return to_json(await self._run_tool(name))

    async def _run_tool(self, name):
        """執行工具並記錄軌跡；參數一律使用分析目標（小模型常改寫參數）。"""
        func, kind = self.tool_funcs[name]
        await self._log({"type": "tool_call", "tool_name": name, "input": {kind: self.target}})
        t0 = time()
        try:
            result, from_cache, exectime = await func(self.target, self.cache_collection)
        except Exception as e:  # 例如 IPWHOIS 遇到私有位址、WHOIS 查無網域
            result, from_cache, exectime = {"error": f"{type(e).__name__}: {e}"}, False, int((time() - t0) * 1000)
        await self._log({"type": "tool_result", "tool_name": name, "output": result,
                         "duration_ms": exectime, "from_cache": from_cache})
        self.raw_results[name] = result
        self.tool_calls_count += 1
        return compact(name, result, self.now)

    # ---------- RAG ----------

    async def _retrieve(self):
        if not RAG_ENABLED:
            return []
        retriever = self.retriever or get_retriever()
        if retriever is None:
            return []
        try:
            refs = await retriever.search(query_text(self.evidence), self.facts["type"], k=RAG_TOP_K)
        except Exception as e:
            await self._log_thinking(f"RAG 檢索失敗（{type(e).__name__}），本次不帶參考準則")
            return []
        await self._log_thinking("RAG 參考準則：" + "；".join(f"{r['title']}｜{r['heading']}" for r in refs))
        return refs

    # ---------- 第二輪：判定（結構化輸出） ----------

    async def _judge(self):
        messages = build_judge_messages(self.evidence, self.refs)
        report, reason = None, ""
        for _ in range(2):
            resp = await self._chat(self.JUDGE_MODEL, messages, format=self.REPORT_SCHEMA,
                                    options={"num_predict": self.NUM_PREDICT})
            report = parse_report(resp.message.content)
            if report:
                break
            reason = "輸出不是合格的 JSON 報告"
        report = report or fallback_report(self.evidence, reason)
        # 查過哪些來源是事實，以實際呼叫紀錄為準，不採用模型自填的內容
        report["sources_checked"] = list(self.raw_results)
        return report

    # ---------- 共用 ----------

    async def _chat(self, model, messages, tools=None, format=None, options=None):
        opts = {"temperature": 0, "num_ctx": LLM_NUM_CTX, "seed": 42}
        opts.update(options or {})
        try:
            resp = await self.client.chat(model=model, messages=messages, tools=tools, format=format, options=opts)
        except (ollama.ResponseError, ConnectionError, OSError) as e:
            raise HTTPException(status_code=503, detail=f"本機 LLM 服務無法使用（{model}）：{e}")
        self.iterations += 1
        self.input_tokens += resp.prompt_eval_count or 0
        self.output_tokens += resp.eval_count or 0
        return resp

    async def _log(self, doc):
        doc.update({"analysis_id": self.analysis_id, "iteration": self.iterations,
                    "timestamp": datetime.now(timezone.utc)})
        await self.tool_calls_collection.insert_one(doc)

    async def _log_thinking(self, content):
        await self._log({"type": "thinking", "content": content})
