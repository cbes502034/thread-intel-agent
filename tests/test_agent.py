"""Agent 迴圈的行為測試。

重點在驗證這一版真的是迴圈:工具結果會回饋給模型,模型可以依據前一輪的
結果再決定下一步 —— 舊版寫死兩次呼叫,做不到這件事。
"""

import pytest

import agent as agent_module
from agent import AI, AgentError

from conftest import FakeCollection


class Block:
    def __init__(self, type_, name=None, input_=None, id_="tu_1"):
        self.type = type_
        self.name = name
        self.input = input_
        self.id = id_


class Usage:
    def __init__(self, input_tokens=100, output_tokens=50):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class Message:
    def __init__(self, content, usage=None):
        self.content = content
        self.usage = usage or Usage()


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def create(self, **kwargs):
        # messages 這個 list 之後還會繼續被 append,存參照的話斷言看到的會是
        # 最終狀態而不是這次呼叫當下的內容,所以要淺拷貝一份快照。
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        if not self._responses:
            raise AssertionError("模型被呼叫的次數超過預期")
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def report_block(risk_level="LOW", **overrides):
    payload = {
        "target_type": "ip",
        "risk_level": risk_level,
        "summary": "測試摘要",
        "evidence": [{"source": "abuseipdb", "finding": "無異常", "confidence": "high"}],
        "sources_checked": ["abuseipdb_lookup"],
        "recommendation": "無需處理",
    }
    payload.update(overrides)
    return Block("tool_use", "submit_report", payload, "tu_report")


@pytest.fixture
def fake_tools(monkeypatch):
    """把工具換成不碰網路的假實作,回傳 (結果, 是否命中快取, 耗時)。"""
    calls = []

    def make(result, from_cache=False, ms=10):
        async def tool(target, collection):
            calls.append(target)
            return result, from_cache, ms
        return tool

    dispatch = {
        "abuseipdb_lookup": (make({"abuseConfidenceScore": 0}), "ip"),
        "ipwhois_lookup": (make({"asn": "AS15169"}, from_cache=True), "ip"),
        "virustotal_ip_lookup": (
            make({"last_analysis_stats": {"malicious": 0}}), "ip"
        ),
    }
    monkeypatch.setattr(agent_module, "TOOL_DISPATCH", dispatch)
    return calls


def build_agent(responses):
    agent_module._client = FakeClient(responses)
    return AI("8.8.8.8", FakeCollection("cache"), FakeCollection("tool_calls"))


async def test_loop_feeds_results_back_and_continues(fake_tools):
    """第一輪查一個來源,第二輪依結果再查一個,第三輪才交報告。"""
    ai = build_agent([
        Message([Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, "t1")]),
        Message([Block("tool_use", "virustotal_ip_lookup", {"ip": "8.8.8.8"}, "t2")]),
        Message([report_block()]),
    ])

    report = await ai.run()

    assert ai.iterations == 3
    assert ai.tool_calls_count == 2
    assert report["risk_level"] == "LOW"
    assert ai.stopped_reason == "submitted"
    assert fake_tools == ["8.8.8.8", "8.8.8.8"]


async def test_parallel_tool_calls_in_one_turn(fake_tools):
    ai = build_agent([
        Message([
            Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, "t1"),
            Block("tool_use", "ipwhois_lookup", {"ip": "8.8.8.8"}, "t2"),
        ]),
        Message([report_block()]),
    ])

    await ai.run()

    assert ai.tool_calls_count == 2
    assert ai.cache_hits == 1, "ipwhois 那個假工具回報命中快取"


async def test_usage_is_accumulated_across_every_call(fake_tools):
    """舊版只記最後一次呼叫的 usage,前面幾輪全部漏掉。"""
    ai = build_agent([
        Message(
            [Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, "t1")],
            usage=Usage(1000, 200),
        ),
        Message([report_block()], usage=Usage(1500, 300)),
    ])

    await ai.run()

    assert ai.input_tokens == 2500
    assert ai.output_tokens == 500


async def test_every_tool_use_gets_a_tool_result(fake_tools):
    """少回一個 tool_result,下一次 API 呼叫就會被拒絕。"""
    ai = build_agent([
        Message([Block("tool_use", "no_such_tool", {"ip": "8.8.8.8"}, "t1")]),
        Message([report_block()]),
    ])

    await ai.run()

    second_call = agent_module._client.messages.calls[1]
    tool_results = second_call["messages"][-1]["content"]
    assert len(tool_results) == 1
    assert tool_results[0]["tool_use_id"] == "t1"
    assert tool_results[0]["is_error"] is True


async def test_missing_argument_does_not_crash(fake_tools):
    ai = build_agent([
        Message([Block("tool_use", "abuseipdb_lookup", {}, "t1")]),
        Message([report_block()]),
    ])

    report = await ai.run()
    assert report["risk_level"] == "LOW"


async def test_tool_exception_is_contained(monkeypatch):
    async def exploding(target, collection):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        agent_module, "TOOL_DISPATCH", {"abuseipdb_lookup": (exploding, "ip")}
    )

    ai = build_agent([
        Message([Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, "t1")]),
        Message([report_block()]),
    ])

    report = await ai.run()
    assert report["risk_level"] == "LOW"


async def test_forces_report_on_last_iteration(fake_tools):
    """迴圈一定要收斂,不能無限查下去。"""
    ai = build_agent([
        Message([Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, f"t{i}")])
        for i in range(5)
    ] + [Message([report_block()])])
    ai.MAX_ITERATIONS = 6

    await ai.run()

    assert ai.iterations == 6
    assert ai.stopped_reason == "max_iterations"
    last_call = agent_module._client.messages.calls[-1]
    assert last_call["tool_choice"] == {"type": "tool", "name": "submit_report"}


async def test_nudges_model_when_it_neither_queries_nor_reports(fake_tools):
    ai = build_agent([
        Message([Block("text")]),
        Message([report_block()]),
    ])

    await ai.run()

    second_call = agent_module._client.messages.calls[1]
    assert "submit_report" in second_call["messages"][-1]["content"]


async def test_partial_report_is_coerced(fake_tools):
    """強制工具呼叫撞上 max_tokens 時,回傳的 input 可能殘缺。"""
    ai = build_agent([
        Message([Block("tool_use", "submit_report", {"risk_level": "NONSENSE"}, "r")]),
    ])

    report = await ai.run()

    assert report["risk_level"] == "UNKNOWN"
    assert report["evidence"] == []
    assert report["sources_checked"] == []
    assert report["summary"] == ""


async def test_final_report_is_written_to_the_trace(fake_tools):
    """舊版只記錄第一輪的查詢,最關鍵的判斷那一步沒有留下紀錄。"""
    trace = FakeCollection("tool_calls")
    agent_module._client = FakeClient([
        Message([Block("tool_use", "abuseipdb_lookup", {"ip": "8.8.8.8"}, "t1")]),
        Message([report_block(risk_level="HIGH")]),
    ])
    ai = AI("8.8.8.8", FakeCollection("cache"), trace)

    await ai.run()

    types = [d["type"] for d in trace.docs]
    assert types == ["tool_call", "tool_result", "report"]
    assert trace.docs[-1]["output"]["risk_level"] == "HIGH"


async def test_raises_when_no_report_is_produced(fake_tools):
    ai = build_agent([Message([Block("text")])])
    ai.MAX_ITERATIONS = 0

    with pytest.raises(AgentError):
        await ai.run()
