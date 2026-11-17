from dotenv import load_dotenv
import os
from fastapi.security import APIKeyHeader

load_dotenv()
BLOCKLIST_EXPIRE_DAYS = 30
MONGODB_URL = os.getenv("MONGODB_URL")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_KEY = os.getenv("API_KEY")

# ---- 本機 LLM（Ollama）----
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
AGENT_MODEL = os.getenv("AGENT_MODEL", "qwen2.5:1.5b")         # 第一輪：決定呼叫哪些工具
JUDGE_MODEL = os.getenv("JUDGE_MODEL", "threat-intel-judge")    # 第二輪：LoRA 微調後的判定模型
EMBED_MODEL = os.getenv("EMBED_MODEL", "bge-m3")                # RAG 嵌入模型
RAG_ENABLED = os.getenv("RAG_ENABLED", "true").lower() != "false"
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "4"))
MAX_TOOL_ROUNDS = 2          # 查證模型最多問兩輪，之後由必查清單補齊
LLM_NUM_CTX = 4096

ABUSEIPDB_REQUESTS_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_REQUESTS_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VIRUSTOTAL_DOMAINS_REQUESTS_URL = "https://www.virustotal.com/api/v3/domains/{}"

API_KEY_HEADER = APIKeyHeader(name="X-API-Key")


def _tool(name, description, param, param_desc):
    """Ollama 的工具格式（與 OpenAI function calling 相同）。"""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {param: {"type": "string", "description": param_desc}},
                "required": [param],
            },
        },
    }


PLANNER_SYSTEM_PROMPT = """你是資安威脅情資分析 Agent 的查證階段。使用者會給你一個 IP 或網域，你要呼叫工具蒐集證據。
- IP：在同一次回覆中同時呼叫 ipwhois_lookup、abuseipdb_lookup、virustotal_ip_lookup 三個工具
- 網域：在同一次回覆中同時呼叫 whois_lookup、virustotal_domain_lookup 兩個工具
只查其中一個不算查證完成。工具參數一律填使用者給的目標本身，不要改寫。
全部查完後只要回覆「查證完成」，不需要下結論，結論由下一個階段產生。"""

JUDGE_SYSTEM_PROMPT = """你是資安威脅情資分析師，負責判定一個 IP 或網域的風險等級。
你會收到：分析目標、程式判定的目標事實（facts）、各情資工具的精簡證據，以及從知識庫檢索到的參考準則。
只能依據這些內容判斷，不可臆測或捏造數字。輸出一個 JSON 物件：
- target_type：ip 或 domain（依 facts.type）
- evidence：每個查詢過的來源一筆，source 用工具名稱，finding 寫出關鍵數值，confidence 是這筆證據對判定的影響力（high、medium、low）
- risk_level：依判定準則選 HIGH、MEDIUM、LOW 或 UNKNOWN
- summary：一到兩句繁體中文，說明判定理由與關鍵數值
- sources_checked：查詢過的工具名稱
- recommendation：具體的處置建議"""

# 第二輪的結構化輸出格式（Ollama format 參數，以文法限制解碼，保證回傳可解析）。
# 欄位順序刻意讓模型先寫證據、再下風險等級。
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "target_type": {"type": "string", "enum": ["ip", "domain"]},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "finding": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["source", "finding", "confidence"],
            },
        },
        "risk_level": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]},
        "summary": {"type": "string"},
        "sources_checked": {"type": "array", "items": {"type": "string"}},
        "recommendation": {"type": "string"},
    },
    "required": ["target_type", "evidence", "risk_level", "summary", "sources_checked", "recommendation"],
}


class AgentConfig:
    def __init__(self):
        self.WHOIS = [_tool("whois_lookup", "查詢網域的 WHOIS 註冊資訊，包含註冊商、註冊日期、國家", "domain", "要查詢的網域名稱")]
        self.IPWHOIS = [_tool("ipwhois_lookup", "查詢 IP 的 RDAP 註冊資訊，包含 ASN、網段、國家", "ip", "要查詢的 IP 位址")]
        self.ABUSEIPDB = [_tool("abuseipdb_lookup", "查詢 IP 在 AbuseIPDB 的濫用信心分數、被檢舉次數、是否為 Tor 出口節點", "ip", "要查詢的 IP 位址")]
        self.VIRUSTOTAL_IP = [_tool("virustotal_ip_lookup", "查詢 IP 在 VirusTotal 的多引擎掃描結果與社群信譽", "ip", "要查詢的 IP 位址")]
        self.VIRUSTOTAL_DOMAIN = [_tool("virustotal_domain_lookup", "查詢網域在 VirusTotal 的多引擎掃描結果、分類與知名度", "domain", "要查詢的網域名稱")]
        self.TOOLS = self.WHOIS + self.IPWHOIS + self.ABUSEIPDB + self.VIRUSTOTAL_IP + self.VIRUSTOTAL_DOMAIN

        self.PLANNER_SYSTEM_PROMPT = PLANNER_SYSTEM_PROMPT
        self.JUDGE_SYSTEM_PROMPT = JUDGE_SYSTEM_PROMPT
        self.REPORT_SCHEMA = REPORT_SCHEMA

        self.AGENT_MODEL = AGENT_MODEL
        self.JUDGE_MODEL = JUDGE_MODEL
        self.NUM_PREDICT = 900
