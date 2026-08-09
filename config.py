from dotenv import load_dotenv
import os

load_dotenv()
BLOCKLIST_EXPIRE_DAYS = 30
MONGODB_URL = os.getenv("MONGODB_URL")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_REQUESTS_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_IP_REQUESTS_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VIRUSTOTAL_DOMAINS_REQUESTS_URL = "https://www.virustotal.com/api/v3/domains/{}"

class AgentConfig:
    def __init__(self):
        
        self.WHOIS = [{
            "name":"whois_lookup",
            "description":"查詢 domain 的 WHOIS 註冊資訊,包含註冊商、註冊日期、國家等",
            "input_schema":{
                "type":"object",
                "properties":{
                    "domain":{
                        "type":"string",
                        "description":"要查詢的domain名稱"
                    }
                },
                "required":["domain"]
            }
        }]
        
        self.IPWHOIS = [{
            "name":"ipwhois_lookup",
            "description":"查詢 ip 的 IPWHOIS 註冊資訊,包含註冊商、註冊日期、國家等",
            "input_schema":{
                "type":"object",
                "properties":{
                    "ip":{
                        "type":"string",
                        "description":"要查詢的ip位址"
                    }
                },
                "required":["ip"]
            }
        }]
        self.ABUSEIPDB = [{
            
            "name": "abuseipdb_lookup",
            "description": "查詢 ip 在 abuseipdb 中的危險與風險指標,包含惡意可信度分數、總被舉報次數、詳細攻擊紀錄等等，",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "要查詢的ip位址"
                    }
                },
                "required": ["ip"]
            }
                
        }]
        self.VIRUSTOTAL_IP = [{
            
            "name": "virustotal_ip_lookup",
            "description": "查詢 ip 在 VirusTotal 的多引擎掃描結果,重點欄位包含多少引擎判定惡意/乾淨(last_analysis_stats)、威脅類型分類如 phishing 或 malware(categories)、社群信譽分數(reputation)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "要查詢的ip位址"
                    }
                },
                "required": ["ip"]
            }
                
        }]
        self.VIRUSTOTAL_DOMAIN = [{
            
            "name": "virustotal_domain_lookup",
            "description": "查詢 domains 在 VirusTotal 的多引擎掃描結果,重點欄位包含多少引擎判定惡意/乾淨(last_analysis_stats)、威脅類型分類如 phishing 或 malware(categories)、社群信譽分數(reputation)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "要查詢的domain名稱"
                    }
                },
                "required": ["domain"]
            }
                
        }]
        
        self.AI_SYSTEM_PROMPT = """你是資安威脅情資分析 Agent。
        
        使用者會給你一個 IP 或 domain,你要用可用的工具查證,然後產出結構化的風險分析報告。
        
        風險等級判定原則:
        - HIGH: 多來源證據指向惡意
        - MEDIUM: 有部分可疑跡象,但證據不夠充分
        - LOW: 查無異常,屬於正常服務
        - UNKNOWN: 資料不足以判斷
        
        當你完成分析,最後只能回傳一個 JSON 物件,不要有其他文字、不要用 markdown 格式,格式如下:
        
        {
          "risk_level": "HIGH 或 MEDIUM 或 LOW 或 UNKNOWN",
          "summary": "一段簡短的分析摘要",
          "evidence": [
            {"source": "工具名稱", "finding": "發現了什麼", "confidence": "high 或 medium 或 low"}
          ],
          "sources_checked": ["用過的工具名稱清單"],
          "recommendation": "建議動作"
        }
        """ 
        
        self.MODEL = "claude-haiku-4-5"
        self.MAX_TOKEN = 2500
        
        self.SUBMIT_REPORT_TOOL = [{
            "name": "submit_report",
            "description": "當你完成分析後,呼叫這個工具來提交最終的結構化報告",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target_type":{
                        "type": "string",
                        "enum": ["ip", "domain"],
                        "description":"判斷輸入的目標是 ip位址 還是 domain名稱"
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                        "description": "風險等級"
                    },
                    "summary": {
                        "type": "string",
                        "description": "分析摘要"
                    },
                    "evidence": {
                        "type": "array",
                        "description": "證據列表",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": {"type": "string"},
                                "finding": {"type": "string"},
                                "confidence": {"type": "string", "enum": ["high", "medium", "low"]}
                            }
                        }
                    },
                    "sources_checked": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "建議動作"
                    }
                },
                "required": ["target_type","risk_level", "summary", "evidence", "sources_checked", "recommendation"]
            }
        }]
