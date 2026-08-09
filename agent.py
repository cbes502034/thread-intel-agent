import anthropic
from config import ANTHROPIC_API_KEY, AgentConfig
from tools.whois_ import whois_lookup
from tools.ipwhois_ import ipwhois_lookup
from tools.abuseipdb_ import abuseipdb_lookup
from tools.virustotal_ import virustotal_domain_lookup
from tools.virustotal_ import virustotal_ip_lookup
from time import time
from utils import get_analysis_id
from datetime import datetime, timezone

class AI(AgentConfig):
    def __init__(self, user, cache_collection, tool_calls_collection):
        super().__init__()
        self.user = user
        self.cache_collection = cache_collection
        self.tool_calls_collection = tool_calls_collection
    

    async def run(self):
        start = time()
        self.analysis_id, self.now = get_analysis_id(return_now=True)
        client = anthropic.Anthropic(
                api_key=ANTHROPIC_API_KEY
            )
        iterations = 0
        
        messages = [{"role": "user", "content": f"請幫我查詢{self.user}的註冊資訊"}]
        message = client.messages.create(
            max_tokens=self.MAX_TOKEN,
            messages=messages,
            model=self.MODEL,
            tools=self.WHOIS+
                  self.IPWHOIS+
                  self.ABUSEIPDB+
                  self.VIRUSTOTAL_IP+
                   self.VIRUSTOTAL_DOMAIN,
            system=self.AI_SYSTEM_PROMPT,
            # tool_choice={"type":"tool", "name":"submit_report"}
        )
        iterations+=1
        
        messages.append({"role":"assistant",
                          "content":message.content})
        
        tool_calls_count = 0
        
        for block in message.content:
            if block.type == "tool_use":
                await self.tool_calls_collection.insert_one({
                    "analysis_id": self.analysis_id,
                    "iteration": iterations,
                    "type": "tool_call",
                    "tool_name": block.name,
                    "input": block.input,
                    "timestamp": datetime.now(timezone.utc)
                })
                if block.name == "whois_lookup":
                    result, from_cache, exectime  = await whois_lookup(block.input["domain"], self.cache_collection)

                elif block.name == "ipwhois_lookup":
                    result, from_cache, exectime = await ipwhois_lookup(block.input["ip"], self.cache_collection)
                
                elif block.name == "abuseipdb_lookup":
                    result, from_cache, exectime = await abuseipdb_lookup(block.input["ip"], self.cache_collection)
                
                elif block.name == "virustotal_ip_lookup":
                    result, from_cache, exectime = await virustotal_ip_lookup(block.input["ip"], self.cache_collection)
                
                elif block.name == "virustotal_domain_lookup":
                    result, from_cache, exectime = await virustotal_domain_lookup(block.input["domain"], self.cache_collection)
                await self.tool_calls_collection.insert_one({
                      "analysis_id": self.analysis_id,
                      "iteration": iterations,
                      "type": "tool_result",           
                      "tool_name": block.name,
                      "output": result,
                      "duration_ms": exectime,
                      "from_cache": from_cache,
                      "timestamp": datetime.now(timezone.utc)
                })
                messages.append({
                    "role":"user",
                    "content":[{
                        "type":"tool_result",
                        "tool_use_id":block.id,
                        "content":str(result)
                    }]
                })
                tool_calls_count+=1
                

                
        
        self.result = client.messages.create(
            max_tokens=self.MAX_TOKEN,
            messages=messages,
            model=self.MODEL,
            tools=self.WHOIS+self.IPWHOIS+
                  self.ABUSEIPDB+
                  self.VIRUSTOTAL_IP+
                  self.VIRUSTOTAL_DOMAIN+
                  self.SUBMIT_REPORT_TOOL,
            system=self.AI_SYSTEM_PROMPT,
            tool_choice={"type":"tool", "name":"submit_report"}
        )
        iterations+=1
        
        self.tool_calls_count = tool_calls_count
        self.iterations = iterations
        for block in self.result.content:
            if block.type == "tool_use" and block.name == "submit_report":
                final_report = block.input
        self.final_report = final_report
        self.duration_ms = int((time() - start) * 1000)
