import requests
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_IP_REQUESTS_URL, VIRUSTOTAL_DOMAINS_REQUESTS_URL
from utils import duration, iscache


@duration
@iscache("virustotal_ip")
async def virustotal_ip_lookup(ip, collection): 
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(VIRUSTOTAL_IP_REQUESTS_URL.format(ip), headers=headers)
        if response.status_code == 200:
            result = response.json()["data"]
            return result
        return {"error": f"API 回應失敗,status_code: {response.status_code}"}

@duration
@iscache("virustotal_domain")
async def virustotal_domain_lookup(domain, collection):
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(VIRUSTOTAL_DOMAINS_REQUESTS_URL.format(domain), headers=headers)
        if response.status_code == 200:
            result = response.json()["data"]
            return result
        return {"error": f"API 回應失敗,status_code: {response.status_code}"}