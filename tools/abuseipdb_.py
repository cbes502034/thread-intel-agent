import requests
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_REQUESTS_URL
from utils import duration, iscache
@duration
@iscache("abuseipdb")
async def abuseipdb_lookup(ip, collection):

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip
    }
    
    response = requests.get(ABUSEIPDB_REQUESTS_URL, headers=headers, params=params)

    if response.status_code == 200:
        result = response.json()["data"]
        return result

    return {"error": f"API 回應失敗,status_code: {response.status_code}"}


