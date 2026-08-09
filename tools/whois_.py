import whois
from utils import duration, iscache

@duration
@iscache("whois")
async def whois_lookup(domain, collection):
    result = whois.whois(domain)
    return result

