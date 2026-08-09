import ipwhois
from utils import duration, iscache
@duration
@iscache("ipwhois")
async def ipwhois_lookup(ip, collection):
    result = ipwhois.IPWhois(ip).lookup_rdap()
    return result
