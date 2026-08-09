from datetime import datetime, timezone
from uuid import uuid4
from functools import wraps
from time import time
from cache import make_cache_key, set_cache, get_cache
from fastapi import Security, HTTPException, status
from config import API_KEY_HEADER, API_KEY

def get_analysis_id(return_now= False):
    uid = uuid4().hex[:6]
    now = datetime.now(timezone.utc)
    d = now.strftime("%Y%m%d")
    prefix = "ana"
    if return_now:
        return f"{prefix}_{d}_{uid}", now
    return f"{prefix}_{d}_{uid}"

def duration(fun):
    @wraps(fun)
    async def wrap(*args, **kwargs):
        start = time()
        back, middle_tuple = await fun(*args, **kwargs)
        exec_time = int((time() - start) * 1000)
        return back, *middle_tuple, exec_time
    return wrap

def iscache(name):
    def decorator(fun):
        @wraps(fun)
        async def wrap(arg, collection, *args):
            cache_key = make_cache_key(name, arg)
            cache = await get_cache(collection, cache_key)
            if cache:
                return cache, (True, )
            result = await fun(arg, collection)
            await set_cache(collection, cache_key, result)
            return result, (False, )
        return wrap
    return decorator

async def verify_api_key(key: str = Security(API_KEY_HEADER)):
    if key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return key