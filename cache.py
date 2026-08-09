from datetime import datetime, timezone, timedelta

def make_cache_key(tool_name, target):
    return f"{tool_name}:{target}"

async def get_cache(collection, key):
    cache = await collection.find_one({"key":key})
    if cache:
        expires_at = cache["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at > datetime.now(timezone.utc):
            return cache["value"]
        return None
    return cache # None

async def set_cache(collection, key, value):
    cache = {
        "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        "key": key,
        "value": value
    }
    await collection.update_one(
        {"key": key},
        {"$set": cache},
        upsert=True
    )