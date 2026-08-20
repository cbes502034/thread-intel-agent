"""共用的非同步 HTTP client。

原本每個工具都用同步的 `requests.get`,但工具是在 async 的請求流程裡被
await 的 —— 那條 blocking 呼叫會鎖住整個 event loop,一次 10~30 秒的分析
期間連 /health 都回不了。改用 httpx 的 AsyncClient,並共用同一個實例
以重複利用連線。
"""

import httpx

from config import EXTERNAL_TIMEOUT_SECONDS

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            headers={"User-Agent": "threat-intel-agent/1.0"},
            follow_redirects=True,
        )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None
