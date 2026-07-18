import os
import time

import httpx

URL = "https://openrouter.ai/api/v1/chat/completions"


def chat(model: str, messages: list[dict], tools: list[dict] | None = None, *,
         client: httpx.Client | None = None, temperature: float = 0.0) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    body: dict = {"model": model, "messages": messages, "temperature": temperature}
    if tools:
        body["tools"] = tools
    c = client or _shared()
    for attempt in range(4):
        r = c.post(URL, json=body, headers={"Authorization": f"Bearer {key}"})
        if r.status_code in (429, 500, 502, 503) and attempt < 3:
            time.sleep(2 ** attempt)
            continue
        r.raise_for_status()
        return r.json()["choices"][0]["message"]


_client: httpx.Client | None = None


def _shared() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(timeout=60)
    return _client
