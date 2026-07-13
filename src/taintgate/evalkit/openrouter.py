import os

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
    c = client or httpx.Client(timeout=120)
    r = c.post(URL, json=body, headers={"Authorization": f"Bearer {key}"})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]
