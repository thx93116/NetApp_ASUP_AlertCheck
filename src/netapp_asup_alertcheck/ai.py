from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


def build_messages(question_direction: str, evidence: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "You analyze NetApp AutoSupport evidence. Return strict JSON only. "
                "Do not claim facts not present in evidence. Include status, severity, "
                "confidence, impacted_objects, recommended_actions, kb_search_required, "
                "and kb_search_queries."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {"question_direction": question_direction, "evidence": evidence},
                ensure_ascii=False,
                sort_keys=True,
            ),
        },
    ]


def parse_ai_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("AI response must be a JSON object")
    return data


def call_openai_compatible(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout: int = 60,
) -> dict[str, Any]:
    if not api_key:
        raise ValueError("AI_PROVIDER_API_KEY is required")
    if not model:
        raise ValueError("AI_PROVIDER_MODEL is required")
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise RuntimeError(f"AI provider request failed: {exc}") from exc

    content = body["choices"][0]["message"]["content"]
    return parse_ai_json(content)
