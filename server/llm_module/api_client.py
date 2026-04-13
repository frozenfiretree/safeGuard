from __future__ import annotations

import json
from typing import Any, Dict, List

import httpx

from .config import LLMConfig


class LLMClientError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config

    def chat_json(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        if not self.config.available:
            raise LLMClientError("llm client not configured")

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(f"{self.config.base_url}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        try:
            content = data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMClientError(f"invalid llm response payload: {exc}") from exc

        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        if not isinstance(content, str) or not content.strip():
            raise LLMClientError("llm returned empty content")

        return _safe_parse_json(content)


def _safe_parse_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise LLMClientError("llm returned invalid json")
