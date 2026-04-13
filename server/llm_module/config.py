from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_BASE_URLS = {
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "deepseek": "https://api.deepseek.com",
    "openai": "https://api.openai.com/v1",
}

DEFAULT_MODELS = {
    "qwen": "qwen-plus",
    "deepseek": "deepseek-chat",
    "openai": "gpt-4.1-mini",
}


def _provider_default_api_key(provider: str) -> str:
    if provider == "qwen":
        return os.environ.get("DASHSCOPE_API_KEY", "").strip()
    if provider == "deepseek":
        return os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY", "").strip()
    return ""


@dataclass
class LLMConfig:
    provider: str = "qwen"
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    timeout_seconds: int = 60
    max_input_chars: int = 12000
    max_blocks_per_call: int = 8
    enabled: bool = True

    def __post_init__(self) -> None:
        self.provider = (self.provider or "qwen").strip().lower()
        if self.provider not in DEFAULT_BASE_URLS:
            self.provider = "qwen"
        if not self.model:
            self.model = DEFAULT_MODELS[self.provider]
        if not self.base_url:
            self.base_url = DEFAULT_BASE_URLS[self.provider]
        self.base_url = self.base_url.rstrip("/")
        if not self.api_key:
            self.api_key = _provider_default_api_key(self.provider)
        self.timeout_seconds = max(10, int(self.timeout_seconds or 60))
        self.max_input_chars = max(1000, int(self.max_input_chars or 12000))
        self.max_blocks_per_call = max(1, int(self.max_blocks_per_call or 8))

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.api_key) and bool(self.model) and bool(self.base_url)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            provider=os.environ.get("SAFEGUARD_LLM_PROVIDER", "qwen"),
            model=os.environ.get("SAFEGUARD_LLM_MODEL", ""),
            api_key=os.environ.get("SAFEGUARD_LLM_API_KEY", ""),
            base_url=os.environ.get("SAFEGUARD_LLM_BASE_URL", ""),
            timeout_seconds=int(os.environ.get("SAFEGUARD_LLM_TIMEOUT_SECONDS", "60")),
            max_input_chars=int(os.environ.get("SAFEGUARD_LLM_MAX_INPUT_CHARS", "12000")),
            max_blocks_per_call=int(os.environ.get("SAFEGUARD_LLM_MAX_BLOCKS_PER_CALL", "8")),
            enabled=os.environ.get("SAFEGUARD_LLM_ENABLED", "true").strip().lower() not in {"0", "false", "no"},
        )
