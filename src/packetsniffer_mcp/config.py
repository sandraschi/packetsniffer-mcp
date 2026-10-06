"""Multi-provider LLM configuration - local + cloud."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass


@dataclass
class LLMProvider:
    """LLM provider with endpoint, model, and API key."""

    provider: str  # ollama | lmstudio | openai | anthropic | google
    base_url: str
    model: str
    api_key: str | None = None

    @property
    def is_local(self) -> bool:
        return self.provider in ("ollama", "lmstudio")


# Preset provider profiles
PRESETS: dict[str, LLMProvider] = {
    "ollama": LLMProvider(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
    ),
    "lmstudio": LLMProvider(
        provider="lmstudio",
        base_url="http://127.0.0.1:1234/v1",
        model="local-model",
    ),
    "openai": LLMProvider(
        provider="openai",
        base_url="https://api.openai.com/v1",
        model="gpt-4o",
    ),
    "anthropic": LLMProvider(
        provider="anthropic",
        base_url="https://api.anthropic.com/v1",
        model="claude-sonnet-4-20250514",
    ),
    "google": LLMProvider(
        provider="google",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        model="gemini-2.5-flash",
    ),
}


def detect_local_provider() -> LLMProvider | None:
    """Auto-detect local LLM providers via TCP health check."""
    for name in ("ollama", "lmstudio"):
        preset = PRESETS[name]
        try:
            host = preset.base_url.split("://")[1].split(":")[0]
            port = int(preset.base_url.split(":")[-1].split("/")[0])
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((host, port))
            s.close()
            return preset
        except Exception:
            pass
    return None


def get_llm_config() -> LLMProvider:
    """Get the active LLM provider from env vars or auto-detection.

    Environment variables:
        PACKETSNIFFER_MCP_LLM_PROVIDER   - ollama | lmstudio | openai | anthropic | google
        PACKETSNIFFER_MCP_LLM_BASE_URL   - override API base URL
        PACKETSNIFFER_MCP_LLM_MODEL      - override model name
        PACKETSNIFFER_MCP_LLM_API_KEY    - API key (required for cloud providers)
    """
    provider_name = os.getenv("PACKETSNIFFER_MCP_LLM_PROVIDER", "").lower()

    if provider_name and provider_name in PRESETS:
        preset = PRESETS[provider_name]
        return LLMProvider(
            provider=provider_name,
            base_url=os.getenv("PACKETSNIFFER_MCP_LLM_BASE_URL", preset.base_url),
            model=os.getenv("PACKETSNIFFER_MCP_LLM_MODEL", preset.model),
            api_key=os.getenv("PACKETSNIFFER_MCP_LLM_API_KEY") or preset.api_key,
        )

    # Auto-detect local provider
    local = detect_local_provider()
    if local:
        model = os.getenv("PACKETSNIFFER_MCP_LLM_MODEL", local.model)
        return LLMProvider(provider=local.provider, base_url=local.base_url, model=model)

    # Fallback: Ollama default
    return PRESETS["ollama"]
