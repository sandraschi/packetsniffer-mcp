"""Unified LLM client — routes to local or cloud providers."""

# ruff: noqa: E501  — generated payload lines exceed 120 chars

from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

import httpx

from packetsniffer_mcp.config import LLMProvider, get_llm_config

logger = logging.getLogger(__name__)


class LLMClient:
    """Unified chat client for all LLM providers.

    Supports: Ollama, LM Studio (local), OpenAI, Anthropic, Google (cloud).
    Provider-specific API format adaptation is handled transparently.
    """

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or get_llm_config()

    # -- Chat completion (non-streaming) --

    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        history: list[dict[str, str]] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> dict[str, Any]:
        """Send a chat completion and return the response dict."""
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                if self.provider.provider == "anthropic":
                    return await self._chat_anthropic(client, messages, temperature, max_tokens)
                if self.provider.provider == "google":
                    return await self._chat_google(client, prompt, system, temperature, max_tokens)
                return await self._chat_openai_compat(client, messages, temperature, max_tokens)
        except httpx.HTTPError as e:
            logger.error("LLM chat failed: %s", e)
            return {"error": str(e), "content": "", "model": self.provider.model}

    async def _chat_openai_compat(
        self, client: httpx.AsyncClient, messages: list, temperature: float, max_tokens: int,
    ) -> dict[str, Any]:
        headers = {}
        if self.provider.api_key:
            headers["Authorization"] = f"Bearer {self.provider.api_key}"
        resp = await client.post(
            f"{self.provider.base_url.rstrip('/')}/chat/completions",
            json={"model": self.provider.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens},
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {"success": True, "content": content, "model": self.provider.model, "provider": self.provider.provider}

    async def _chat_anthropic(
        self, client: httpx.AsyncClient, messages: list, temperature: float, max_tokens: int,
    ) -> dict[str, Any]:
        system = next((m["content"] for m in messages if m["role"] == "system"), None)
        user_msgs = [m for m in messages if m["role"] != "system"]
        headers = {
            "x-api-key": self.provider.api_key or "",
            "anthropic-version": "2023-06-01",
        }
        body = {
            "model": self.provider.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_msgs,
        }
        if system:
            body["system"] = system
        resp = await client.post(
            f"{self.provider.base_url.rstrip('/')}/messages",
            json=body, headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        content = "".join(b.get("text", "") for b in data.get("content", []))
        return {"success": True, "content": content, "model": self.provider.model, "provider": "anthropic"}

    async def _chat_google(
        self, client: httpx.AsyncClient, prompt: str, system: str | None, temperature: float, max_tokens: int,
    ) -> dict[str, Any]:
        api_key = self.provider.api_key or ""
        contents = [{"parts": [{"text": prompt}], "role": "user"}]
        if system:
            contents.insert(0, {"parts": [{"text": system}], "role": "user"})
        resp = await client.post(
            f"{self.provider.base_url.rstrip('/')}/models/{self.provider.model}:generateContent",
            params={"key": api_key},
            json={"contents": contents, "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}},
        )
        resp.raise_for_status()
        data = resp.json()
        content = "".join(
            p.get("text", "") for c in data.get("candidates", [])
            for p in c.get("content", {}).get("parts", [])
        )
        return {"success": True, "content": content, "model": self.provider.model, "provider": "google"}

    # -- Streaming chat (SSE) --

    async def chat_stream(
        self, prompt: str, system: str | None = None, history: list[dict[str, str]] | None = None,
        temperature: float = 0.7, max_tokens: int = 2048,
    ) -> AsyncIterator[str]:
        """Stream chat completion tokens."""
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=300.0) as client:
            headers = {}
            if self.provider.api_key:
                headers["Authorization"] = f"Bearer {self.provider.api_key}"
            async with client.stream(
                "POST",
                f"{self.provider.base_url.rstrip('/')}/chat/completions",
                json={"model": self.provider.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens, "stream": True},
                headers=headers,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if delta:
                                yield delta
                        except json.JSONDecodeError:
                            pass

    # -- Health check --

    async def health(self) -> dict[str, Any]:
        """Test connectivity to the configured LLM provider."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.provider.base_url.rstrip('/')}/models")
                return {"reachable": resp.status_code < 500, "provider": self.provider.provider, "model": self.provider.model}
        except Exception as e:
            return {"reachable": False, "provider": self.provider.provider, "error": str(e)}
