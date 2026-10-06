"""FastMCP sampling handler - delegates to LLM client."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from packetsniffer_mcp.config import get_llm_config

logger = logging.getLogger(__name__)

try:
    from fastmcp import Context
except ImportError:
    from fastmcp.server.context import Context  # type: ignore[attr-defined]


class SamplingHandler:
    """Route MCP sampling to the configured LLM provider."""

    def __init__(self) -> None:
        self._config = get_llm_config()

    async def __call__(
        self,
        context: Context,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        del context
        payload: dict[str, Any] = {"model": self._config.model, "messages": messages}
        if tools:
            payload["tools"] = tools

        headers: dict[str, str] = {}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"

        async with httpx.AsyncClient(
            base_url=self._config.base_url,
            headers=headers,
            timeout=120.0,
        ) as client:
            response = await client.post("/chat/completions", json=payload)
            response.raise_for_status()
            return response.json()
