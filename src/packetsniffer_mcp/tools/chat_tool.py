"""LLM chat tool - local or cloud provider via unified client."""

# ruff: noqa: E501  - Field descriptions are verbose by design

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from packetsniffer_mcp.config import get_llm_config
from packetsniffer_mcp.llm_client import LLMClient
from packetsniffer_mcp.mcp_instance import mcp

logger = logging.getLogger(__name__)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
async def chat(
    prompt: Annotated[str, Field(description="The message or question to send to the LLM.")],
    system: Annotated[str | None, Field(description="Optional system prompt to set context.")] = None,
    provider: Annotated[
        str | None, Field(description="Override provider: ollama, lmstudio, openai, anthropic, google.")
    ] = None,
    model: Annotated[str | None, Field(description="Override model name.")] = None,
    temperature: Annotated[float, Field(description="Sampling temperature 0.0-2.0.", ge=0.0, le=2.0)] = 0.7,
    max_tokens: Annotated[int, Field(description="Max tokens in response.", ge=1, le=32768)] = 2048,
) -> dict:
    """Chat with the configured LLM provider (local or cloud).

    Uses the unified LLM client which auto-detects local providers (Ollama, LM Studio)
    and supports cloud providers (OpenAI, Anthropic, Google Gemini) via API keys.

    The provider and model can be overridden per-request.

    ## Return Format
    {"success": bool, "content": str, "model": str, "provider": str}

    ## Examples
    await chat(prompt="What is the capital of Austria?")
    await chat(prompt="Explain quantum computing in 3 sentences", system="Be concise.")
    await chat(prompt="Hello", provider="openai", model="gpt-4o")
    await chat(prompt="Describe Vienna", temperature=0.3)
    """
    if not prompt.strip():
        return {"success": False, "error": "prompt is required"}

    config = get_llm_config()

    # Provider override
    if provider and provider != config.provider:
        from packetsniffer_mcp.config import LLMProvider, PRESETS  # noqa: I001

        preset = PRESETS.get(provider)
        if not preset:
            return {"success": False, "error": f"Unknown provider: {provider}. Valid: {', '.join(PRESETS)}"}
        config = LLMProvider(
            provider=provider,
            base_url=preset.base_url,
            model=model or preset.model,
        )
    elif model:
        config = LLMProvider(
            provider=config.provider,
            base_url=config.base_url,
            model=model,
        )

    client = LLMClient(config)

    try:
        result = await client.chat(
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if "error" in result:
            return result
        return {
            "success": True,
            "content": result.get("content", ""),
            "model": result.get("model", config.model),
            "provider": result.get("provider", config.provider),
        }
    except Exception as e:
        logger.error("Chat tool failed: %s", e)
        return {
            "success": False,
            "error": str(e),
            "recovery_options": [
                "Check LLM provider is running and reachable",
                "Set PACKETSNIFFER_MCP_LLM_PROVIDER to override auto-detection",
                "For cloud providers, set the corresponding API key env var",
            ],
        }
